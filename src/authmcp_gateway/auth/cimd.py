"""OAuth Client ID Metadata Document (CIMD) handler.

Implements the authorization-server side of
``draft-ietf-oauth-client-id-metadata-document-00``, as required by the MCP
authorization specification:

- The authorization server fetches metadata when it sees a URL-formatted
  ``client_id``.
- The fetched document MUST be valid JSON, contain the required fields, and
  its ``client_id`` MUST equal the document URL exactly.
- ``redirect_uri`` is validated against the document's ``redirect_uris``
  array using exact-string match (per OAuth 2.1 §4.1.1.4).

SSRF protection follows CIMD draft §6:
- ``https`` scheme only, with a non-empty path component.
- DNS-resolved targets in private/loopback/link-local/reserved ranges are
  refused.
- Body size and request timeout are bounded; redirects are not followed.
"""

import ipaddress
import logging
import socket
import threading
import time
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Dict, Optional, Tuple, cast
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)


_FETCH_TIMEOUT_SECONDS = 5.0
_FETCH_MAX_BODY_BYTES = 1 * 1024 * 1024  # 1 MB
_DEFAULT_CACHE_TTL_SECONDS = 300

_REQUIRED_FIELDS = ("client_id", "client_name", "redirect_uris")


class CIMDError(Exception):
    """Raised when CIMD validation or fetch fails."""


_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_cache_lock = threading.Lock()


def _is_safe_target(host: str) -> bool:
    """Return True iff *host* resolves only to public, routable addresses."""
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    if not infos:
        return False
    for info in infos:
        addr = cast(str, info[4][0])
        try:
            ip = ipaddress.ip_address(addr.split("%", 1)[0])  # strip IPv6 zone
        except ValueError:
            return False
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_unspecified
            or ip.is_reserved
        ):
            return False
    return True


def _validate_url(url: str, check_target: Callable[[str], bool]) -> Optional[str]:
    """Return an error string or None if *url* is acceptable as a CIMD client_id."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return "client_id URL must use the https scheme"
    if not parsed.netloc:
        return "client_id URL is missing host"
    if not parsed.path or parsed.path == "/":
        return "client_id URL must contain a path component"
    if parsed.username or parsed.password:
        return "client_id URL must not contain user info"
    if parsed.fragment:
        return "client_id URL must not contain a fragment"
    host = parsed.hostname or ""
    if not check_target(host):
        return "client_id URL host resolves to a non-public address"
    return None


def _validate_metadata(metadata: Any, url: str) -> Optional[str]:
    """Return an error string or None for a fetched metadata payload."""
    if not isinstance(metadata, dict):
        return "metadata is not a JSON object"
    missing = [f for f in _REQUIRED_FIELDS if f not in metadata]
    if missing:
        return f"metadata missing required fields: {missing}"
    if metadata["client_id"] != url:
        return "metadata client_id does not match document URL"
    redirect_uris = metadata["redirect_uris"]
    if not isinstance(redirect_uris, list) or not redirect_uris:
        return "metadata redirect_uris must be a non-empty list"
    if not all(isinstance(item, str) and item for item in redirect_uris):
        return "metadata redirect_uris must contain only non-empty strings"
    return None


def _parse_cache_ttl(headers) -> Optional[float]:
    """Extract a cache TTL from ``Cache-Control`` / ``Expires`` headers, if any."""
    cc = headers.get("cache-control") if hasattr(headers, "get") else None
    if cc:
        for part in cc.split(","):
            part = part.strip().lower()
            if part in ("no-store", "no-cache", "private"):
                return 0.0
            if part.startswith("max-age="):
                try:
                    return max(0.0, float(part.split("=", 1)[1]))
                except ValueError:
                    continue
    expires = headers.get("expires") if hasattr(headers, "get") else None
    if expires:
        try:
            dt = parsedate_to_datetime(expires)
            return max(0.0, dt.timestamp() - time.time())
        except Exception:  # noqa: BLE001
            pass
    return None


def fetch_client_metadata(
    url: str,
    *,
    http_client: Optional[httpx.Client] = None,
    _check_target: Callable[[str], bool] = _is_safe_target,
) -> Dict[str, Any]:
    """Fetch and validate a CIMD metadata document for *url*.

    Args:
        url: URL-formatted ``client_id`` from the authorization request.
        http_client: Optional pre-configured ``httpx.Client`` (mainly for tests).
        _check_target: SSRF gate; defaults to a DNS-aware private-IP check.

    Returns:
        Parsed metadata dict on success.

    Raises:
        CIMDError: when the URL is unacceptable, the fetch fails, or the
            returned document does not satisfy the spec.
    """
    err = _validate_url(url, _check_target)
    if err:
        raise CIMDError(err)

    now = time.time()
    with _cache_lock:
        cached = _cache.get(url)
        if cached and cached[0] > now:
            return cached[1]

    owns_client = http_client is None
    client = http_client or httpx.Client(
        timeout=_FETCH_TIMEOUT_SECONDS,
        follow_redirects=False,
    )
    try:
        try:
            resp = client.get(url, headers={"Accept": "application/json"})
        except httpx.HTTPError as exc:
            raise CIMDError(f"failed to fetch metadata document: {exc}") from exc

        if resp.status_code != 200:
            raise CIMDError(f"metadata document returned HTTP {resp.status_code}")
        if len(resp.content) > _FETCH_MAX_BODY_BYTES:
            raise CIMDError("metadata document exceeds 1 MB limit")
        try:
            metadata = resp.json()
        except (ValueError, TypeError):
            raise CIMDError("metadata document is not valid JSON")

        err = _validate_metadata(metadata, url)
        if err:
            raise CIMDError(err)

        ttl = _parse_cache_ttl(resp.headers)
        if ttl is None:
            ttl = _DEFAULT_CACHE_TTL_SECONDS
        if ttl > 0:
            with _cache_lock:
                _cache[url] = (now + ttl, metadata)
        return cast(Dict[str, Any], metadata)
    finally:
        if owns_client:
            client.close()


def is_redirect_uri_in_metadata(metadata: Dict[str, Any], redirect_uri: str) -> bool:
    """Exact-match check of *redirect_uri* against ``metadata.redirect_uris``."""
    return redirect_uri in (metadata.get("redirect_uris") or [])


def clear_cache() -> None:
    """Drop the in-memory metadata cache (intended for tests)."""
    with _cache_lock:
        _cache.clear()
