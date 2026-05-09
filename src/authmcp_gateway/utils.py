"""Utility functions for AuthMCP Gateway."""

from typing import Iterable, List, Optional, Set, Tuple

from starlette.requests import Request


def _parse_scopes(scopes_value: str) -> List[str]:
    """Parse OAuth scopes from string (space or comma-separated).

    Args:
        scopes_value: Space or comma-separated scope string

    Returns:
        List of individual scope strings

    Example:
        >>> _parse_scopes("openid profile email")
        ['openid', 'profile', 'email']
        >>> _parse_scopes("openid,profile,email")
        ['openid', 'profile', 'email']
    """
    scopes_value = scopes_value.strip()
    if not scopes_value:
        return []
    parts = [part.strip() for part in scopes_value.replace(",", " ").split()]
    return [part for part in parts if part]


def validate_scopes(
    requested_scope: Optional[str], allowed: Iterable[str]
) -> Tuple[bool, Set[str]]:
    """Check that every requested scope token is present in *allowed*.

    Args:
        requested_scope: Raw scope string from the OAuth request, or None.
        allowed: Iterable of permitted scope tokens (typically AuthConfig.allowed_scopes).

    Returns:
        ``(True, empty_set)`` when every requested token is in *allowed* (or the
        request has no scope at all). Otherwise ``(False, unknown_scope_tokens)``.
    """
    allowed_set = set(allowed)
    if not requested_scope:
        return True, set()
    requested = set(_parse_scopes(requested_scope))
    unknown = requested - allowed_set
    if unknown:
        return False, unknown
    return True, set()


def get_request_ip(request: Optional[Request]) -> Optional[str]:
    """Extract client IP from request headers or socket info.

    Priority:
    1) X-Forwarded-For (first non-empty IP)
    2) X-Real-IP
    3) request.client.host
    """
    if request is None:
        return None

    xff = request.headers.get("x-forwarded-for")
    if xff:
        for part in xff.split(","):
            ip = part.strip()
            if ip and ip.lower() != "unknown":
                return ip

    xri = request.headers.get("x-real-ip")
    if xri:
        ip = xri.strip()
        if ip:
            return ip

    if request.client:
        return request.client.host
    return None
