"""Fail-closed destination checks for virtual outbound HTTP requests."""

from __future__ import annotations

import ipaddress
from urllib.parse import SplitResult, urlsplit


class OutboundDestinationError(ValueError):
    """Raised when a reviewed virtual HTTP request is unsafe to execute."""


def validate_virtual_http_destination(reviewed_url: str, resolved_url: str) -> None:
    """Allow only a reviewed public HTTP(S) origin with public DNS answers."""
    reviewed = _parse(reviewed_url, "reviewed URL")
    resolved = _parse(resolved_url, "resolved URL")
    if _origin(reviewed) != _origin(resolved):
        raise OutboundDestinationError("Virtual HTTP requests cannot change the reviewed scheme, host, or port")
    if "{{" in reviewed.netloc or "}}" in reviewed.netloc:
        raise OutboundDestinationError("Virtual HTTP request authority cannot be templated")
    try:
        ip = ipaddress.ip_address(resolved.hostname)
    except ValueError as exc:
        raise OutboundDestinationError(
            "Virtual HTTP destinations must use a reviewed public IP address; hostnames are disabled to prevent DNS rebinding"
        ) from exc
    if not ip.is_global:
        raise OutboundDestinationError("Virtual HTTP destination resolves to a blocked network address")


def _parse(value: str, label: str) -> SplitResult:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise OutboundDestinationError(f"Virtual {label} must be an absolute HTTP(S) URL without user info")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise OutboundDestinationError(f"Virtual {label} has an invalid port") from exc
    return parsed


def _origin(value: SplitResult) -> tuple[str, str, int]:
    return value.scheme, value.hostname.lower(), value.port or _default_port(value.scheme)


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80
