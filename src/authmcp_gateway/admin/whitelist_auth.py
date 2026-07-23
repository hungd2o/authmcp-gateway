"""Whitelist-only verification session helpers."""

from __future__ import annotations

import hmac
from typing import Any, Optional

from starlette.requests import Request
from starlette.responses import Response

from authmcp_gateway.auth.whitelist_store import (
    create_whitelist_session,
    get_active_whitelist_session,
    revoke_whitelist_session,
)

PLAIN_COOKIE_NAME = "authmcp_whitelist_session"
SECURE_COOKIE_NAME = "__Host-authmcp-whitelist"


def _is_https(request: Request) -> bool:
    return request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"


def _cookie_value(request: Request) -> Optional[str]:
    return request.cookies.get(SECURE_COOKIE_NAME) or request.cookies.get(PLAIN_COOKIE_NAME)


def _admin_binding(request: Request) -> str:
    """Bind the Whitelist session to the admin JWT ``jti`` set by AdminAuthMiddleware.

    Returns "" if unset (defensive only — authenticated admin routes always
    have this set before reaching Whitelist handlers).
    """
    return getattr(request.state, "admin_session_jti", "") or ""


def verify_bootstrap_value(request: Request, supplied: str) -> bool:
    configured = (request.app.state.config.whitelist_token or "").strip()
    candidate = (supplied or "").strip()
    return bool(configured and candidate and hmac.compare_digest(candidate, configured))


def create_session_for_request(
    request: Request,
    *,
    method: str,
    credential_type: str | None = None,
    credential_id: str | None = None,
    credential_rp_id: str | None = None,
) -> tuple[str, dict[str, Any]]:
    config = request.app.state.config
    return create_whitelist_session(
        config.auth.sqlite_path,
        user_id=int(request.state.user_id),
        admin_session_id=_admin_binding(request),
        method=method,
        ttl_minutes=int(config.whitelist_auth.session_minutes),
        assurance_level=method,
        credential_type=credential_type or method,
        credential_id=credential_id,
        credential_rp_id=credential_rp_id,
    )


def get_session_for_request(request: Request) -> Optional[dict[str, Any]]:
    config = request.app.state.config
    return get_active_whitelist_session(
        config.auth.sqlite_path,
        handle=_cookie_value(request),
        user_id=int(request.state.user_id),
        admin_session_id=_admin_binding(request),
    )


def revoke_session_for_request(request: Request) -> bool:
    config = request.app.state.config
    return revoke_whitelist_session(
        config.auth.sqlite_path,
        handle=_cookie_value(request),
        user_id=int(request.state.user_id),
        admin_session_id=_admin_binding(request),
    )


def set_session_cookie(response: Response, request: Request, handle: str) -> None:
    secure = _is_https(request)
    response.set_cookie(
        key=SECURE_COOKIE_NAME if secure else PLAIN_COOKIE_NAME,
        value=handle,
        path="/",
        max_age=int(request.app.state.config.whitelist_auth.session_minutes) * 60,
        httponly=True,
        secure=secure,
        samesite="strict",
    )


def clear_session_cookies(response: Response) -> None:
    response.delete_cookie(PLAIN_COOKIE_NAME, path="/")
    response.delete_cookie(SECURE_COOKIE_NAME, path="/", secure=True, samesite="strict")
