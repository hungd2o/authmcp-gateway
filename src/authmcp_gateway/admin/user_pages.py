"""Admin: User portal pages (login, account, token management)."""

import logging
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

import jwt
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from authmcp_gateway.admin.routes import get_config, render_template
from authmcp_gateway.auth.jwt_handler import create_access_token, decode_token_unsafe, verify_token
from authmcp_gateway.auth.user_store import (
    blacklist_token,
    create_user_personal_access_token,
    get_user_personal_access_token,
    is_token_blacklisted,
    list_user_personal_access_tokens,
    revoke_user_personal_access_token,
)
from authmcp_gateway.utils import get_request_ip

logger = logging.getLogger(__name__)

PAT_LIFETIME_OPTIONS_MINUTES = {
    "standard": 60 * 24,
    "long": 60 * 24 * 90,
    "very_long": 60 * 24 * 365,
    "lifetime": 60 * 24 * 365 * 10,
}

__all__ = [
    "user_portal",
    "user_login_page",
    "user_login_api",
    "user_logout",
    "user_account_token",
    "user_account_rotate_token",
    "user_account_info",
    "user_account_pat_list",
    "user_account_pat_create",
    "user_account_pat_revoke",
    "user_account_pat_rotate",
]


def _is_https_request(request: Request) -> bool:
    """Return True when request is served via HTTPS (directly or behind proxy)."""
    host = (request.url.hostname or "").lower()
    if host in {"localhost", "127.0.0.1", "::1"}:
        return False
    return request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"


def _verify_user_token_or_401(
    token: str, _config
) -> Tuple[Optional[Dict[str, Any]], Optional[JSONResponse]]:
    """Verify a user-portal access token from the cookie.

    Centralises the JWT verify + JTI blacklist + admin-rejection sequence
    used by every authenticated user-portal endpoint.

    Returns:
        ``(payload, None)`` on success, where ``payload`` is the decoded
        JWT claims dict.

        ``(None, JSONResponse)`` on failure — the response is the 401/403
        the caller must return immediately:

        * 401 ``Token revoked`` if the JTI is blacklisted.
        * 403 ``Admin accounts must use the admin panel.`` if the token
          belongs to an admin (user portal is for non-admins only).
        * 401 ``Invalid or expired token`` for any
          ``jwt.PyJWTError`` / ``sqlite3.Error``.
    """
    try:
        payload = verify_token(token, "access", _config.jwt)
        jti = decode_token_unsafe(token).get("jti")
        if jti and is_token_blacklisted(_config.auth.sqlite_path, jti):
            return None, JSONResponse({"detail": "Token revoked"}, status_code=401)
        if payload.get("is_superuser"):
            return None, JSONResponse(
                {"detail": "Admin accounts must use the admin panel."}, status_code=403
            )
        return payload, None
    except (jwt.PyJWTError, sqlite3.Error):
        return None, JSONResponse({"detail": "Invalid or expired token"}, status_code=401)


async def user_portal(request: Request) -> Response:
    """User portal page for obtaining access token (non-admin).

    Returns an :class:`HTMLResponse` for authenticated non-admins or a
    :class:`RedirectResponse` to ``/login`` / ``/admin`` for unauthenticated
    or admin users — hence the broader :class:`Response` return type.
    """
    from authmcp_gateway.auth.user_store import get_user_by_id

    _config = get_config(request)
    token = request.cookies.get("user_token")
    if not token:
        return RedirectResponse(url="/login", status_code=302)

    try:
        payload = verify_token(token, "access", _config.jwt)
        if payload.get("is_superuser"):
            return RedirectResponse(url="/admin", status_code=302)
    except jwt.PyJWTError:
        return RedirectResponse(url="/login", status_code=302)

    username = payload.get("username")
    if not username and payload.get("sub"):
        try:
            user = get_user_by_id(_config.auth.sqlite_path, int(payload["sub"]))
            if user:
                username = user.get("username")
        except (sqlite3.Error, ValueError, TypeError):
            # ValueError/TypeError on int(payload["sub"]) for malformed sub;
            # sqlite3.Error from the DB lookup. Either is non-fatal — page
            # still renders without a friendly username.
            username = None

    return render_template("user_portal.html", username=username)


async def user_login_page(request: Request) -> HTMLResponse:
    """User login page (non-admin)."""
    return render_template("user_login.html")


async def user_login_api(request: Request) -> JSONResponse:
    """Login for non-admin users and set user_token cookie."""
    from authmcp_gateway.auth.password import verify_password_with_rehash
    from authmcp_gateway.auth.token_service import get_or_create_user_token
    from authmcp_gateway.auth.user_store import (
        get_user_by_username,
        log_auth_event,
        try_upgrade_password_hash,
        update_last_login,
    )

    _config = get_config(request)
    body = await request.json()
    username = body.get("username")
    password = body.get("password")

    if not username or not password:
        return JSONResponse({"detail": "Username and password required"}, status_code=400)

    user = get_user_by_username(_config.auth.sqlite_path, username)
    password_ok = False
    upgraded_hash = None
    if user:
        password_ok, upgraded_hash = verify_password_with_rehash(password, user["password_hash"])
    if not user or not password_ok:
        log_auth_event(
            db_path=_config.auth.sqlite_path,
            event_type="login",
            username=username,
            ip_address=get_request_ip(request),
            user_agent=request.headers.get("user-agent"),
            success=False,
            details="Invalid credentials",
        )
        return JSONResponse({"detail": "Invalid username or password"}, status_code=401)
    try_upgrade_password_hash(_config.auth.sqlite_path, user["id"], upgraded_hash, username)

    if user.get("is_superuser"):
        return JSONResponse({"detail": "Admin accounts must use the admin panel."}, status_code=403)

    update_last_login(_config.auth.sqlite_path, user["id"])

    access_token, _ = get_or_create_user_token(
        _config.auth.sqlite_path,
        user["id"],
        user["username"],
        False,
        _config.jwt,
        _config.jwt.access_token_expire_minutes,
        current_token=request.cookies.get("user_token"),
    )

    response = JSONResponse({"success": True})
    is_https = _is_https_request(request)
    response.set_cookie(
        "user_token",
        access_token,
        httponly=True,
        samesite="lax",
        secure=is_https,
        max_age=_config.jwt.access_token_expire_minutes * 60,
    )
    return response


async def user_logout(request: Request) -> Response:
    """Clear user session cookie."""
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("user_token")
    return response


async def user_account_token(request: Request) -> JSONResponse:
    """Return access token for authenticated non-admin user."""
    from authmcp_gateway.auth.token_service import get_or_create_user_token
    from authmcp_gateway.auth.user_store import get_user_by_id

    _config = get_config(request)
    token = request.cookies.get("user_token")
    if not token:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)

    payload, error = _verify_user_token_or_401(token, _config)
    if error:
        return error
    assert payload is not None  # _verify_user_token_or_401 invariant

    sub = payload.get("sub")
    if not sub:
        return JSONResponse({"detail": "Invalid token: missing sub"}, status_code=401)
    user_id = int(sub)
    username = payload.get("username") or ""
    if not username:
        user = get_user_by_id(_config.auth.sqlite_path, user_id)
        username = user["username"] if user else ""

    access_token, _ = get_or_create_user_token(
        _config.auth.sqlite_path,
        user_id,
        username,
        False,
        _config.jwt,
        _config.jwt.access_token_expire_minutes,
        current_token=token,
    )

    response = JSONResponse({"access_token": access_token})
    is_https = _is_https_request(request)
    response.set_cookie(
        "user_token",
        access_token,
        httponly=True,
        samesite="lax",
        secure=is_https,
        max_age=_config.jwt.access_token_expire_minutes * 60,
    )
    return response


async def user_account_rotate_token(request: Request) -> JSONResponse:
    """Rotate access token for authenticated non-admin user."""
    from authmcp_gateway.auth.token_service import rotate_user_token

    _config = get_config(request)
    token = request.cookies.get("user_token")
    if not token:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)

    payload, error = _verify_user_token_or_401(token, _config)
    if error:
        return error
    assert payload is not None  # _verify_user_token_or_401 invariant

    sub = payload.get("sub")
    if not sub:
        return JSONResponse({"detail": "Invalid token: missing sub"}, status_code=401)
    user_id = int(sub)
    username = payload.get("username") or ""
    new_token, _ = rotate_user_token(
        _config.auth.sqlite_path,
        user_id,
        username,
        False,
        _config.jwt,
        _config.jwt.access_token_expire_minutes,
        current_token=token,
    )

    response = JSONResponse({"access_token": new_token})
    is_https = _is_https_request(request)
    response.set_cookie(
        "user_token",
        new_token,
        httponly=True,
        samesite="lax",
        secure=is_https,
        max_age=_config.jwt.access_token_expire_minutes * 60,
    )
    return response


async def user_account_info(request: Request) -> JSONResponse:
    """Return user info, token expiry, and accessible MCP servers."""
    from datetime import datetime, timezone

    from authmcp_gateway.auth.token_service import get_or_create_user_token
    from authmcp_gateway.auth.user_store import get_user_by_id
    from authmcp_gateway.mcp.store import list_mcp_servers

    _config = get_config(request)
    token = request.cookies.get("user_token")
    if not token:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)

    payload, error = _verify_user_token_or_401(token, _config)
    if error:
        return error
    assert payload is not None  # _verify_user_token_or_401 invariant

    sub = payload.get("sub")
    if not sub:
        return JSONResponse({"detail": "Invalid token: missing sub"}, status_code=401)
    user_id = int(sub)
    username = payload.get("username") or ""
    if not username:
        user = get_user_by_id(_config.auth.sqlite_path, user_id)
        username = user["username"] if user else ""

    access_token, exp_dt = get_or_create_user_token(
        _config.auth.sqlite_path,
        user_id,
        username,
        False,
        _config.jwt,
        _config.jwt.access_token_expire_minutes,
        current_token=token,
    )

    expires_at = None
    expires_in_seconds = None
    if exp_dt:
        try:
            expires_at = exp_dt.isoformat()
            expires_in_seconds = int((exp_dt - datetime.now(timezone.utc)).total_seconds())
        except (TypeError, ValueError, AttributeError):
            # Defensive: malformed exp_dt (naive datetime, wrong type) is
            # presented without an expires_in field rather than failing
            # the whole token-info response.
            pass

    servers = list_mcp_servers(_config.auth.sqlite_path, enabled_only=True, user_id=user_id)
    public_base = (_config.mcp_public_url or "").rstrip("/")
    server_list = []
    from authmcp_gateway.mcp.proxy import normalize_server_name

    for s in servers:
        server_slug = normalize_server_name(s["name"])
        server_list.append(
            {
                "id": s["id"],
                "name": s["name"],
                "endpoint": (
                    f"{public_base}/mcp/{server_slug}" if public_base else f"/mcp/{server_slug}"
                ),
            }
        )

    response = JSONResponse(
        {
            "username": username,
            "expires_at": expires_at,
            "expires_in_seconds": expires_in_seconds,
            "servers": server_list,
            "gateway_endpoint": f"{public_base}/mcp" if public_base else "/mcp",
        }
    )
    is_https = _is_https_request(request)
    response.set_cookie(
        "user_token",
        access_token,
        httponly=True,
        samesite="lax",
        secure=is_https,
        max_age=_config.jwt.access_token_expire_minutes * 60,
    )
    return response


def _parse_pat_expiry(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    except (TypeError, ValueError):
        return None


def _serialize_pat_row(row: Dict[str, Any]) -> Dict[str, Any]:
    exp_dt = _parse_pat_expiry(row.get("expires_at"))
    revoked = row.get("revoked_at")
    expires_in_seconds = None
    if exp_dt:
        expires_in_seconds = int((exp_dt - datetime.now(timezone.utc)).total_seconds())
    return {
        "id": row.get("id"),
        "name": row.get("token_name"),
        "expires_at": exp_dt.isoformat() if exp_dt else row.get("expires_at"),
        "expires_in_seconds": expires_in_seconds,
        "lifetime_minutes": row.get("lifetime_minutes"),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
        "last_used_at": row.get("last_used_at"),
        "last_used_ip": row.get("last_used_ip"),
        "revoked_at": revoked,
        "is_active": revoked is None and (expires_in_seconds is None or expires_in_seconds > 0),
    }


def _get_user_identity(payload: Dict[str, Any]) -> tuple[int, str]:
    sub = payload.get("sub")
    if not sub:
        raise ValueError("Invalid token: missing sub")
    user_id = int(sub)
    return user_id, (payload.get("username") or "")


async def user_account_pat_list(request: Request) -> JSONResponse:
    """List user-managed personal access tokens for authenticated non-admin user."""
    _config = get_config(request)
    token = request.cookies.get("user_token")
    if not token:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)

    payload, error = _verify_user_token_or_401(token, _config)
    if error:
        return error
    assert payload is not None
    try:
        user_id, _ = _get_user_identity(payload)
    except (TypeError, ValueError):
        return JSONResponse({"detail": "Invalid token: missing sub"}, status_code=401)

    rows = list_user_personal_access_tokens(_config.auth.sqlite_path, user_id)
    return JSONResponse(
        {
            "tokens": [_serialize_pat_row(row) for row in rows],
            "lifetime_options": {
                key: int(minutes) for key, minutes in PAT_LIFETIME_OPTIONS_MINUTES.items()
            },
        }
    )


async def user_account_pat_create(request: Request) -> JSONResponse:
    """Create a new named personal access token for authenticated non-admin user."""
    _config = get_config(request)
    token = request.cookies.get("user_token")
    if not token:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)

    payload, error = _verify_user_token_or_401(token, _config)
    if error:
        return error
    assert payload is not None
    try:
        user_id, username = _get_user_identity(payload)
    except (TypeError, ValueError):
        return JSONResponse({"detail": "Invalid token: missing sub"}, status_code=401)

    body = await request.json()
    token_name = str(body.get("name") or "").strip()
    lifetime_key = str(body.get("lifetime") or "long").strip().lower()
    lifetime_minutes = PAT_LIFETIME_OPTIONS_MINUTES.get(lifetime_key)
    if not lifetime_minutes:
        return JSONResponse({"detail": "Invalid lifetime option"}, status_code=400)
    if not token_name or len(token_name) < 3 or len(token_name) > 64:
        return JSONResponse(
            {"detail": "Token name must be between 3 and 64 characters"},
            status_code=400,
        )

    access_token = create_access_token(
        user_id=user_id,
        username=username,
        is_superuser=False,
        config=_config.jwt,
        expire_minutes=lifetime_minutes,
    )
    decoded = decode_token_unsafe(access_token)
    jti = decoded.get("jti")
    exp = decoded.get("exp")
    if not jti or not exp:
        return JSONResponse({"detail": "Failed to create token"}, status_code=500)
    exp_dt = datetime.fromtimestamp(int(exp), tz=timezone.utc)
    token_id = create_user_personal_access_token(
        _config.auth.sqlite_path,
        user_id=user_id,
        token_name=token_name,
        token_jti=str(jti),
        expires_at=exp_dt,
        lifetime_minutes=lifetime_minutes,
    )
    return JSONResponse(
        {
            "id": token_id,
            "name": token_name,
            "access_token": access_token,
            "expires_at": exp_dt.isoformat(),
            "lifetime_minutes": lifetime_minutes,
        },
        status_code=201,
    )


async def user_account_pat_revoke(request: Request) -> JSONResponse:
    """Revoke a user-managed personal access token."""
    _config = get_config(request)
    token = request.cookies.get("user_token")
    if not token:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)

    payload, error = _verify_user_token_or_401(token, _config)
    if error:
        return error
    assert payload is not None
    try:
        user_id, _ = _get_user_identity(payload)
    except (TypeError, ValueError):
        return JSONResponse({"detail": "Invalid token: missing sub"}, status_code=401)

    token_id = int(request.path_params["token_id"])
    pat = get_user_personal_access_token(_config.auth.sqlite_path, user_id, token_id)
    if not pat:
        return JSONResponse({"detail": "Token not found"}, status_code=404)
    if pat.get("revoked_at"):
        return JSONResponse({"success": True, "already_revoked": True})

    revoked = revoke_user_personal_access_token(_config.auth.sqlite_path, user_id, token_id)
    if not revoked:
        return JSONResponse({"detail": "Token already revoked"}, status_code=409)

    try:
        exp_dt = _parse_pat_expiry(pat.get("expires_at"))
        if exp_dt and pat.get("token_jti"):
            blacklist_token(_config.auth.sqlite_path, str(pat["token_jti"]), exp_dt)
    except sqlite3.Error:
        logger.exception("Failed to blacklist revoked PAT jti=%s", pat.get("token_jti"))

    return JSONResponse({"success": True})


async def user_account_pat_rotate(request: Request) -> JSONResponse:
    """Rotate a user-managed personal access token and return a replacement."""
    _config = get_config(request)
    token = request.cookies.get("user_token")
    if not token:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)

    payload, error = _verify_user_token_or_401(token, _config)
    if error:
        return error
    assert payload is not None
    try:
        user_id, username = _get_user_identity(payload)
    except (TypeError, ValueError):
        return JSONResponse({"detail": "Invalid token: missing sub"}, status_code=401)

    token_id = int(request.path_params["token_id"])
    pat = get_user_personal_access_token(_config.auth.sqlite_path, user_id, token_id)
    if not pat:
        return JSONResponse({"detail": "Token not found"}, status_code=404)
    if pat.get("revoked_at"):
        return JSONResponse({"detail": "Cannot rotate revoked token"}, status_code=409)

    try:
        exp_dt = _parse_pat_expiry(pat.get("expires_at"))
        if exp_dt and pat.get("token_jti"):
            blacklist_token(_config.auth.sqlite_path, str(pat["token_jti"]), exp_dt)
    except sqlite3.Error:
        logger.exception("Failed to blacklist old PAT on rotate jti=%s", pat.get("token_jti"))

    revoke_user_personal_access_token(_config.auth.sqlite_path, user_id, token_id)

    lifetime_minutes = int(pat.get("lifetime_minutes") or PAT_LIFETIME_OPTIONS_MINUTES["long"])
    new_token = create_access_token(
        user_id=user_id,
        username=username,
        is_superuser=False,
        config=_config.jwt,
        expire_minutes=lifetime_minutes,
    )
    decoded = decode_token_unsafe(new_token)
    jti = decoded.get("jti")
    exp = decoded.get("exp")
    if not jti or not exp:
        return JSONResponse({"detail": "Failed to rotate token"}, status_code=500)

    new_exp_dt = datetime.fromtimestamp(int(exp), tz=timezone.utc)
    new_id = create_user_personal_access_token(
        _config.auth.sqlite_path,
        user_id=user_id,
        token_name=str(pat.get("token_name") or "Personal Token"),
        token_jti=str(jti),
        expires_at=new_exp_dt,
        lifetime_minutes=lifetime_minutes,
    )
    return JSONResponse(
        {
            "id": new_id,
            "name": pat.get("token_name"),
            "access_token": new_token,
            "expires_at": new_exp_dt.isoformat(),
            "lifetime_minutes": lifetime_minutes,
        }
    )
