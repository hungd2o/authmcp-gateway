"""Admin API: API Keys (Personal Access Tokens) management."""

import logging
from datetime import datetime, timezone
from typing import Any

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse

from authmcp_gateway.admin.routes import api_error_handler, get_config, render_template
from authmcp_gateway.admin.user_pages import PAT_LIFETIME_OPTIONS_MINUTES, _parse_pat_expiry
from authmcp_gateway.auth.jwt_handler import create_access_token, decode_token_unsafe
from authmcp_gateway.auth.user_store import (
    admin_revoke_personal_access_token,
    blacklist_token,
    create_user_personal_access_token,
    get_personal_access_token_by_id,
    list_all_personal_access_tokens,
)

logger = logging.getLogger(__name__)

__all__ = [
    "admin_api_keys",
    "api_list_all_api_keys",
    "api_create_api_key",
    "api_revoke_api_key",
]


def _serialize_admin_pat_row(row: dict[str, Any]) -> dict[str, Any]:
    exp_dt = _parse_pat_expiry(row.get("expires_at"))
    expires_in_seconds = None
    if exp_dt:
        expires_in_seconds = int((exp_dt - datetime.now(timezone.utc)).total_seconds())
    revoked = row.get("revoked_at")
    return {
        **row,
        "name": row.get("token_name"),
        "expires_at": exp_dt.isoformat() if exp_dt else row.get("expires_at"),
        "expires_in_seconds": expires_in_seconds,
        "is_active": revoked is None and (expires_in_seconds is None or expires_in_seconds > 0),
    }


async def admin_api_keys(request: Request) -> HTMLResponse:
    """Admin API keys management page."""
    return render_template("admin/api_keys.html", active_page="api-keys")


@api_error_handler
async def api_list_all_api_keys(request: Request) -> JSONResponse:
    """API: List all personal access tokens across all users."""
    _config = get_config(request)
    admin_user_id = request.state.user_id
    rows = list_all_personal_access_tokens(_config.auth.sqlite_path)
    return JSONResponse(
        {
            "tokens": [_serialize_admin_pat_row(row) for row in rows],
            "current_user_id": admin_user_id,
            "lifetime_options": {
                key: int(minutes) for key, minutes in PAT_LIFETIME_OPTIONS_MINUTES.items()
            },
        }
    )


@api_error_handler
async def api_create_api_key(request: Request) -> JSONResponse:
    """API: Create a personal access token for the current admin user."""
    _config = get_config(request)
    user_id = int(request.state.user_id)
    username = str(request.state.username or "").strip()

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
        is_superuser=True,
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


@api_error_handler
async def api_revoke_api_key(request: Request) -> JSONResponse:
    """API: Revoke a personal access token by ID (admin)."""
    _config = get_config(request)
    token_id = int(request.path_params["token_id"])
    token = get_personal_access_token_by_id(_config.auth.sqlite_path, token_id)
    if not token:
        return JSONResponse({"detail": "Token not found or already revoked"}, status_code=404)
    revoked = admin_revoke_personal_access_token(_config.auth.sqlite_path, token_id)
    if not revoked:
        return JSONResponse({"detail": "Token not found or already revoked"}, status_code=404)
    exp_dt = _parse_pat_expiry(token.get("expires_at"))
    if exp_dt and token.get("token_jti"):
        blacklist_token(_config.auth.sqlite_path, str(token["token_jti"]), exp_dt)
    return JSONResponse({"status": "revoked"})
