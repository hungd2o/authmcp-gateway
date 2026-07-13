"""Admin API: API Keys (Personal Access Tokens) management."""

import logging

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse

from authmcp_gateway.admin.routes import api_error_handler, get_config, render_template
from authmcp_gateway.auth.user_store import (
    admin_revoke_personal_access_token,
    list_all_personal_access_tokens,
)

logger = logging.getLogger(__name__)

__all__ = [
    "admin_api_keys",
    "api_list_all_api_keys",
    "api_revoke_api_key",
]


async def admin_api_keys(request: Request) -> HTMLResponse:
    """Admin API keys management page."""
    return render_template("admin/api_keys.html", active_page="api-keys")


@api_error_handler
async def api_list_all_api_keys(request: Request) -> JSONResponse:
    """API: List all personal access tokens across all users."""
    _config = get_config(request)
    admin_user_id = request.state.user_id
    rows = list_all_personal_access_tokens(_config.auth.sqlite_path)
    return JSONResponse({"tokens": rows, "current_user_id": admin_user_id})


@api_error_handler
async def api_revoke_api_key(request: Request) -> JSONResponse:
    """API: Revoke a personal access token by ID (admin)."""
    _config = get_config(request)
    token_id = int(request.path_params["token_id"])
    revoked = admin_revoke_personal_access_token(_config.auth.sqlite_path, token_id)
    if not revoked:
        return JSONResponse(
            {"detail": "Token not found or already revoked"}, status_code=404
        )
    return JSONResponse({"status": "revoked"})
