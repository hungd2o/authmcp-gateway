"""Admin API: MCP server management."""

import asyncio
import hmac
import json
import logging
import os
import shlex
from datetime import datetime
from io import StringIO

import jwt
from dotenv import dotenv_values
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse

from authmcp_gateway.admin.routes import api_error_handler, get_config, render_template

logger = logging.getLogger(__name__)

__all__ = [
    "admin_mcp_servers",
    "admin_whitelist",
    "parse_jwt_expiration",
    "api_list_mcp_servers",
    "api_mcp_servers_token_status",
    "api_create_mcp_server",
    "api_delete_mcp_server",
    "api_update_mcp_server",
    "api_test_mcp_server",
    "api_get_mcp_server_tools",
    "api_mcp_server_process_action",
    "api_whitelist_pending",
    "api_whitelist_servers_action",
    "api_whitelist_virtual_tools_action",
]


async def admin_mcp_servers(_: Request) -> HTMLResponse:
    """MCP servers management page."""
    from authmcp_gateway.settings_manager import get_settings_manager

    try:
        sm = get_settings_manager()
        default_timeout = sm.get("timeouts", "proxy_timeout", default=30)
    except Exception:
        default_timeout = 30

    return render_template(
        "admin/mcp_servers.html",
        active_page="mcp-servers",
        default_timeout=default_timeout,
    )


async def admin_whitelist(_: Request) -> HTMLResponse:
    """Whitelist approval page."""
    return render_template("admin/whitelist.html", active_page="whitelist")


def parse_jwt_expiration(token: str) -> dict:
    """Parse JWT token to extract expiration info.

    Args:
        token: JWT token string

    Returns:
        Dict with expires_at, days_left, status or {"status": "unknown"}
    """
    try:
        # Decode without signature verification (we just need exp claim)
        decoded = jwt.decode(token, options={"verify_signature": False})
        exp = decoded.get("exp")

        if exp:
            exp_dt = datetime.fromtimestamp(exp)
            now = datetime.now()
            days_left = (exp_dt - now).days

            # Determine status
            if days_left < 0:
                status = "expired"
            elif days_left < 7:
                status = "warning"
            else:
                status = "ok"

            return {
                "expires_at": exp_dt.isoformat(),
                "expires_at_formatted": exp_dt.strftime("%Y-%m-%d %H:%M"),
                "days_left": days_left,
                "status": status,
                "has_expiration": True,
            }
        else:
            # JWT without exp claim - never expires
            return {"status": "never", "has_expiration": False, "message": "No expiration"}
    except Exception as e:
        logger.debug(f"Failed to parse JWT token: {e}")

    return {"status": "unknown", "has_expiration": False, "message": "Not a JWT token"}


def _schedule_health_check(db_path: str, server_id: int) -> None:
    """Queue a background health check without blocking the admin request."""

    async def _run() -> None:
        from authmcp_gateway.mcp.health import get_health_checker
        from authmcp_gateway.mcp.store import get_mcp_server

        try:
            health_checker = get_health_checker()
            server = get_mcp_server(db_path, server_id)
            if server and server.get("approval_state") == "approved":
                await health_checker.check_server(server)
        except Exception as e:
            logger.debug(f"Health check skipped for server {server_id}: {e}")

    asyncio.create_task(_run())


async def api_list_mcp_servers(request: Request) -> JSONResponse:
    """API: List all MCP servers."""
    from authmcp_gateway.mcp.store import list_mcp_servers

    servers = list_mcp_servers(get_config(request).auth.sqlite_path)
    try:
        from authmcp_gateway.mcp.process_manager import get_process_manager

        process_manager = get_process_manager()
    except Exception:
        process_manager = None

    for server in servers:
        transport_type = (server.get("transport_type") or "http").lower()
        if transport_type == "stdio" and process_manager is not None:
            server["process_status"] = process_manager.get_status(server["id"])
        elif transport_type == "pipe":
            server["process_status"] = "n/a"
        else:
            server["process_status"] = "n/a"

    return JSONResponse({"servers": servers})


def _normalize_transport_payload(data: dict) -> dict:
    """Normalize and validate transport payload fields."""
    transport_type = (data.get("transport_type") or "http").lower()
    data["transport_type"] = transport_type

    if isinstance(data.get("command_args"), str):
        raw = data.get("command_args", "")
        normalized_raw = _strip_hash_comments(raw)
        if not normalized_raw.strip():
            data["command_args"] = []
        else:
            try:
                parsed = json.loads(normalized_raw)
                data["command_args"] = (
                    [str(part) for part in parsed] if isinstance(parsed, list) else []
                )
            except json.JSONDecodeError:
                try:
                    data["command_args"] = shlex.split(normalized_raw)
                except ValueError as exc:
                    raise ValueError(f"Invalid command_args: {exc}") from exc
    elif isinstance(data.get("command_args"), list):
        data["command_args"] = [str(part) for part in data["command_args"]]
    elif data.get("command_args") is None:
        data["command_args"] = []
    else:
        raise ValueError("command_args must be a JSON array, list, or string")
    if isinstance(data.get("env_vars"), str):
        raw_env = data.get("env_vars", "")
        if not raw_env.strip():
            data["env_vars"] = {}
        else:
            parsed_env = dotenv_values(stream=StringIO(raw_env))
            invalid_keys = [key for key, value in parsed_env.items() if value is None]
            if invalid_keys:
                raise ValueError(
                    "Invalid env_vars line(s): expected KEY=VALUE for "
                    + ", ".join(sorted(invalid_keys))
                )
            data["env_vars"] = {str(key): str(value) for key, value in parsed_env.items()}
    elif isinstance(data.get("env_vars"), dict):
        data["env_vars"] = {str(key): str(value) for key, value in data["env_vars"].items()}
    elif data.get("env_vars") is None:
        data["env_vars"] = {}
    else:
        raise ValueError("env_vars must be a mapping or KEY=VALUE lines")

    if "expose_port" in data:
        try:
            data["expose_port"] = int(data["expose_port"]) if data["expose_port"] else None
        except (TypeError, ValueError):
            data["expose_port"] = None

    if transport_type == "http" and not data.get("url"):
        raise ValueError("url is required for http transport")
    if transport_type == "stdio" and not data.get("command"):
        raise ValueError("command is required for stdio transport")
    if transport_type == "pipe" and not data.get("pipe_path"):
        raise ValueError("pipe_path is required for pipe transport")

    return data


def _strip_hash_comments(raw: str) -> str:
    """Strip shell-style # comments outside quoted strings."""
    cleaned_lines = []
    for line in raw.splitlines():
        cleaned_line = _strip_hash_comment_from_line(line).strip()
        if cleaned_line:
            cleaned_lines.append(cleaned_line)
    return "\n".join(cleaned_lines)


def _strip_hash_comment_from_line(line: str) -> str:
    """Strip inline # comments when they begin a comment region."""
    in_single_quote = False
    in_double_quote = False
    escaped = False

    for idx, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and (in_single_quote or in_double_quote):
            escaped = True
            continue
        if char == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
            continue
        if char == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
            continue
        if (
            char == "#"
            and not in_single_quote
            and not in_double_quote
            and (idx == 0 or line[idx - 1].isspace())
        ):
            return line[:idx].rstrip()

    return line


async def api_mcp_servers_token_status(request: Request) -> JSONResponse:
    """API: Get token expiration status for all MCP servers."""
    from authmcp_gateway.mcp.store import list_mcp_servers

    servers = list_mcp_servers(get_config(request).auth.sqlite_path)

    result = []
    for server in servers:
        token_info = {"status": "none"}  # Default for servers without auth

        # Only check Bearer tokens
        if server.get("auth_type") == "bearer" and server.get("auth_token"):
            token_info = parse_jwt_expiration(server["auth_token"])

        result.append(
            {
                "id": server["id"],
                "name": server["name"],
                "auth_type": server["auth_type"],
                "token_status": token_info,
            }
        )

    return JSONResponse({"servers": result})


@api_error_handler
async def api_create_mcp_server(request: Request) -> JSONResponse:
    """API: Create new MCP server."""
    from authmcp_gateway.mcp.store import create_mcp_server, get_mcp_server

    _config = get_config(request)
    data = await request.json()
    data = _normalize_transport_payload(data)

    # Parse timeout: None means "use global default"
    timeout_val = data.get("timeout")
    if timeout_val is not None:
        try:
            timeout_val = int(timeout_val) if timeout_val else None
        except (ValueError, TypeError):
            timeout_val = None

    server_id = create_mcp_server(
        db_path=_config.auth.sqlite_path,
        name=data["name"],
        url=data.get("url") or "",
        description=data.get("description"),
        tool_prefix=data.get("tool_prefix"),
        enabled=data.get("enabled", True),
        auth_type=data.get("auth_type", "none"),
        auth_token=data.get("auth_token"),
        routing_strategy=data.get("routing_strategy", "prefix"),
        timeout=timeout_val,
        transport_type=data.get("transport_type", "http"),
        command=data.get("command"),
        command_args=data.get("command_args"),
        pipe_path=data.get("pipe_path"),
        expose_port=data.get("expose_port"),
        working_dir=data.get("working_dir"),
        env_vars=data.get("env_vars"),
    )

    server = get_mcp_server(_config.auth.sqlite_path, server_id)
    if server and server.get("approval_state") == "approved":
        _schedule_health_check(_config.auth.sqlite_path, server_id)

    return JSONResponse(
        {
            "id": server_id,
            "message": "Server created successfully",
            "approval_state": (server or {}).get("approval_state", "pending"),
        }
    )


@api_error_handler
async def api_delete_mcp_server(request: Request) -> JSONResponse:
    """API: Delete MCP server."""
    from authmcp_gateway.mcp.store import delete_mcp_server

    _config = get_config(request)
    server_id = int(request.path_params["server_id"])

    success = delete_mcp_server(_config.auth.sqlite_path, server_id)

    if success:
        # Invalidate cache
        from authmcp_gateway.mcp.proxy import McpProxy

        proxy = McpProxy(_config.auth.sqlite_path)
        proxy.invalidate_cache(server_id)

        return JSONResponse({"message": "Server deleted successfully"})
    else:
        return JSONResponse({"error": "Server not found"}, status_code=404)


@api_error_handler
async def api_update_mcp_server(request: Request) -> JSONResponse:
    """API: Update MCP server."""
    from authmcp_gateway.mcp.store import get_mcp_server, update_mcp_server

    _config = get_config(request)
    server_id = int(request.path_params["server_id"])
    data = await request.json()

    # Sanitize timeout: empty/zero → None (use global default)
    if "timeout" in data:
        try:
            data["timeout"] = int(data["timeout"]) if data["timeout"] else None
        except (ValueError, TypeError):
            data["timeout"] = None

    requested_fields = set(data.keys())
    current = get_mcp_server(_config.auth.sqlite_path, server_id)
    if not current:
        return JSONResponse({"error": "Server not found"}, status_code=404)
    merged = {**current, **data}
    normalized = _normalize_transport_payload(merged)
    data = {key: normalized.get(key) for key in requested_fields}

    # Update server
    success = update_mcp_server(db_path=_config.auth.sqlite_path, server_id=server_id, **data)

    if success:
        # Invalidate cache
        from authmcp_gateway.mcp.proxy import McpProxy

        proxy = McpProxy(_config.auth.sqlite_path)
        proxy.invalidate_cache(server_id)

        server = get_mcp_server(_config.auth.sqlite_path, server_id)
        if server and server.get("approval_state") == "approved":
            _schedule_health_check(_config.auth.sqlite_path, server_id)

        return JSONResponse({"message": "Server updated successfully"})
    else:
        return JSONResponse({"error": "Server not found"}, status_code=404)


@api_error_handler
async def api_test_mcp_server(request: Request) -> JSONResponse:
    """API: Test MCP server connection."""
    from authmcp_gateway.mcp.health import HealthChecker
    from authmcp_gateway.mcp.store import get_mcp_server

    _config = get_config(request)
    server_id = int(request.path_params["server_id"])
    server = get_mcp_server(_config.auth.sqlite_path, server_id)

    if not server:
        return JSONResponse({"error": "Server not found"}, status_code=404)
    if server.get("approval_state") != "approved":
        return JSONResponse(
            {
                "error": server.get("blocked_reason")
                or "Server is pending whitelist approval and cannot be tested"
            },
            status_code=403,
        )

    # Perform health check
    health_checker = HealthChecker(_config.auth.sqlite_path)
    result = await health_checker.check_server(server)

    # Convert datetime to ISO string for JSON serialization
    if "checked_at" in result and result["checked_at"]:
        result["checked_at"] = result["checked_at"].isoformat()

    return JSONResponse(result)


@api_error_handler
async def api_get_mcp_server_tools(request: Request) -> JSONResponse:
    """API: Get tools from MCP server."""
    from authmcp_gateway.mcp.proxy import McpProxy
    from authmcp_gateway.mcp.store import get_mcp_server, list_virtual_tools

    _config = get_config(request)
    server_id = int(request.path_params["server_id"])
    server = get_mcp_server(_config.auth.sqlite_path, server_id)

    if not server:
        return JSONResponse({"error": "Server not found"}, status_code=404)
    if server.get("approval_state") != "approved":
        return JSONResponse(
            {
                "error": server.get("blocked_reason")
                or "Server is pending whitelist approval and tools cannot be listed"
            },
            status_code=403,
        )

    # Fetch tools from server
    proxy = McpProxy(_config.auth.sqlite_path)
    tools = await proxy._fetch_tools_from_server(server)
    virtual_tools = list_virtual_tools(
        _config.auth.sqlite_path,
        mcp_server_id=server_id,
        enabled_only=True,
    )

    result_tools = []
    for tool in tools:
        result_tools.append(
            {
                "name": tool.get("name"),
                "description": tool.get("description"),
                "input_schema": tool.get("inputSchema") or {},
                "source_server": server.get("name"),
                "approval_state": "approved",
                "tool_type": "native",
            }
        )
    for tool in virtual_tools:
        result_tools.append(
            {
                "name": tool.get("name"),
                "description": tool.get("description"),
                "input_schema": (tool.get("config") or {}).get("input_schema", {}),
                "source_server": tool.get("source_server_name") or server.get("name"),
                "approval_state": tool.get("approval_state", "pending"),
                "tool_type": "virtual",
            }
        )

    return JSONResponse({"server": server, "tools": result_tools})


@api_error_handler
async def api_mcp_server_process_action(request: Request) -> JSONResponse:
    """API: control stdio process lifecycle (start/stop/restart)."""
    from authmcp_gateway.mcp.process_manager import get_process_manager
    from authmcp_gateway.mcp.store import get_mcp_server

    _config = get_config(request)
    server_id = int(request.path_params["server_id"])
    action = request.path_params["action"]

    server = get_mcp_server(_config.auth.sqlite_path, server_id)
    if not server:
        return JSONResponse({"error": "Server not found"}, status_code=404)
    if server.get("approval_state") != "approved":
        return JSONResponse(
            {
                "error": server.get("blocked_reason")
                or "Server is pending whitelist approval and process control is blocked"
            },
            status_code=403,
        )

    if (server.get("transport_type") or "http").lower() != "stdio":
        return JSONResponse(
            {"error": "Process actions are supported only for stdio transport"}, status_code=400
        )

    process_manager = get_process_manager()
    if action == "start":
        await process_manager.start_server(server_id, server)
    elif action == "stop":
        await process_manager.stop_server(server_id)
    elif action == "restart":
        await process_manager.restart_server(server_id)
    else:
        return JSONResponse({"error": "Invalid action"}, status_code=400)

    return JSONResponse(
        {"message": f"Process {action} requested", "status": process_manager.get_status(server_id)}
    )


def _has_valid_whitelist_token(request: Request) -> bool:
    expected_token = (os.getenv("MCP_WHITELIST_TOKEN") or "").strip()
    provided_token = (request.headers.get("x-whitelist-token") or "").strip()
    return bool(
        expected_token and provided_token and hmac.compare_digest(provided_token, expected_token)
    )


def _whitelist_token_error() -> JSONResponse:
    return JSONResponse({"error": "Valid whitelist token required"}, status_code=401)


@api_error_handler
async def api_whitelist_pending(request: Request) -> JSONResponse:
    from authmcp_gateway.mcp.store import list_pending_mcp_servers, list_pending_virtual_tools

    if not _has_valid_whitelist_token(request):
        return _whitelist_token_error()

    db_path = get_config(request).auth.sqlite_path
    return JSONResponse(
        {
            "servers": list_pending_mcp_servers(db_path),
            "virtual_tools": list_pending_virtual_tools(db_path),
        }
    )


@api_error_handler
async def api_whitelist_servers_action(request: Request) -> JSONResponse:
    from authmcp_gateway.mcp.store import update_server_approval

    if not _has_valid_whitelist_token(request):
        return _whitelist_token_error()

    server_id = int(request.path_params["server_id"])
    payload = await request.json()
    action = (payload.get("action") or "").lower()
    reason = payload.get("reason")
    allowlist_policy = payload.get("allowlist_policy")
    actor = payload.get("actor") or "whitelist-admin"
    approval_state = {"approve": "approved", "reject": "rejected", "revoke": "revoked"}.get(action)
    if not approval_state:
        return JSONResponse({"error": "Invalid action"}, status_code=400)

    success = update_server_approval(
        get_config(request).auth.sqlite_path,
        server_id=server_id,
        approval_state=approval_state,
        actor=actor,
        blocked_reason=reason,
        allowlist_policy=allowlist_policy,
    )
    if not success:
        return JSONResponse(
            {"error": "Server not found or does not match allowlist policy"},
            status_code=400,
        )
    return JSONResponse({"message": f"Server {approval_state}"})


@api_error_handler
async def api_whitelist_virtual_tools_action(request: Request) -> JSONResponse:
    from authmcp_gateway.mcp.store import update_virtual_tool_approval

    if not _has_valid_whitelist_token(request):
        return _whitelist_token_error()

    tool_id = int(request.path_params["tool_id"])
    payload = await request.json()
    action = (payload.get("action") or "").lower()
    reason = payload.get("reason")
    actor = payload.get("actor") or "whitelist-admin"
    approval_state = {"approve": "approved", "reject": "rejected", "revoke": "revoked"}.get(action)
    if not approval_state:
        return JSONResponse({"error": "Invalid action"}, status_code=400)
    if not update_virtual_tool_approval(
        get_config(request).auth.sqlite_path,
        tool_id=tool_id,
        approval_state=approval_state,
        actor=actor,
        blocked_reason=reason,
    ):
        return JSONResponse({"error": "Virtual tool not found"}, status_code=404)
    return JSONResponse({"message": f"Virtual tool {approval_state}"})
