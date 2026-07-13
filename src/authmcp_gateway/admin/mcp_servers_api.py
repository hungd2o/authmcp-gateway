"""Admin API: MCP server management."""

import json
import logging
import shlex
from datetime import datetime

import jwt
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse

from authmcp_gateway.admin.routes import api_error_handler, get_config, render_template

logger = logging.getLogger(__name__)

__all__ = [
    "admin_mcp_servers",
    "parse_jwt_expiration",
    "api_list_mcp_servers",
    "api_mcp_servers_token_status",
    "api_create_mcp_server",
    "api_delete_mcp_server",
    "api_update_mcp_server",
    "api_test_mcp_server",
    "api_get_mcp_server_tools",
    "api_mcp_server_process_action",
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
        raw = data.get("command_args", "").strip()
        if not raw:
            data["command_args"] = []
        else:
            try:
                parsed = json.loads(raw)
                data["command_args"] = [str(part) for part in parsed] if isinstance(parsed, list) else []
            except json.JSONDecodeError:
                try:
                    data["command_args"] = shlex.split(raw)
                except ValueError as exc:
                    raise ValueError(f"Invalid command_args: {exc}") from exc
    elif isinstance(data.get("command_args"), list):
        data["command_args"] = [str(part) for part in data["command_args"]]
    elif data.get("command_args") is None:
        data["command_args"] = []
    else:
        raise ValueError("command_args must be a JSON array, list, or string")
    if isinstance(data.get("env_vars"), str):
        raw_env = data.get("env_vars", "").strip()
        if not raw_env:
            data["env_vars"] = {}
        else:
            try:
                parsed_env = json.loads(raw_env)
                data["env_vars"] = parsed_env if isinstance(parsed_env, dict) else {}
            except json.JSONDecodeError:
                data["env_vars"] = {}

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
    from authmcp_gateway.mcp.store import create_mcp_server

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

    # Trigger health check for new server
    from authmcp_gateway.mcp.health import get_health_checker

    try:
        health_checker = get_health_checker()
        from authmcp_gateway.mcp.store import get_mcp_server

        server = get_mcp_server(_config.auth.sqlite_path, server_id)
        if server:
            await health_checker.check_server(server)
    except Exception as e:
        # Health checker might not be initialized yet; log for visibility.
        logger.debug(f"Health check skipped for new server {server_id}: {e}")

    return JSONResponse({"id": server_id, "message": "Server created successfully"})


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

        # Trigger health check for updated server
        from authmcp_gateway.mcp.health import get_health_checker

        try:
            health_checker = get_health_checker()
            server = get_mcp_server(_config.auth.sqlite_path, server_id)
            if server:
                await health_checker.check_server(server)
        except Exception as e:
            # Health checker might not be initialized yet; log for visibility.
            logger.debug(f"Health check skipped for updated server {server_id}: {e}")

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
    from authmcp_gateway.mcp.store import get_mcp_server

    _config = get_config(request)
    server_id = int(request.path_params["server_id"])
    server = get_mcp_server(_config.auth.sqlite_path, server_id)

    if not server:
        return JSONResponse({"error": "Server not found"}, status_code=404)

    # Fetch tools from server
    proxy = McpProxy(_config.auth.sqlite_path)
    tools = await proxy._fetch_tools_from_server(server)

    # Extract tool names
    tool_names = [tool.get("name") for tool in tools if "name" in tool]

    return JSONResponse(tool_names)


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
