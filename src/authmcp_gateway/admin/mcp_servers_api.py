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

from authmcp_gateway.admin.routes import (
    api_error_handler,
    get_config,
    get_mcp_runtime,
    render_template,
)
from authmcp_gateway.mcp.templating import validate_template_string, validate_templates_in_value

logger = logging.getLogger(__name__)

_PROTECTED_SERVER_UPDATE_FIELDS = frozenset(
    {
        "allowlist_policy",
        "approval_metadata",
        "approval_state",
        "blocked_reason",
        "config_fingerprint",
        "last_health_check",
        "last_error",
        "refresh_endpoint",
        "refresh_token_encrypted",
        "refresh_token_hash",
        "risk_level",
        "status",
        "token_expires_at",
        "token_last_refreshed",
        "tools_count",
        "updated_at",
    }
)

_PROCESS_DETAIL_STRING_FIELDS = frozenset(
    {
        "desired_state",
        "pool_state",
        "aggregate",
        "config_fingerprint_short",
        "last_crash_at",
        "last_reconcile_at",
    }
)
_PROCESS_DETAIL_INTEGER_FIELDS = frozenset(
    {
        "generation",
        "pool_size",
        "active",
        "idle",
        "queue_depth",
        "restart_count",
    }
)
_PROCESS_DETAIL_WORKER_STRING_FIELDS = frozenset({"worker_id", "state"})
_PROCESS_DETAIL_WORKER_INTEGER_FIELDS = frozenset(
    {"pid", "uptime_secs", "restart_count", "last_exit_code"}
)

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
    "api_create_virtual_tool",
    "api_delete_virtual_tool",
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


def _legacy_process_detail(raw_detail: dict) -> dict:
    """Adapt the current manager summary until get_status_detail() is available."""
    workers_by_state = raw_detail.get("workers")
    if not isinstance(workers_by_state, dict):
        workers_by_state = {}

    worker_counts = {
        state: count
        for state, count in workers_by_state.items()
        if isinstance(state, str) and isinstance(count, int) and not isinstance(count, bool)
    }
    pool_state = raw_detail.get("state")
    detail: dict[str, object] = {
        "pool_state": pool_state,
        "aggregate": pool_state,
        "generation": raw_detail.get("generation"),
        "pool_size": sum(worker_counts.values()),
        "active": worker_counts.get("busy", 0),
        "idle": worker_counts.get("ready", 0),
        "queue_depth": raw_detail.get("waiting"),
    }
    fingerprint = raw_detail.get("fingerprint")
    if isinstance(fingerprint, str):
        detail["config_fingerprint_short"] = fingerprint[:12]
    return detail


def _safe_process_detail(process_manager: object, server_id: int) -> dict | None:
    """Return only the manager's public lifecycle fields for an STDIO server."""
    get_status_detail = getattr(process_manager, "get_status_detail", None)
    legacy_status_detail = getattr(process_manager, "status_detail", None)

    try:
        if callable(get_status_detail):
            raw_detail = get_status_detail(server_id)
        elif callable(legacy_status_detail):
            raw_detail = _legacy_process_detail(legacy_status_detail(server_id))
        else:
            return None
    except Exception:
        logger.debug("Process detail unavailable for server %s", server_id, exc_info=True)
        return None

    if not isinstance(raw_detail, dict):
        logger.debug("Process detail for server %s was not a mapping", server_id)
        return None

    detail: dict[str, object] = {
        field: value
        for field, value in raw_detail.items()
        if field in _PROCESS_DETAIL_STRING_FIELDS and isinstance(value, str)
    }
    detail.update(
        {
            field: value
            for field, value in raw_detail.items()
            if field in _PROCESS_DETAIL_INTEGER_FIELDS
            and isinstance(value, int)
            and not isinstance(value, bool)
        }
    )

    raw_workers = raw_detail.get("workers")
    if isinstance(raw_workers, list):
        workers: list[dict[str, object]] = []
        for raw_worker in raw_workers:
            if not isinstance(raw_worker, dict):
                continue
            worker: dict[str, object] = {
                field: value
                for field, value in raw_worker.items()
                if field in _PROCESS_DETAIL_WORKER_STRING_FIELDS and isinstance(value, str)
            }
            worker.update(
                {
                    field: value
                    for field, value in raw_worker.items()
                    if field in _PROCESS_DETAIL_WORKER_INTEGER_FIELDS
                    and (
                        value is None
                        or (isinstance(value, int) and not isinstance(value, bool))
                        or (field == "uptime_secs" and isinstance(value, float))
                    )
                }
            )
            workers.append(worker)
        detail["workers"] = workers

    return detail or None


async def api_list_mcp_servers(request: Request) -> JSONResponse:
    """API: List all MCP servers."""
    from authmcp_gateway.mcp.store import list_mcp_servers, list_virtual_tools

    db_path = get_config(request).auth.sqlite_path
    servers = list_mcp_servers(db_path)
    process_manager = get_mcp_runtime(request).process_manager

    virtual_tool_counts: dict = {}
    for tool in list_virtual_tools(db_path):
        server_id = tool.get("mcp_server_id")
        virtual_tool_counts[server_id] = virtual_tool_counts.get(server_id, 0) + 1

    for server in servers:
        transport_type = (server.get("transport_type") or "http").lower()
        if transport_type == "stdio":
            server["process_status"] = process_manager.get_status(server["id"])
            process_detail = _safe_process_detail(process_manager, server["id"])
            if process_detail is not None:
                server["process_detail"] = process_detail
        elif transport_type == "pipe":
            server["process_status"] = "n/a"
        else:
            server["process_status"] = "n/a"
        server["virtual_tools_count"] = virtual_tool_counts.get(server["id"], 0)

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


def _normalize_virtual_tool_process_config(config: dict, *, require_command: bool = True) -> dict:
    normalized = dict(config or {})
    if require_command and not str(normalized.get("command") or "").strip():
        raise ValueError("config.command is required")
    normalized["command"] = str(normalized.get("command") or "").strip()

    normalized = _normalize_transport_payload(
        {
            "transport_type": "stdio",
            "command": normalized["command"],
            "command_args": normalized.get("command_args"),
            "env_vars": normalized.get("env_vars"),
        }
    )

    process_config = {
        "command": normalized["command"],
        "command_args": normalized["command_args"],
        "env_vars": normalized["env_vars"],
        "working_dir": (config or {}).get("working_dir") or None,
    }
    validate_templates_in_value(process_config["command_args"], "config.command_args")
    validate_templates_in_value(process_config["env_vars"], "config.env_vars")
    return process_config


def _normalize_virtual_tool_stdin_config(config: dict) -> dict:
    stdin_cfg = dict((config or {}).get("stdin") or {})
    if not stdin_cfg:
        return {"mode": "json"}

    mode = str(stdin_cfg.get("mode") or "json").strip().lower()
    if mode not in {"json", "template", "none"}:
        raise ValueError("config.stdin.mode must be 'json', 'template', or 'none'")

    normalized: dict[str, object] = {"mode": mode}
    if mode == "template":
        if "template" not in stdin_cfg:
            raise ValueError("config.stdin.template is required when stdin.mode='template'")
        validate_templates_in_value(stdin_cfg.get("template"), "config.stdin.template")
        normalized["template"] = stdin_cfg.get("template")
    return normalized


def _normalize_virtual_tool_config(execution_type: str, config: dict) -> dict:
    normalized = dict(config or {})
    editor_mode = str(normalized.get("editor_mode") or "advanced").strip().lower()
    if editor_mode not in {"simple", "advanced"}:
        raise ValueError("config.editor_mode must be 'simple' or 'advanced'")
    normalized["editor_mode"] = editor_mode
    input_schema = normalized.get("input_schema")
    if input_schema is None:
        normalized["input_schema"] = {}
    elif not isinstance(input_schema, dict):
        raise ValueError("config.input_schema must be an object")

    if execution_type == "http_call":
        request_cfg = normalized.get("request") or {}
        if not isinstance(request_cfg, dict):
            raise ValueError("config.request must be an object for http_call")
        method = str(request_cfg.get("method") or "GET").upper()
        url = str(request_cfg.get("url") or "").strip()
        if not url:
            raise ValueError("config.request.url is required for http_call")
        validate_template_string(url)
        headers = request_cfg.get("headers") or {}
        if not isinstance(headers, dict):
            raise ValueError("config.request.headers must be an object for http_call")
        query = request_cfg.get("query")
        if query is not None and not isinstance(query, dict):
            raise ValueError("config.request.query must be an object for http_call")
        body = request_cfg.get("body")
        validate_templates_in_value(headers, "config.request.headers")
        if query is not None:
            validate_templates_in_value(query, "config.request.query")
        if body is not None:
            validate_templates_in_value(body, "config.request.body")
        normalized_request = {
            "method": method,
            "url": url,
            "headers": {str(key): str(value) for key, value in headers.items()},
        }
        if query is not None:
            normalized_request["query"] = {str(key): value for key, value in query.items()}
        if body is not None:
            normalized_request["body"] = body
        normalized["request"] = normalized_request
        return normalized

    if execution_type == "stdio_call":
        process_config = _normalize_virtual_tool_process_config(normalized)
        normalized.update(process_config)
        normalized["stdin"] = _normalize_virtual_tool_stdin_config(normalized)
        return normalized

    if execution_type == "pipeline_call":
        steps = normalized.get("steps")
        if not isinstance(steps, list) or not steps:
            raise ValueError("config.steps must be a non-empty array for pipeline_call")
        normalized_steps = []
        for step in steps:
            if not isinstance(step, dict):
                raise ValueError("Each pipeline step must be an object")
            normalized_steps.append(_normalize_virtual_tool_process_config(step))
        normalized["steps"] = normalized_steps
        env_vars = normalized.get("env_vars")
        if env_vars is not None and not isinstance(env_vars, (dict, str)):
            raise ValueError("config.env_vars must be a mapping or KEY=VALUE lines")
        if env_vars is not None:
            normalized["env_vars"] = _normalize_transport_payload(
                {"transport_type": "stdio", "command": "pipeline", "env_vars": env_vars}
            )["env_vars"]
        else:
            normalized["env_vars"] = {}
        validate_templates_in_value(normalized["env_vars"], "config.env_vars")
        normalized["working_dir"] = normalized.get("working_dir") or None
        return normalized

    raise ValueError("execution_type must be 'http_call', 'stdio_call', or 'pipeline_call'")


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
        runtime = get_mcp_runtime(request)
        remove_server = getattr(runtime, "remove_server", None)
        if callable(remove_server):
            await remove_server(server_id)
        else:
            await runtime.block_and_stop_server(server_id)

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
    if not isinstance(data, dict):
        return JSONResponse({"error": "Request body must be a JSON object"}, status_code=400)

    protected_fields = sorted(_PROTECTED_SERVER_UPDATE_FIELDS.intersection(data))
    if protected_fields:
        return JSONResponse(
            {"error": f"Protected fields cannot be updated here: {', '.join(protected_fields)}"},
            status_code=400,
        )

    # Sanitize timeout: empty/zero → None (use global default)
    if "timeout" in data:
        try:
            data["timeout"] = int(data["timeout"]) if data["timeout"] else None
        except (ValueError, TypeError):
            data["timeout"] = None
    if "enabled" in data:
        if not isinstance(data["enabled"], bool):
            return JSONResponse({"error": "enabled must be a JSON boolean"}, status_code=400)
        data["enabled"] = int(data["enabled"])

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
        server = get_mcp_server(_config.auth.sqlite_path, server_id)
        runtime = get_mcp_runtime(request)
        if server and (
            not server.get("enabled", True) or server.get("approval_state") != "approved"
        ):
            await runtime.block_and_stop_server(server_id)
        elif server:
            await runtime.reconcile_server(server)

        if server and server.get("approval_state") == "approved" and server.get("enabled", True):
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
    if server.get("approval_state") != "approved" or not server.get("enabled", True):
        return JSONResponse(
            {
                "error": server.get("blocked_reason")
                or "Server is disabled or pending whitelist approval and cannot be tested"
            },
            status_code=403,
        )

    runtime = get_mcp_runtime(request)
    if (server.get("transport_type") or "http").lower() == "stdio":
        try:
            await runtime.reconcile_server(server)
            tools_count = await runtime.process_manager.probe_tools(
                server_id, timeout=float(server.get("timeout") or 10)
            )
        except Exception as error:
            from authmcp_gateway.mcp.store import update_server_health

            error_message = str(error).strip() or type(error).__name__
            update_server_health(
                _config.auth.sqlite_path, server_id, status="error", error=error_message
            )
            return JSONResponse({"status": "error", "tools_count": None, "error": error_message})
        from authmcp_gateway.mcp.store import mark_server_online_if_active, update_server_health

        if not mark_server_online_if_active(_config.auth.sqlite_path, server_id, tools_count):
            update_server_health(
                _config.auth.sqlite_path,
                server_id,
                status="offline",
                error="Server is no longer active",
            )
            return JSONResponse(
                {"status": "blocked", "tools_count": None, "error": "Server is no longer active"},
                status_code=409,
            )
        return JSONResponse({"status": "online", "tools_count": tools_count, "error": None})

    # Perform health check for remote transports.
    health_checker = HealthChecker(
        _config.auth.sqlite_path,
        process_manager=runtime.process_manager,
    )
    result = await health_checker.check_server(server)

    # Convert datetime to ISO string for JSON serialization
    if "checked_at" in result and result["checked_at"]:
        result["checked_at"] = result["checked_at"].isoformat()

    return JSONResponse(result)


@api_error_handler
async def api_get_mcp_server_tools(request: Request) -> JSONResponse:
    """API: Get tools from MCP server."""
    from authmcp_gateway.mcp.store import get_mcp_server, list_virtual_tools

    _config = get_config(request)
    server_id = int(request.path_params["server_id"])
    server = get_mcp_server(_config.auth.sqlite_path, server_id)

    if not server:
        return JSONResponse({"error": "Server not found"}, status_code=404)
    if server.get("approval_state") != "approved" or not server.get("enabled", True):
        return JSONResponse(
            {
                "error": server.get("blocked_reason")
                or "Server is disabled or pending whitelist approval and tools cannot be listed"
            },
            status_code=403,
        )

    # Fetch tools through the application-owned proxy.
    tools = await get_mcp_runtime(request).proxy._fetch_tools_from_server(server)
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
                "id": tool.get("id"),
                "name": tool.get("name"),
                "description": tool.get("description"),
                "input_schema": (tool.get("config") or {}).get("input_schema", {}),
                "source_server": tool.get("source_server_name") or server.get("name"),
                "approval_state": tool.get("approval_state", "pending"),
                "tool_type": "virtual",
                "execution_type": tool.get("execution_type"),
            }
        )

    return JSONResponse({"server": server, "tools": result_tools})


@api_error_handler
async def api_mcp_server_process_action(request: Request) -> JSONResponse:
    """API: control stdio process lifecycle (start/stop/restart)."""
    from authmcp_gateway.mcp.store import (
        get_mcp_server,
        mark_server_online_if_active,
        update_server_health,
    )

    _config = get_config(request)
    server_id = int(request.path_params["server_id"])
    action = request.path_params["action"]

    server = get_mcp_server(_config.auth.sqlite_path, server_id)
    if not server:
        return JSONResponse({"error": "Server not found"}, status_code=404)
    if server.get("approval_state") != "approved" or not server.get("enabled", True):
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

    process_manager = get_mcp_runtime(request).process_manager
    if action in {"start", "restart"} and process_manager.is_blocked(server_id):
        return JSONResponse({"error": "STDIO server is blocked"}, status_code=403)
    try:
        if action == "start":
            await process_manager.start_server(server_id, server)
        elif action == "stop":
            await process_manager.stop_server(server_id)
        elif action == "restart":
            await process_manager.restart_server(server_id)
        else:
            return JSONResponse({"error": "Invalid action"}, status_code=400)

        if action in {"start", "restart"}:
            tools_count = await process_manager.probe_tools(
                server_id, timeout=float(server.get("timeout") or 10)
            )
    except Exception as error:
        error_message = str(error).strip() or type(error).__name__
        update_server_health(_config.auth.sqlite_path, server_id, status="error", error=error_message)
        return JSONResponse(
            {
                "error": error_message,
                "message": f"Process {action} failed its backend check",
                "status": process_manager.get_status(server_id),
            },
            status_code=502,
        )

    if action in {"start", "restart"}:
        if not mark_server_online_if_active(_config.auth.sqlite_path, server_id, tools_count):
            update_server_health(
                _config.auth.sqlite_path,
                server_id,
                status="offline",
                error="Server is no longer active",
            )
            return JSONResponse(
                {
                    "error": "Server is no longer active",
                    "status": process_manager.get_status(server_id),
                },
                status_code=409,
            )

    response: dict[str, object] = {
        "message": f"Process {action} requested",
        "status": process_manager.get_status(server_id),
    }
    process_detail = _safe_process_detail(process_manager, server_id)
    if process_detail is not None:
        response["process_detail"] = process_detail
    return JSONResponse(response)


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
    from authmcp_gateway.mcp.store import list_mcp_servers_by_state, list_virtual_tools_by_state
    from authmcp_gateway.mcp.trust import (
        APPROVAL_APPROVED,
        APPROVAL_PENDING,
        APPROVAL_REJECTED,
        APPROVAL_REVOKED,
    )

    if not _has_valid_whitelist_token(request):
        return _whitelist_token_error()

    db_path = get_config(request).auth.sqlite_path
    state_param = (request.query_params.get("state") or "").strip().lower() or None

    valid_states = {APPROVAL_PENDING, APPROVAL_APPROVED, APPROVAL_REJECTED, APPROVAL_REVOKED}
    if state_param and state_param not in valid_states:
        return JSONResponse(
            {"error": f"Invalid state. Must be one of: {', '.join(sorted(valid_states))}"},
            status_code=400,
        )

    servers = list_mcp_servers_by_state(db_path, state_param)
    virtual_tools = list_virtual_tools_by_state(db_path, state_param)

    return JSONResponse(
        {
            "servers": servers,
            "virtual_tools": virtual_tools,
            "state_filter": state_param,
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
    runtime = get_mcp_runtime(request)
    if approval_state == "approved":
        await runtime.allow_server(server_id)
    else:
        await runtime.block_and_stop_server(server_id)
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


@api_error_handler
async def api_create_virtual_tool(request: Request) -> JSONResponse:
    """API: Create a virtual tool for an MCP server."""
    from authmcp_gateway.mcp.store import create_virtual_tool, get_mcp_server

    _config = get_config(request)
    server_id = int(request.path_params["server_id"])

    server = get_mcp_server(_config.auth.sqlite_path, server_id)
    if not server:
        return JSONResponse({"error": "Server not found"}, status_code=404)

    payload = await request.json()
    name = (payload.get("name") or "").strip()
    if not name:
        return JSONResponse({"error": "Tool name is required"}, status_code=400)

    execution_type = (payload.get("execution_type") or "").strip().lower()
    description = (payload.get("description") or "").strip() or None

    try:
        config = _normalize_virtual_tool_config(execution_type, payload.get("config") or {})
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    try:
        tool_id = create_virtual_tool(
            db_path=_config.auth.sqlite_path,
            mcp_server_id=server_id,
            name=name,
            description=description,
            execution_type=execution_type,
            config=config,
            enabled=True,
        )
    except Exception as exc:
        logger.error("Failed to create virtual tool: %s", exc)
        return JSONResponse({"error": str(exc)}, status_code=500)

    return JSONResponse({"tool_id": tool_id}, status_code=201)


@api_error_handler
async def api_delete_virtual_tool(request: Request) -> JSONResponse:
    """API: Delete a virtual tool."""
    from authmcp_gateway.mcp.store import delete_virtual_tool, get_virtual_tool

    _config = get_config(request)
    server_id = int(request.path_params["server_id"])
    tool_id = int(request.path_params["tool_id"])

    tool = get_virtual_tool(_config.auth.sqlite_path, tool_id)
    if not tool:
        return JSONResponse({"error": "Virtual tool not found"}, status_code=404)
    if tool.get("mcp_server_id") != server_id:
        return JSONResponse(
            {"error": "Virtual tool does not belong to this server"}, status_code=404
        )

    success = delete_virtual_tool(_config.auth.sqlite_path, tool_id)
    if success:
        return JSONResponse({"message": "Virtual tool deleted"})
    return JSONResponse({"error": "Failed to delete virtual tool"}, status_code=500)
