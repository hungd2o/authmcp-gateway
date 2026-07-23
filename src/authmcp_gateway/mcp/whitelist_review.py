"""Safe, explicit Whitelist review payloads and approval snapshots.

This module turns a server or virtual-tool record into either a compact queue
summary or a full review document for Whitelist administrators.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

def _text(value: Any) -> str:
    return str(value) if value is not None else ""


def _display(value: Any, *, key: str | None = None) -> dict[str, Any]:
    if value is None:
        return {"value": "Not configured", "state": "not_configured"}
    if value == "":
        return {"value": "Empty", "state": "empty"}
    return {"value": value, "state": "configured"}


def _safe_url(value: Any) -> dict[str, Any]:
    raw = _text(value)
    if not raw:
        return {
            "complete": "Not configured",
            "scheme": "",
            "host": "",
            "port": None,
            "path": "",
            "https": False,
        }
    parsed = urlsplit(raw)
    return {
        "complete": raw,
        "scheme": parsed.scheme.lower(),
        "host": parsed.hostname or "",
        "port": parsed.port,
        "path": parsed.path or "/",
        "https": parsed.scheme.lower() == "https",
    }


def _env_rows(values: Any) -> list[dict[str, Any]]:
    if not isinstance(values, dict):
        return []
    return [
        {"name": str(name), **_display(value, key=str(name))}
        for name, value in sorted(values.items(), key=lambda item: str(item[0]).lower())
    ]


def _field(
    key: str,
    label: str,
    value: Any,
    *,
    display_type: str = "text",
    fingerprinted: bool = True,
) -> dict[str, Any]:
    if display_type in {"json", "list", "environment"}:
        return {
            "key": key,
            "label": label,
            "value": value,
            "display_type": display_type,
            "fingerprinted": fingerprinted,
        }
    return {
        "key": key,
        "label": label,
        **_display(value, key=key),
        "display_type": display_type,
        "fingerprinted": fingerprinted,
    }


def _management(server: dict[str, Any]) -> dict[str, Any]:
    value = server.get("management")
    if not isinstance(value, dict):
        value = server.get("management_config")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            value = {"mode": "invalid"}
    return value if isinstance(value, dict) else {"mode": "none"}


def _snapshot_value(value: Any, *, key: str | None = None) -> Any:
    if isinstance(value, dict):
        return {
            str(item_key): _snapshot_value(item_value, key=str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [_snapshot_value(item) for item in value]
    return value


def build_server_approval_snapshot(server: dict[str, Any]) -> dict[str, Any]:
    """Store a safe, comparable configuration snapshot on approval."""
    transport = _text(server.get("transport_type") or "http").lower()
    fields: dict[str, Any] = {
        "enabled": bool(server.get("enabled")),
        "transport_type": transport,
        "tool_prefix": server.get("tool_prefix") or "",
        "routing_strategy": server.get("routing_strategy") or "prefix",
        "timeout": server.get("timeout"),
        "management": _management(server),
    }
    if transport == "http":
        fields["http"] = {
            "url": server.get("url") or "",
            "auth_type": server.get("auth_type") or "none",
            "auth_token": server.get("auth_token"),
            "refresh_token": server.get("refresh_token_hash"),
            "refresh_endpoint": server.get("refresh_endpoint") or "",
        }
    elif transport == "stdio":
        fields["process"] = {
            "command": server.get("command") or "",
            "command_args": list(server.get("command_args") or []),
            "working_dir": server.get("working_dir") or "",
            "env_vars": dict(server.get("env_vars") or {}),
            "min_workers": server.get("min_workers"),
            "max_workers": server.get("max_workers"),
            "expose_port": server.get("expose_port"),
        }
    elif transport == "pipe":
        fields["pipe"] = {
            "pipe_path": server.get("pipe_path") or "",
            "expose_port": server.get("expose_port"),
        }
    return {"version": 2, "fields": fields}


def build_virtual_tool_approval_snapshot(tool: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": 2,
        "fields": {
            "source_server": tool.get("mcp_server_id"),
            "enabled": bool(tool.get("enabled")),
            "name": tool.get("name") or "",
            "execution_type": tool.get("execution_type") or "",
            "config": dict(tool.get("config") or {}),
        },
    }


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(value, dict) and not ("secret" in value and "digest" in value):
        flattened: dict[str, Any] = {}
        for key, item in value.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            flattened.update(_flatten(item, child))
        return flattened
    return {prefix: value}


def _change_label(path: str, *, virtual: bool) -> str:
    labels = {
        "enabled": "Enabled state",
        "transport_type": "Transport type",
        "tool_prefix": "Tool prefix",
        "routing_strategy": "Routing strategy",
        "timeout": "Request timeout",
        "management": "Management configuration",
        "http.url": "HTTP destination",
        "http.auth_type": "Authentication type",
        "http.auth_token": "HTTP credential",
        "http.refresh_token": "Refresh credential",
        "http.refresh_endpoint": "Refresh endpoint",
        "process.command": "Executable",
        "process.command_args": "Command arguments",
        "process.working_dir": "Working directory",
        "process.min_workers": "Minimum workers",
        "process.max_workers": "Maximum workers",
        "process.expose_port": "Exposed port",
        "pipe.pipe_path": "Pipe path",
        "pipe.expose_port": "Exposed port",
        "source_server": "Source MCP server",
        "name": "Tool name",
        "execution_type": "Execution type",
        "config": "Tool configuration",
    }
    if ".env_vars." in path:
        variable = path.rsplit(".", 1)[-1]
        return f"Environment value: {variable}"
    if path.startswith("config.steps"):
        return "Pipeline steps"
    if path.startswith("config.request"):
        return "HTTP request configuration"
    if path.startswith("config."):
        return "Virtual tool configuration"
    return labels.get(path, path.replace("_", " ").replace(".", " · ").title())


def _changes(previous: Any, current: Any, *, virtual: bool = False) -> dict[str, Any]:
    if not isinstance(previous, dict) or previous.get("version") != 2:
        return {
            "status": "first_approval",
            "summary": "First approval — no previous approved configuration is available for comparison.",
            "items": [],
        }
    old_values = _flatten(previous.get("fields", {}))
    new_values = _flatten(current.get("fields", {}))
    items: list[dict[str, str]] = []
    for path in sorted(set(old_values) | set(new_values)):
        before, after = old_values.get(path), new_values.get(path)
        if before == after:
            continue
        change = (
            "added"
            if path not in old_values
            else "removed" if path not in new_values else "changed"
        )
        items.append(
            {
                "field": path,
                "label": _change_label(path, virtual=virtual),
                "change": change,
                "severity": (
                    "high"
                    if any(
                        token in path
                        for token in ("command", "url", "env", "steps", "management", "auth")
                    )
                    else "medium"
                ),
            }
        )
    return {
        "status": "unchanged" if not items else "changed",
        "summary": (
            "No configuration changes since the previous approval."
            if not items
            else "Changed since previous approval."
        ),
        "items": items,
    }


def _decision(item: dict[str, Any]) -> dict[str, Any]:
    metadata = (
        item.get("approval_metadata") if isinstance(item.get("approval_metadata"), dict) else {}
    )
    return {
        "current_state": item.get("approval_state") or "pending",
        "previous_actor": metadata.get("actor"),
        "previous_at": metadata.get("updated_at") or metadata.get("timestamp"),
        "previous_reason": (
            metadata.get("reason") if metadata.get("reason") else None
        ),
        "blocked_reason": (
            item.get("blocked_reason")
            if item.get("blocked_reason")
            else None
        ),
    }


def _server_risk(server: dict[str, Any]) -> dict[str, Any]:
    transport = _text(server.get("transport_type") or "http").lower()
    reasons: list[str] = []
    if transport in {"stdio", "pipe"}:
        reasons.append("May start or connect to a local process")
    if transport == "stdio" and server.get("working_dir"):
        reasons.append("Uses a configurable local working directory")
    if transport == "stdio" and server.get("env_vars"):
        reasons.append("Receives environment variables")
    if transport == "http":
        url = _safe_url(server.get("url"))
        reasons.append("Sends requests to the configured network destination")
        if url["scheme"] == "http":
            reasons.append("Uses an unencrypted HTTP connection")
    return {
        "level": server.get("risk_level") or ("high" if transport in {"stdio", "pipe"} else "low"),
        "reasons": reasons,
    }


def build_server_whitelist_summary(server: dict[str, Any]) -> dict[str, Any]:
    transport = _text(server.get("transport_type") or "http").lower()
    env = _env_rows(server.get("env_vars"))
    management = _management(server)
    decision = _decision(server)
    snapshot = build_server_approval_snapshot(server)
    changes = _changes((server.get("approval_metadata") or {}).get("snapshot"), snapshot)
    destination = (
        _safe_url(server.get("url"))["complete"]
        if transport == "http"
        else server.get("command") or server.get("pipe_path") or "Not configured"
    )
    return {
        "id": server["id"],
        "kind": "server",
        "name": server.get("name") or "Unnamed server",
        "description": server.get("description") or "",
        "enabled": bool(server.get("enabled")),
        "approval_state": server.get("approval_state") or "pending",
        "risk": _server_risk(server),
        "transport_type": transport,
        "destination": destination,
        "working_dir": server.get("working_dir"),
        "argument_count": len(server.get("command_args") or []),
        "environment": {"count": len(env)},
        "env_vars": dict(server.get("env_vars") or {}),
        "auth_token": server.get("auth_token"),
        "refresh_token_hash": server.get("refresh_token_hash"),
        "worker_pool": {"min": server.get("min_workers"), "max": server.get("max_workers")},
        "management_summary": management.get("mode", "none"),
        "decision": decision,
        "changed": changes,
        "config_fingerprint": server.get("config_fingerprint") or "",
    }


def build_server_whitelist_review(server: dict[str, Any]) -> dict[str, Any]:
    transport = _text(server.get("transport_type") or "http").lower()
    snapshot = build_server_approval_snapshot(server)
    changes = _changes((server.get("approval_metadata") or {}).get("snapshot"), snapshot)
    sections: list[dict[str, Any]] = [
        {
            "key": "identity",
            "title": "Identity and current decision",
            "fields": [
                _field("id", "ID", server.get("id"), fingerprinted=False),
                _field("name", "Name", server.get("name"), fingerprinted=False),
                _field(
                    "description", "Description", server.get("description"), fingerprinted=False
                ),
                _field("enabled", "Enabled", "Enabled" if server.get("enabled") else "Disabled"),
                _field(
                    "approval_state",
                    "Approval state",
                    server.get("approval_state"),
                    fingerprinted=False,
                ),
                _field("risk_level", "Risk level", server.get("risk_level"), fingerprinted=False),
                _field("created_at", "Created", server.get("created_at"), fingerprinted=False),
                _field("updated_at", "Updated", server.get("updated_at"), fingerprinted=False),
            ],
        },
        {
            "key": "routing",
            "title": "Routing and gateway behavior",
            "fields": [
                _field("tool_prefix", "Tool prefix", server.get("tool_prefix")),
                _field("routing_strategy", "Routing strategy", server.get("routing_strategy")),
                _field("timeout", "Request timeout", server.get("timeout")),
                _field("transport_type", "Transport type", transport),
            ],
        },
    ]
    if transport == "http":
        url = _safe_url(server.get("url"))
        sections.append(
            {
                "key": "http",
                "title": "HTTP transport",
                "warning": (
                    "This endpoint is not encrypted (HTTP)." if url["scheme"] == "http" else None
                ),
                "fields": [
                    _field("url", "Complete URL", url["complete"], display_type="code"),
                    _field("url_scheme", "Scheme", url["scheme"]),
                    _field("url_host", "Host", url["host"]),
                    _field("url_port", "Port", url["port"]),
                    _field("url_path", "Path", url["path"]),
                    _field(
                        "https",
                        "Connection security",
                        "HTTPS" if url["https"] else "HTTP (not encrypted)",
                    ),
                    _field("auth_type", "Authentication type", server.get("auth_type") or "none"),
                    _field(
                        "auth_token",
                        "Backend credential",
                        server.get("auth_token") or "Not configured",
                    ),
                    _field(
                        "refresh_token",
                        "Refresh credential",
                        server.get("refresh_token_hash") or "Not configured",
                    ),
                    _field("refresh_endpoint", "Refresh endpoint", server.get("refresh_endpoint")),
                ],
            }
        )
    elif transport == "stdio":
        sections.append(
            {
                "key": "process",
                "title": "Local process",
                "fields": [
                    _field("command", "Executable", server.get("command"), display_type="code"),
                    _field(
                        "command_args",
                        "Arguments",
                        list(server.get("command_args") or []),
                        display_type="list",
                    ),
                    _field(
                        "working_dir",
                        "Working directory",
                        server.get("working_dir"),
                        display_type="code",
                    ),
                    _field(
                        "env_vars",
                        "Environment",
                        _env_rows(server.get("env_vars")),
                        display_type="environment",
                    ),
                    _field("min_workers", "Minimum workers", server.get("min_workers")),
                    _field("max_workers", "Maximum workers", server.get("max_workers")),
                    _field("expose_port", "Exposed port", server.get("expose_port")),
                ],
            }
        )
    elif transport == "pipe":
        sections.append(
            {
                "key": "pipe",
                "title": "Pipe transport",
                "fields": [
                    _field("pipe_path", "Pipe path", server.get("pipe_path"), display_type="code"),
                    _field("timeout", "Request timeout", server.get("timeout")),
                    _field("expose_port", "Exposed port", server.get("expose_port")),
                ],
            }
        )
    sections.append(
        {
            "key": "management",
            "title": "Management configuration",
            "fields": [
                _field(
                    "management",
                    "Configuration",
                    _management(server),
                    display_type="json",
                )
            ],
        }
    )
    return {
        **build_server_whitelist_summary(server),
        "sections": sections,
        "capabilities": _server_risk(server)["reasons"],
        "changes": changes,
        "config_fingerprint": server.get("config_fingerprint") or "",
    }


def _tool_risk(tool: dict[str, Any]) -> dict[str, Any]:
    execution_type = _text(tool.get("execution_type")).lower()
    reasons = []
    if execution_type == "http_call":
        reasons.append("May send network requests with the reviewed request template")
    if execution_type in {"stdio_call", "pipeline_call"}:
        reasons.append("May start the reviewed local process configuration")
        reasons.append("May access the reviewed working directory and environment")
    return {
        "level": (
            "high"
            if execution_type in {"http_call", "stdio_call", "pipeline_call"}
            else tool.get("risk_level") or "low"
        ),
        "reasons": reasons,
    }


def _tool_execution_sections(tool: dict[str, Any]) -> list[dict[str, Any]]:
    config = dict(tool.get("config") or {})
    execution_type = _text(tool.get("execution_type")).lower()
    if execution_type == "http_call":
        request = dict(config.get("request") or {})
        url = _safe_url(request.get("url"))
        return [
            {
                "key": "http_request",
                "title": "HTTP request",
                "warning": (
                    "This endpoint is not encrypted (HTTP)." if url["scheme"] == "http" else None
                ),
                "fields": [
                    _field("request_method", "HTTP method", request.get("method") or "GET"),
                    _field(
                        "request_url",
                        "Complete URL or template",
                        url["complete"],
                        display_type="code",
                    ),
                    _field("request_host", "Destination host", url["host"]),
                    _field(
                        "request_headers",
                        "Headers",
                        request.get("headers") or {},
                        display_type="json",
                    ),
                    _field(
                        "request_query",
                        "Query configuration",
                        request.get("query"),
                        display_type="json",
                    ),
                    _field(
                        "request_body", "Body or template", request.get("body"), display_type="json"
                    ),
                ],
            }
        ]
    if execution_type == "stdio_call":
        return [
            {
                "key": "local_process",
                "title": "Local process",
                "fields": [
                    _field("command", "Executable", config.get("command"), display_type="code"),
                    _field(
                        "command_args",
                        "Arguments",
                        list(config.get("command_args") or []),
                        display_type="list",
                    ),
                    _field(
                        "working_dir",
                        "Working directory",
                        config.get("working_dir"),
                        display_type="code",
                    ),
                    _field(
                        "env_vars",
                        "Environment",
                        _env_rows(config.get("env_vars")),
                        display_type="environment",
                    ),
                    _field(
                        "stdin",
                        "STDIN configuration",
                        config.get("stdin") or {"mode": "json"},
                        display_type="json",
                    ),
                ],
            }
        ]
    if execution_type == "pipeline_call":
        steps = []
        for index, step in enumerate(config.get("steps") or [], start=1):
            if not isinstance(step, dict):
                continue
            steps.append(
                {
                    "index": index,
                    "command": _display(step.get("command"), key="command"),
                    "arguments": list(step.get("command_args") or []),
                    "working_dir": _display(step.get("working_dir"), key="working_dir"),
                    "environment": _env_rows(step.get("env_vars")),
                }
            )
        return [
            {
                "key": "pipeline",
                "title": "Local process pipeline",
                "fields": [
                    _field("steps", "Ordered process steps", steps, display_type="json"),
                    _field(
                        "working_dir",
                        "Shared working directory",
                        config.get("working_dir"),
                        display_type="code",
                    ),
                    _field(
                        "env_vars",
                        "Shared environment",
                        _env_rows(config.get("env_vars")),
                        display_type="environment",
                    ),
                ],
            }
        ]
    return []


def build_virtual_tool_whitelist_summary(tool: dict[str, Any]) -> dict[str, Any]:
    snapshot = build_virtual_tool_approval_snapshot(tool)
    changes = _changes(
        (tool.get("approval_metadata") or {}).get("snapshot"), snapshot, virtual=True
    )
    return {
        "id": tool["id"],
        "kind": "virtual_tool",
        "name": tool.get("name") or "Unnamed virtual tool",
        "description": tool.get("description") or "",
        "enabled": bool(tool.get("enabled")),
        "approval_state": tool.get("approval_state") or "pending",
        "risk": _tool_risk(tool),
        "execution_type": tool.get("execution_type") or "",
        "source_server_name": tool.get("source_server_name") or "Unavailable",
        "editor_mode": (
            (tool.get("config") or {}).get("editor_mode", "advanced")
            if isinstance(tool.get("config"), dict)
            else "advanced"
        ),
        "decision": _decision(tool),
        "changed": changes,
        "config_fingerprint": tool.get("config_fingerprint") or "",
    }


def build_virtual_tool_whitelist_review(tool: dict[str, Any]) -> dict[str, Any]:
    config = dict(tool.get("config") or {})
    snapshot = build_virtual_tool_approval_snapshot(tool)
    changes = _changes(
        (tool.get("approval_metadata") or {}).get("snapshot"), snapshot, virtual=True
    )
    sections = [
        {
            "key": "identity",
            "title": "Identity and current decision",
            "fields": [
                _field("id", "ID", tool.get("id"), fingerprinted=False),
                _field("name", "Name", tool.get("name")),
                _field("description", "Description", tool.get("description"), fingerprinted=False),
                _field("enabled", "Enabled", "Enabled" if tool.get("enabled") else "Disabled"),
                _field(
                    "approval_state",
                    "Approval state",
                    tool.get("approval_state"),
                    fingerprinted=False,
                ),
                _field("risk_level", "Risk level", _tool_risk(tool)["level"], fingerprinted=False),
                _field("source_server_name", "Source MCP server", tool.get("source_server_name")),
                _field("execution_type", "Execution type", tool.get("execution_type")),
                _field("editor_mode", "Editor mode", config.get("editor_mode", "advanced")),
                _field("created_at", "Created", tool.get("created_at"), fingerprinted=False),
                _field("updated_at", "Updated", tool.get("updated_at"), fingerprinted=False),
            ],
        },
        *_tool_execution_sections(tool),
        {
            "key": "input",
            "title": "Input schema",
            "fields": [
                _field(
                    "input_schema",
                    "Input schema",
                    config.get("input_schema") or {},
                    display_type="json",
                )
            ],
        },
        {
            "key": "advanced",
            "title": "Advanced configuration",
            "fields": [_field("config", "Configuration", config, display_type="json")],
        },
    ]
    return {
        **build_virtual_tool_whitelist_summary(tool),
        "sections": sections,
        "capabilities": _tool_risk(tool)["reasons"],
        "changes": changes,
        "config_fingerprint": tool.get("config_fingerprint") or "",
    }
