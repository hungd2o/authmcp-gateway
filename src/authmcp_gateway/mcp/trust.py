"""Zero-trust MCP approval and policy helpers."""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

APPROVAL_APPROVED = "approved"
APPROVAL_PENDING = "pending"
APPROVAL_REJECTED = "rejected"
APPROVAL_REVOKED = "revoked"

RISK_HIGH = "high"
RISK_LOW = "low"

HTTP_POLICY_DEFAULT_SCHEME = "https"
HTTP_POLICY_DEFAULT_PORT = 443


def default_risk_level(transport_type: Optional[str]) -> str:
    transport = (transport_type or "http").lower()
    if transport in {"stdio", "pipe"}:
        return RISK_HIGH
    return RISK_LOW


def approval_is_active(state: Optional[str]) -> bool:
    return (state or APPROVAL_PENDING).lower() == APPROVAL_APPROVED


def build_server_fingerprint(server: Dict[str, Any]) -> str:
    """Return deterministic SHA256 fingerprint for a server runtime config."""
    transport = (server.get("transport_type") or "http").lower()
    payload: Dict[str, Any] = {"transport_type": transport}
    if transport == "http":
        payload["url"] = server.get("url") or ""
    elif transport == "stdio":
        payload["command"] = server.get("command") or ""
        payload["command_args"] = list(server.get("command_args") or [])
        payload["working_dir"] = server.get("working_dir") or ""
        payload["env_vars"] = dict(server.get("env_vars") or {})
        payload["min_workers"] = server.get("min_workers")
        payload["max_workers"] = server.get("max_workers")
    elif transport == "pipe":
        payload["pipe_path"] = server.get("pipe_path") or ""
    else:
        payload["raw"] = server

    management = server.get("management")
    if not isinstance(management, dict):
        raw_management = server.get("management_config")
        if isinstance(raw_management, str):
            try:
                management = json.loads(raw_management)
            except json.JSONDecodeError:
                management = {"invalid": True}
    payload["management"] = management if isinstance(management, dict) else {"mode": "none"}

    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def build_virtual_tool_fingerprint(tool: Dict[str, Any]) -> str:
    payload = {
        "name": tool.get("name") or "",
        "execution_type": tool.get("execution_type") or "",
        "config": tool.get("config") or {},
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _normalize_http_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
    normalized: Dict[str, Any] = {
        "scheme": str(policy.get("scheme") or HTTP_POLICY_DEFAULT_SCHEME).lower(),
        "host": str(policy.get("host") or "").lower(),
        "port": int(policy.get("port") or HTTP_POLICY_DEFAULT_PORT),
    }
    path_prefix = str(policy.get("path_prefix") or "").strip()
    if path_prefix:
        if not path_prefix.startswith("/"):
            path_prefix = f"/{path_prefix}"
        normalized["path_prefix"] = path_prefix
    return normalized


def derive_server_allowlist_policy(server: Dict[str, Any]) -> Dict[str, Any]:
    transport = (server.get("transport_type") or "http").lower()
    if transport == "http":
        parsed = urlparse(server.get("url") or "")
        scheme = (parsed.scheme or HTTP_POLICY_DEFAULT_SCHEME).lower()
        host = (parsed.hostname or "").lower()
        port = parsed.port
        if port is None:
            port = 443 if scheme == "https" else 80
        policy = {
            "kind": "http",
            "scheme": scheme,
            "host": host,
            "port": port,
        }
        if parsed.path and parsed.path != "/":
            policy["path_prefix"] = parsed.path
        return _normalize_http_policy(policy)
    if transport == "stdio":
        return {
            "kind": "stdio",
            "command": server.get("command") or "",
            "command_args": list(server.get("command_args") or []),
            "working_dir": server.get("working_dir") or "",
            "env_fingerprint": hashlib.sha256(
                json.dumps(
                    dict(server.get("env_vars") or {}),
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
        }
    if transport == "pipe":
        return {"kind": "pipe", "path_pattern": server.get("pipe_path") or ""}
    return {"kind": transport}


def server_matches_allowlist_policy(
    server: Dict[str, Any], policy: Optional[Dict[str, Any]]
) -> bool:
    if not isinstance(policy, dict):
        return False

    transport = (server.get("transport_type") or "http").lower()
    if transport == "http":
        parsed = urlparse(server.get("url") or "")
        if not parsed.hostname:
            return False
        normalized = _normalize_http_policy(policy)
        scheme = (parsed.scheme or HTTP_POLICY_DEFAULT_SCHEME).lower()
        host = (parsed.hostname or "").lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        if scheme != normalized.get("scheme"):
            return False
        if host != normalized.get("host"):
            return False
        if int(port) != int(normalized.get("port")):
            return False
        path_prefix = normalized.get("path_prefix")
        if path_prefix:
            current_path = parsed.path or "/"
            if not current_path.startswith(path_prefix):
                return False
        return True

    if transport == "stdio":
        expected = derive_server_allowlist_policy(server)
        return (
            policy.get("command") == expected.get("command")
            and list(policy.get("command_args") or []) == expected.get("command_args")
            and str(policy.get("working_dir") or "") == expected.get("working_dir")
            and str(policy.get("env_fingerprint") or "") == expected.get("env_fingerprint")
        )

    if transport == "pipe":
        expected_pattern = str(policy.get("path_pattern") or "")
        return expected_pattern == str(server.get("pipe_path") or "")

    return False


def build_approval_metadata(
    actor: str, action: str, reason: Optional[str] = None
) -> Dict[str, Any]:
    metadata = {
        "action": action,
        "actor": actor,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if reason:
        metadata["reason"] = reason
    return metadata


def ensure_whitelist_token(existing: Optional[str]) -> tuple[str, bool]:
    token = (existing or "").strip()
    if token:
        return token, False
    return secrets.token_urlsafe(24), True
