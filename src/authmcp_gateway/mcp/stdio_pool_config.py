"""Validated, finite configuration for a managed STDIO server pool."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict, Mapping


class PoolState(str, Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    DRAINING = "draining"
    STOPPING = "stopping"
    FAILED = "failed"
    BLOCKED = "blocked"


class WorkerPoolOverloadedError(RuntimeError):
    """Controlled capacity failure suitable for a 503 + Retry-After mapping."""

    def __init__(self, server_id: int, retry_after: int = 1):
        super().__init__(f"STDIO server {server_id} is at capacity")
        self.server_id, self.retry_after = server_id, retry_after


@dataclass(frozen=True)
class PoolConfig:
    min_workers: int = 0
    max_workers: int = 1
    max_queue: int = 8
    acquire_timeout: float = 5.0
    request_timeout: float = 30.0
    startup_timeout: float = 10.0
    shutdown_timeout: float = 5.0
    idle_timeout: float = 60.0
    health_queue: int = 1


def _settings_default(section: str, key: str, fallback: Any) -> Any:
    """Read dynamic defaults from settings manager when available."""
    try:
        from authmcp_gateway.settings_manager import get_settings_manager

        return get_settings_manager().get(section, key, default=fallback)
    except Exception:
        return fallback


def _integer(value: Any, name: str, default: int, low: int, high: int) -> int:
    result = default if value is None else int(value)
    if not low <= result <= high:
        raise ValueError(f"{name} must be between {low} and {high}")
    return result


def _timeout(value: Any, name: str, default: float) -> float:
    result = default if value is None else float(value)
    if not 0 < result <= 3600:
        raise ValueError(f"{name} must be between 0 and 3600 seconds")
    return result


def pool_config_from_server(server: Mapping[str, Any]) -> PoolConfig:
    max_workers_default = int(_settings_default("mcp_worker", "max_workers", 3))
    max_workers = _integer(server.get("max_workers"), "max_workers", max_workers_default, 1, 32)
    min_workers_default = int(_settings_default("mcp_worker", "min_workers", 1))
    min_workers_default = max(0, min(min_workers_default, max_workers))

    return PoolConfig(
        min_workers=_integer(
            server.get("min_workers"), "min_workers", min_workers_default, 0, max_workers
        ),
        max_workers=max_workers,
        max_queue=_integer(
            server.get("max_queue"),
            "max_queue",
            int(_settings_default("mcp_worker", "max_queue", 8)),
            0,
            1024,
        ),
        acquire_timeout=_timeout(
            server.get("acquire_timeout"),
            "acquire_timeout",
            float(_settings_default("mcp_worker", "acquire_timeout", 5.0)),
        ),
        request_timeout=_timeout(
            server.get("request_timeout"),
            "request_timeout",
            float(_settings_default("mcp_worker", "request_timeout", 30.0)),
        ),
        startup_timeout=_timeout(
            server.get("startup_timeout"),
            "startup_timeout",
            float(_settings_default("mcp_worker", "startup_timeout", 10.0)),
        ),
        shutdown_timeout=_timeout(
            server.get("shutdown_timeout"),
            "shutdown_timeout",
            float(_settings_default("mcp_worker", "shutdown_timeout", 5.0)),
        ),
        idle_timeout=_timeout(
            server.get("idle_timeout"),
            "idle_timeout",
            float(_settings_default("mcp_worker", "idle_timeout", 60.0)),
        ),
        health_queue=_integer(
            server.get("health_queue"),
            "health_queue",
            int(_settings_default("mcp_worker", "health_queue", 1)),
            0,
            32,
        ),
    )


def normalise_server_config(server: Mapping[str, Any]) -> Dict[str, Any]:
    command, args, env, cwd = (
        server.get("command"),
        server.get("command_args") or [],
        server.get("env_vars") or {},
        server.get("working_dir"),
    )
    if not isinstance(command, str) or not command.strip():
        raise ValueError("STDIO server requires a non-empty 'command'")
    if not isinstance(args, list) or not all(isinstance(value, str) for value in args):
        raise ValueError("command_args must be a list of strings")
    if cwd is not None and not isinstance(cwd, str):
        raise ValueError("working_dir must be a string or null")
    if not isinstance(env, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in env.items()
    ):
        raise ValueError("env_vars must be a string-to-string object")
    pool_values = server.get("pool") if isinstance(server.get("pool"), dict) else server
    pool = (
        PoolConfig(**pool_values) if pool_values is not server else pool_config_from_server(server)
    )
    return {
        "command": command,
        "command_args": list(args),
        "working_dir": cwd,
        "env_vars": dict(env),
        "pool": asdict(pool),
    }


def config_fingerprint(server: Mapping[str, Any]) -> str:
    canonical = json.dumps(normalise_server_config(server), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
