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
    max_workers = _integer(server.get("max_workers"), "max_workers", 1, 1, 32)
    return PoolConfig(
        min_workers=_integer(server.get("min_workers"), "min_workers", 0, 0, max_workers),
        max_workers=max_workers,
        max_queue=_integer(server.get("max_queue"), "max_queue", 8, 0, 1024),
        acquire_timeout=_timeout(server.get("acquire_timeout"), "acquire_timeout", 5),
        request_timeout=_timeout(server.get("request_timeout"), "request_timeout", 30),
        startup_timeout=_timeout(server.get("startup_timeout"), "startup_timeout", 10),
        shutdown_timeout=_timeout(server.get("shutdown_timeout"), "shutdown_timeout", 5),
        idle_timeout=_timeout(server.get("idle_timeout"), "idle_timeout", 60),
        health_queue=_integer(server.get("health_queue"), "health_queue", 1, 0, 32),
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
