"""Dedicated, serialized STDIO management sessions for native servers."""

from __future__ import annotations

import asyncio
import inspect
from uuid import uuid4
from typing import Any, Callable

from .control_plane_contract import CONTROL_PLANE_EXTENSION, CONTROL_PLANE_PROTOCOL_VERSION
from .stdio_worker import ManagedStdioWorker, WorkerState
from .transports.stdio_transport import StdioTransport


class ManagementUnavailableError(RuntimeError):
    """The native management session cannot safely be used."""


class NativeManagementClient:
    """One lazy management worker per server/generation; never model-plane state."""

    def __init__(self, timeout: float = 30.0, *, boot_id: str = "current"):
        self._timeout, self._boot_id = timeout, boot_id
        self._workers: dict[tuple[int, str], ManagedStdioWorker] = {}
        self._sessions: dict[tuple[int, str], dict[str, Any]] = {}
        self._server_locks: dict[int, asyncio.Lock] = {}
        self._closed = False

    async def request(
        self, server: dict[str, Any], lifecycle: str, method: str, params: dict[str, Any], *,
        eligible: Callable[[], Any] | None = None,
    ) -> dict[str, Any]:
        server_id, key = int(server["id"]), (int(server["id"]), lifecycle)
        async with self._lock(server_id):
            if self._closed:
                raise ManagementUnavailableError("Management client is closed")
            if eligible is not None:
                check = eligible()
                if inspect.isawaitable(check):
                    await check
            worker = await self._worker(server, key)
            worker.state = WorkerState.BUSY
            try:
                response = await worker.send_payload(
                    {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, self._timeout
                )
                if "error" in response:
                    raise ManagementUnavailableError("Native management operation failed")
                return response
            except BaseException:
                await self._evict(key, worker)
                raise
            finally:
                if worker.state is WorkerState.BUSY:
                    worker.state = WorkerState.READY

    def session_metadata(self, server_id: int, lifecycle: str) -> dict[str, Any] | None:
        metadata = self._sessions.get((server_id, lifecycle))
        return dict(metadata) if metadata else None

    async def invalidate(self, server_id: int) -> None:
        async with self._lock(server_id):
            for key in [key for key in self._workers if key[0] == server_id]:
                await self._evict(key, self._workers[key])

    async def close(self) -> None:
        self._closed = True
        for server_id in list(self._server_locks):
            await self.invalidate(server_id)

    def _lock(self, server_id: int) -> asyncio.Lock:
        return self._server_locks.setdefault(server_id, asyncio.Lock())

    async def _worker(self, server: dict[str, Any], key: tuple[int, str]) -> ManagedStdioWorker:
        if worker := self._workers.get(key):
            if worker.state is WorkerState.READY:
                return worker
            await self._evict(key, worker)
        if (server.get("transport_type") or "http").lower() != "stdio":
            raise ManagementUnavailableError("Management transport is unsupported")
        worker = ManagedStdioWorker(
            StdioTransport(
                str(server["command"]), list(server.get("command_args") or []),
                working_dir=server.get("working_dir"), env_vars=dict(server.get("env_vars") or {}),
            )
        )
        try:
            await worker.start()
            worker.state = WorkerState.BUSY
            response = await worker.send_payload(
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                    "protocolVersion": CONTROL_PLANE_PROTOCOL_VERSION,
                    "capabilities": {"extensions": {CONTROL_PLANE_EXTENSION: {}}},
                    "clientInfo": {"name": "authmcp-management", "version": "1"},
                }}, self._timeout
            )
            result = response.get("result")
            if not isinstance(result, dict) or result.get("protocolVersion") != CONTROL_PLANE_PROTOCOL_VERSION:
                raise ManagementUnavailableError("Native server negotiated an unsupported protocol")
            capabilities = result.get("capabilities")
            extensions = capabilities.get("extensions") if isinstance(capabilities, dict) else None
            if not isinstance(extensions, dict) or CONTROL_PLANE_EXTENSION not in extensions:
                raise ManagementUnavailableError("Native server did not negotiate the control-plane extension")
            await worker.send_notification("notifications/initialized", {})
            worker.state = WorkerState.READY
        except BaseException as exc:
            await worker.close()
            raise ManagementUnavailableError("Native management negotiation failed") from exc
        self._workers[key] = worker
        self._sessions[key] = {
            "boot_id": self._boot_id,
            "lifecycle": key[1],
            "session_epoch": uuid4().hex,
            "negotiated_protocol_version": CONTROL_PLANE_PROTOCOL_VERSION,
            "extensions": dict(extensions),
        }
        return worker

    async def _evict(self, key: tuple[int, str], worker: ManagedStdioWorker) -> None:
        self._workers.pop(key, None)
        self._sessions.pop(key, None)
        await worker.close()
