"""Stable worker protocol and single-flight STDIO worker implementation."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, Protocol, runtime_checkable

if TYPE_CHECKING:
    from .transports.stdio_transport import StdioTransport


class WorkerState(str, Enum):
    STARTING = "starting"
    READY = "ready"
    BUSY = "busy"
    UNHEALTHY = "unhealthy"
    STOPPING = "stopping"
    DEAD = "dead"


@runtime_checkable
class MCPWorkerProtocol(Protocol):
    async def send_request(
        self, method: str, params: Dict[str, Any], *, timeout: float
    ) -> Dict[str, Any]: ...


class ManagedStdioWorker(MCPWorkerProtocol):
    """A leased worker that owns one raw STDIO transport and request stream."""

    def __init__(self, transport: StdioTransport):
        self.transport, self.state, self._request_id = transport, WorkerState.STARTING, 0
        self.started_at: datetime | None = None
        self.last_used_at = datetime.now(timezone.utc)

    @property
    def pid(self) -> int | None:
        return self.transport.pid

    async def start(self) -> None:
        self.state = WorkerState.STARTING
        try:
            await self.transport.start()
        except BaseException:
            self.state = WorkerState.UNHEALTHY
            raise
        self.started_at = self.last_used_at = datetime.now(timezone.utc)
        self.state = WorkerState.READY

    async def send_request(
        self, method: str, params: Dict[str, Any], *, timeout: float
    ) -> Dict[str, Any]:
        self._request_id += 1
        return await self.send_payload(
            {"jsonrpc": "2.0", "id": self._request_id, "method": method, "params": params}, timeout
        )

    async def send_payload(self, payload: Dict[str, Any], timeout: float) -> Dict[str, Any]:
        if self.state is not WorkerState.BUSY:
            raise RuntimeError("STDIO worker is not leased")
        try:
            response = await self.transport.send_request(payload, timeout)
            self.last_used_at = datetime.now(timezone.utc)
            return response
        except BaseException:
            self.state = WorkerState.UNHEALTHY
            raise

    async def close(self, timeout: float = 5.0) -> None:
        self.state = WorkerState.STOPPING
        try:
            await self.transport.close(timeout)
        finally:
            self.state = WorkerState.DEAD
