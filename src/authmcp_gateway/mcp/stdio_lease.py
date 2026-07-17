"""Exclusive leased access to one managed STDIO worker."""

from __future__ import annotations

from typing import Any, Dict

from .stdio_worker import MCPWorkerProtocol, ManagedStdioWorker


class WorkerLease:
    """Exclusive worker ownership. Always release it with ``async with``."""

    def __init__(self, pool: Any, worker: ManagedStdioWorker):
        self._pool, self._worker, self._released = pool, worker, False

    @property
    def worker(self) -> MCPWorkerProtocol:
        return self._worker

    async def __aenter__(self) -> WorkerLease:
        return self

    async def __aexit__(
        self, exc_type: object, exc: BaseException | None, traceback: object
    ) -> bool:
        await self.release(tainted=exc is not None)
        return False

    async def send_request(
        self, method: str, params: Dict[str, Any], *, timeout: float | None = None
    ) -> Dict[str, Any]:
        timeout = self._pool.config.request_timeout if timeout is None else timeout
        return await self._worker.send_request(method, params, timeout=timeout)

    async def send_payload(self, payload: Dict[str, Any], timeout: float) -> Dict[str, Any]:
        return await self._worker.send_payload(payload, timeout)

    async def release(self, *, tainted: bool = False) -> None:
        if not self._released:
            self._released = True
            await self._pool.release(self._worker, tainted=tainted)
