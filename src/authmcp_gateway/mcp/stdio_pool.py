"""Per-server bounded worker pool and lease lifecycle."""

from __future__ import annotations

import asyncio
import hashlib
import json
from contextlib import suppress
from datetime import datetime, timezone
from typing import Any, Dict

from .stdio_lease import WorkerLease
from .stdio_pool_config import PoolConfig, PoolState, WorkerPoolOverloadedError
from .stdio_worker import ManagedStdioWorker, WorkerState
from .transports.stdio_transport import StdioTransport


class ServerPool:
    """Finite worker capacity and queue for a single server generation."""

    def __init__(self, server_id: int, config: Dict[str, Any], generation: int = 1):
        self.server_id, self.server_config, self.generation = server_id, config, generation
        self.config, self.state = PoolConfig(**config["pool"]), PoolState.STOPPED
        self.fingerprint = hashlib.sha256(
            json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.workers: list[ManagedStdioWorker] = []
        self._available = asyncio.Condition(asyncio.Lock())
        self._waiting = self._health_waiting = 0

    def _new_worker(self) -> ManagedStdioWorker:
        return ManagedStdioWorker(
            StdioTransport(
                self.server_config["command"],
                self.server_config["command_args"],
                working_dir=self.server_config["working_dir"],
                env_vars=self.server_config["env_vars"],
            )
        )

    def _ready_worker(self) -> ManagedStdioWorker | None:
        return next((worker for worker in self.workers if worker.state is WorkerState.READY), None)

    async def _start_worker(self, worker: ManagedStdioWorker) -> None:
        self.state = PoolState.STARTING
        try:
            await asyncio.wait_for(worker.start(), timeout=self.config.startup_timeout)
        except BaseException:
            with suppress(Exception):
                await worker.close(self.config.shutdown_timeout)
            async with self._available:
                with suppress(ValueError):
                    self.workers.remove(worker)
                self.state = PoolState.FAILED if not self.workers else PoolState.RUNNING
                self._available.notify_all()
            raise
        async with self._available:
            worker.state = (
                WorkerState.STOPPING
                if self.state in {PoolState.STOPPING, PoolState.BLOCKED}
                else WorkerState.READY
            )
            if worker.state is WorkerState.READY:
                self.state = PoolState.RUNNING
            self._available.notify_all()

    async def acquire(self, purpose: str = "request", timeout: float | None = None) -> WorkerLease:
        if purpose not in {"request", "health", "diagnostic"}:
            raise ValueError("invalid worker purpose")
        timeout = self.config.acquire_timeout if timeout is None else timeout
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        deadline, waited, loop = (
            asyncio.get_running_loop().time() + timeout,
            False,
            asyncio.get_running_loop(),
        )
        try:
            while True:
                worker, start_worker = None, False
                async with self._available:
                    if self.state is PoolState.BLOCKED:
                        raise PermissionError(f"STDIO server {self.server_id} is blocked")
                    if self.state in {PoolState.DRAINING, PoolState.STOPPING}:
                        raise RuntimeError(f"STDIO server {self.server_id} is draining")
                    if worker := self._ready_worker():
                        worker.state = WorkerState.BUSY
                        return WorkerLease(self, worker)
                    if len(self.workers) < self.config.max_workers:
                        worker, start_worker = self._new_worker(), True
                        self.workers.append(worker)
                    else:
                        if not waited:
                            if self._waiting >= self.config.max_queue or (
                                purpose == "health"
                                and self._health_waiting >= self.config.health_queue
                            ):
                                raise WorkerPoolOverloadedError(self.server_id)
                            self._waiting += 1
                            self._health_waiting += purpose == "health"
                            waited = True
                        try:
                            await asyncio.wait_for(
                                self._available.wait(), timeout=deadline - loop.time()
                            )
                        except asyncio.TimeoutError as error:
                            raise WorkerPoolOverloadedError(self.server_id) from error
                if start_worker and worker is not None:
                    await self._start_worker(worker)
        finally:
            if waited:
                async with self._available:
                    self._waiting -= 1
                    self._health_waiting -= purpose == "health"

    async def release(self, worker: ManagedStdioWorker, *, tainted: bool) -> None:
        close = (
            tainted or worker.state is WorkerState.UNHEALTHY or not worker.transport.is_running()
        )
        async with self._available:
            if worker not in self.workers:
                return
            if close or self.state in {PoolState.BLOCKED, PoolState.STOPPING, PoolState.DRAINING}:
                worker.state = WorkerState.STOPPING
                self.workers.remove(worker)
            else:
                worker.state = WorkerState.READY
                worker.last_used_at = datetime.now(timezone.utc)
            self._available.notify_all()
        if close or worker.state is WorkerState.STOPPING:
            await worker.close(self.config.shutdown_timeout)

    async def block(self) -> None:
        async with self._available:
            self.state = PoolState.BLOCKED
            self._available.notify_all()

    async def wait_for_busy_workers(self) -> None:
        deadline = asyncio.get_running_loop().time() + self.config.shutdown_timeout
        async with self._available:
            while any(worker.state is WorkerState.BUSY for worker in self.workers):
                with suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(
                        self._available.wait(),
                        timeout=max(0, deadline - asyncio.get_running_loop().time()),
                    )
                if asyncio.get_running_loop().time() >= deadline:
                    return

    async def ensure_min_workers(self) -> None:
        while len(self.workers) < self.config.min_workers:
            worker = self._new_worker()
            self.workers.append(worker)
            await self._start_worker(worker)

    async def reap_idle(self) -> int:
        cutoff = datetime.now(timezone.utc).timestamp() - self.config.idle_timeout
        async with self._available:
            stale = [
                worker
                for worker in self.workers
                if worker.state is WorkerState.READY and worker.last_used_at.timestamp() < cutoff
            ]
            stale = stale[: max(0, len(self.workers) - self.config.min_workers)]
            for worker in stale:
                self.workers.remove(worker)
                worker.state = WorkerState.STOPPING
            self._available.notify_all()
        await asyncio.gather(*(worker.close(self.config.shutdown_timeout) for worker in stale))
        return len(stale)

    async def stop(self) -> None:
        async with self._available:
            blocked = self.state is PoolState.BLOCKED
            self.state = PoolState.BLOCKED if blocked else PoolState.STOPPING
            workers = list(self.workers)
            for worker in workers:
                if worker.state is WorkerState.READY:
                    worker.state = WorkerState.STOPPING
                    self.workers.remove(worker)
            self._available.notify_all()
        await self.wait_for_busy_workers()
        async with self._available:
            for worker in list(self.workers):
                self.workers.remove(worker)
                worker.state = WorkerState.STOPPING
            self._available.notify_all()
        await asyncio.gather(*(worker.close(self.config.shutdown_timeout) for worker in workers))
        if not blocked:
            self.state = PoolState.STOPPED

    def status_detail(self) -> Dict[str, Any]:
        return {
            "server_id": self.server_id,
            "state": self.state.value,
            "generation": self.generation,
            "fingerprint": self.fingerprint,
            "workers": {
                state.value: sum(worker.state is state for worker in self.workers)
                for state in WorkerState
            },
            "waiting": self._waiting,
            "max_workers": self.config.max_workers,
            "max_queue": self.config.max_queue,
        }
