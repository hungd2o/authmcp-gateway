"""Compatibility facade for bounded STDIO worker pools."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict

from .stdio_lease import WorkerLease
from .stdio_pool import ServerPool
from .stdio_pool_config import PoolState, config_fingerprint, normalise_server_config
from .stdio_worker import MCPWorkerProtocol
from .transports.stdio_transport import StdioTransport


class StdioProcessManager:
    """Application-owned STDIO pools. Sending never implicitly starts a process."""

    def __init__(self):
        self._pools: Dict[int, ServerPool] = {}
        self._blocked_server_ids: set[int] = set()
        self._security_blocked_server_ids: set[int] = set()
        self._closing = False
        self._server_locks: Dict[int, asyncio.Lock] = {}
        self._transports: Dict[int, Any] = {}  # Legacy caller/test compatibility only.
        self._legacy_inflight: Dict[int, int] = {}
        self._legacy_idle: Dict[int, asyncio.Event] = {}
        self._restart_counts: Dict[int, int] = {}
        self._runtime_markers: Dict[int, tuple[int, int] | None] = {}

    def _lock(self, server_id: int) -> asyncio.Lock:
        return self._server_locks.setdefault(server_id, asyncio.Lock())

    def _idle_event(self, server_id: int) -> asyncio.Event:
        event = self._legacy_idle.setdefault(server_id, asyncio.Event())
        if self._legacy_inflight.get(server_id, 0) == 0:
            event.set()
        return event

    def _record_running_instance(self, server_id: int, pool: ServerPool | None) -> None:
        if pool is None:
            return
        marker = next(
            (
                (pool.generation, worker.pid)
                for worker in pool.workers
                if worker.pid is not None and worker.transport.is_running()
            ),
            None,
        )
        if marker is None or self._runtime_markers.get(server_id) == marker:
            return
        if server_id in self._runtime_markers:
            self._restart_counts[server_id] = self._restart_counts.get(server_id, 0) + 1
        self._runtime_markers[server_id] = marker

    def is_blocked(self, server_id: int) -> bool:
        return server_id in self._blocked_server_ids

    def requires_reapproval(self, server_id: int) -> bool:
        """Whether a configuration change was stopped fail-closed."""
        return server_id in self._security_blocked_server_ids

    def _reject_if_closing(self) -> None:
        if self._closing:
            raise RuntimeError("STDIO process manager is shutting down")

    async def block_server(self, server_id: int) -> None:
        async with self._lock(server_id):
            pool = await self._block_server_locked(server_id)
        if pool is not None:
            await pool.wait_for_busy_workers()
        await self._idle_event(server_id).wait()

    async def _block_server_locked(self, server_id: int) -> ServerPool | None:
        self._blocked_server_ids.add(server_id)
        pool = self._pools.get(server_id)
        if pool is not None:
            await pool.block()
        return pool

    async def unblock_server(self, server_id: int) -> None:
        async with self._lock(server_id):
            self._blocked_server_ids.discard(server_id)
            self._security_blocked_server_ids.discard(server_id)
            if (pool := self._pools.get(server_id)) and pool.state is PoolState.BLOCKED:
                pool.state = PoolState.STOPPED

    async def start_server(self, server_id: int, server_config: Dict[str, Any]) -> None:
        """Configure and eagerly start one worker for legacy callers."""
        config = normalise_server_config(server_config)
        async with self._lock(server_id):
            self._reject_if_closing()
            if self.is_blocked(server_id):
                raise PermissionError(f"STDIO server {server_id} is blocked")
            pool = self._pools.get(server_id)
            if pool is None or pool.fingerprint != config_fingerprint(config):
                generation = 1 if pool is None else pool.generation + 1
                if pool is not None:
                    await pool.stop()
                pool = self._pools[server_id] = ServerPool(server_id, config, generation)
            await pool.ensure_min_workers()
            if not pool.workers:
                worker = pool._new_worker()
                pool.workers.append(worker)
                await pool._start_worker(worker)
            if self.is_blocked(server_id):
                await pool.block()
                raise PermissionError(f"STDIO server {server_id} is blocked")
            self._record_running_instance(server_id, pool)
            self._transports[server_id] = next(
                worker.transport for worker in pool.workers if worker.transport.is_running()
            )

    async def acquire(
        self, server_id: int, *, purpose: str = "request", timeout: float | None = None
    ) -> WorkerLease:
        async with self._lock(server_id):
            self._reject_if_closing()
            if self.is_blocked(server_id):
                raise PermissionError(f"STDIO server {server_id} is blocked")
            pool = self._pools.get(server_id)
            if pool is None:
                raise RuntimeError(f"STDIO server {server_id} is not configured")
        await pool.reap_idle()
        lease = await pool.acquire(purpose, timeout)
        self._record_running_instance(server_id, pool)
        return lease

    async def release(self, lease: WorkerLease, *, tainted: bool = False) -> None:
        await lease.release(tainted=tainted)

    async def probe_tools(self, server_id: int, *, timeout: float) -> int:
        """Verify a managed STDIO backend and return its current tool count."""
        async with await self.acquire(server_id, purpose="diagnostic", timeout=timeout) as lease:
            response = await lease.send_request("tools/list", {}, timeout=timeout)
        result = response.get("result")
        tools = result.get("tools") if isinstance(result, dict) else None
        if not isinstance(tools, list):
            raise RuntimeError("STDIO server returned an invalid tools/list response")
        return len(tools)

    async def send_request(
        self, server_id: int, payload: Dict[str, Any], timeout: float
    ) -> Dict[str, Any]:
        """Raw-payload compatibility path; new code uses a leased method/params worker."""
        async with self._lock(server_id):
            self._reject_if_closing()
            if self.is_blocked(server_id):
                raise PermissionError(f"STDIO server {server_id} is blocked")
            managed_pool = server_id in self._pools
            transport = self._transports.get(server_id)
            event = self._idle_event(server_id)
            if not managed_pool:
                if transport is None or not transport.is_running():
                    raise RuntimeError(f"STDIO server {server_id} is not running")
                event.clear()
                self._legacy_inflight[server_id] = self._legacy_inflight.get(server_id, 0) + 1
        if managed_pool:
            async with await self.acquire(server_id, timeout=timeout) as lease:
                return await lease.send_payload(payload, timeout)
        try:
            assert transport is not None
            return await transport.send_request(payload, timeout)
        finally:
            async with self._lock(server_id):
                self._legacy_inflight[server_id] -= 1
                if self._legacy_inflight[server_id] == 0:
                    event.set()

    async def stop_server(self, server_id: int) -> None:
        async with self._lock(server_id):
            await self._stop_server_locked(server_id)

    async def _stop_server_locked(self, server_id: int) -> None:
        if pool := self._pools.get(server_id):
            await pool.stop()
        elif transport := self._transports.get(server_id):
            await transport.close()

    async def block_and_stop_server(self, server_id: int) -> None:
        async with self._lock(server_id):
            pool = await self._block_server_locked(server_id)
        if pool is not None:
            await pool.wait_for_busy_workers()
        await self._idle_event(server_id).wait()
        async with self._lock(server_id):
            await self._stop_server_locked(server_id)

    async def stop_and_remove(self, server_id: int, *, blocked: bool = False) -> None:
        async with self._lock(server_id):
            if blocked:
                self._blocked_server_ids.add(server_id)
            await self._stop_server_locked(server_id)
            self._pools.pop(server_id, None)
            self._transports.pop(server_id, None)
            self._runtime_markers.pop(server_id, None)
            self._restart_counts.pop(server_id, None)

    async def restart_server(self, server_id: int) -> None:
        async with self._lock(server_id):
            self._reject_if_closing()
            if self.is_blocked(server_id):
                raise PermissionError(f"STDIO server {server_id} is blocked")
            pool = self._pools.get(server_id)
            if pool is None:
                raise ValueError(f"No STDIO transport for server {server_id}")
            await pool.stop()
            self._pools.pop(server_id, None)
        await self.start_server(server_id, pool.server_config)

    async def reconcile(
        self, server_id: int, server_config: Dict[str, Any], *, force_generation_swap: bool = False
    ) -> bool:
        """Apply one configuration transition without dropping a healthy pool.

        Executable, arguments, working directory, and environment are security
        boundaries. Their changes fail closed. Capacity and timeout changes are
        staged: the old generation remains available until the replacement has
        successfully started a worker.
        """
        config = normalise_server_config(server_config)
        async with self._lock(server_id):
            self._reject_if_closing()
            pool = self._pools.get(server_id)
            if (
                pool is not None
                and pool.fingerprint == config_fingerprint(config)
                and not force_generation_swap
            ):
                return False
            if self.is_blocked(server_id):
                return False
            if pool is None:
                self._pools[server_id] = ServerPool(server_id, config)
                return True
            if self._is_security_sensitive_change(pool.server_config, config):
                self._security_blocked_server_ids.add(server_id)
                await self._block_server_locked(server_id)
                await self._stop_server_locked(server_id)
                self._pools.pop(server_id, None)
                self._transports.pop(server_id, None)
                return True

            replacement = ServerPool(server_id, config, pool.generation + 1)
            worker = replacement._new_worker()
            replacement.workers.append(worker)
            await replacement._start_worker(worker)
            self._pools[server_id] = replacement
            self._record_running_instance(server_id, replacement)
            self._transports[server_id] = worker.transport
            await pool.stop()
            return True

    @staticmethod
    def _is_security_sensitive_change(current: Dict[str, Any], replacement: Dict[str, Any]) -> bool:
        return any(
            current.get(field) != replacement.get(field)
            for field in ("command", "command_args", "working_dir", "env_vars")
        )

    def get_status(self, server_id: int) -> str:
        pool = self._pools.get(server_id)
        running = (
            any(worker.transport.is_running() for worker in pool.workers)
            if pool
            else bool(getattr(self._transports.get(server_id), "is_running", lambda: False)())
        )
        return "running" if running else "stopped"

    def status_detail(self, server_id: int) -> Dict[str, Any]:
        if pool := self._pools.get(server_id):
            detail = pool.status_detail()
            if self.is_blocked(server_id):
                detail["state"] = PoolState.BLOCKED.value
            return detail
        return {
            "server_id": server_id,
            "state": "blocked" if self.is_blocked(server_id) else "stopped",
            "generation": 0,
            "workers": {},
        }

    def get_status_detail(self, server_id: int) -> Dict[str, Any]:
        """Return a safe, live operations snapshot without launch settings."""
        if not (pool := self._pools.get(server_id)):
            return {
                "desired_state": "blocked" if self.is_blocked(server_id) else "stopped",
                "pool_state": "blocked" if self.is_blocked(server_id) else "stopped",
                "aggregate": "blocked" if self.is_blocked(server_id) else "stopped",
                "generation": 0,
                "pool_size": 0,
                "active": 0,
                "idle": 0,
                "queue_depth": 0,
                "max_workers": 0,
                "min_workers": 0,
                "max_queue": 0,
                "restart_count": self._restart_counts.get(server_id, 0),
                "workers": [],
            }

        now = datetime.now(timezone.utc)
        workers = []
        live_workers = []
        for index, worker in enumerate(pool.workers, start=1):
            is_live = worker.transport.is_running()
            if is_live:
                live_workers.append(worker)
            uptime_secs = (
                max(0, int((now - worker.started_at).total_seconds()))
                if worker.started_at is not None
                else None
            )
            workers.append(
                {
                    "worker_id": f"worker-{index}",
                    "state": worker.state.value if is_live else "dead",
                    "pid": worker.pid,
                    "uptime_secs": uptime_secs,
                    "last_exit_code": worker.returncode,
                }
            )
        if self.is_blocked(server_id):
            state = "blocked"
        elif pool.state is PoolState.RUNNING and not live_workers:
            state = (
                "failed"
                if any(worker.returncode not in {None, 0} for worker in pool.workers)
                else "stopped"
            )
        else:
            state = pool.state.value
        return {
            "desired_state": state,
            "pool_state": state,
            "aggregate": state,
            "generation": pool.generation,
            "pool_size": len(pool.workers),
            "active": sum(worker.state.value == "busy" for worker in live_workers),
            "idle": sum(worker.state.value == "ready" for worker in live_workers),
            "queue_depth": pool._waiting,
            "max_workers": pool.config.max_workers,
            "min_workers": pool.config.min_workers,
            "max_queue": pool.config.max_queue,
            "restart_count": self._restart_counts.get(server_id, 0),
            "config_fingerprint_short": pool.fingerprint[:12],
            "workers": workers,
        }

    def list_running(self) -> Dict[int, str]:
        return {
            server_id: self.get_status(server_id)
            for server_id in set(self._pools) | set(self._transports)
        }

    def get_transport(self, server_id: int) -> StdioTransport | None:
        transport = self._transports.get(server_id)
        return transport if isinstance(transport, StdioTransport) else None

    async def reap_idle(self) -> int:
        return sum(await pool.reap_idle() for pool in list(self._pools.values()))

    async def stop_all(self) -> None:
        self._closing = True
        results = await asyncio.gather(
            *(self.stop_server(server_id) for server_id in self.list_running()),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, BaseException):
                logging.getLogger(__name__).error("Error stopping STDIO server: %s", result)


_process_manager: StdioProcessManager | None = None


def initialize_process_manager() -> StdioProcessManager:
    global _process_manager
    if _process_manager is None:
        _process_manager = StdioProcessManager()
    return _process_manager


def get_process_manager() -> StdioProcessManager:
    if _process_manager is None:
        raise RuntimeError("Process manager not initialized")
    return _process_manager
