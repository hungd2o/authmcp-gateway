"""Raw STDIO JSON-RPC transport and its managed worker adapter."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from collections import deque
from contextlib import suppress
from typing import Any, Deque, Dict, List, Optional

from .base import McpTransport


def _windows_no_window_flags() -> int:
    """Return creation flags that keep child console windows hidden on Windows."""
    if sys.platform != "win32":
        return 0
    import subprocess

    return getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)


# Untrusted third-party stdio servers (npx/uvx/node packages) must not inherit
# the gateway's full environment — it holds JWT_SECRET_KEY, DB credentials,
# API keys (see config.py's load_dotenv()). Only pass what a child process
# actually needs to launch its own runtime/package manager; anything the
# server itself needs goes through its explicit env_vars config instead.
_BASE_ENV_KEYS = (
    frozenset({"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "USER", "SHELL"})
    if sys.platform != "win32"
    else frozenset(
        {
            "PATH",
            "SYSTEMROOT",
            "SYSTEMDRIVE",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "COMSPEC",
            "PATHEXT",
            "NUMBER_OF_PROCESSORS",
            "PROCESSOR_ARCHITECTURE",
            "WINDIR",
        }
    )
)


def _minimal_subprocess_env(extra: Dict[str, str]) -> Dict[str, str]:
    """Base env with only OS/runtime essentials, plus caller-supplied overrides."""
    base = {key: value for key, value in os.environ.items() if key.upper() in _BASE_ENV_KEYS}
    base.update(extra)
    return base


class StdioTransport(McpTransport):
    """Raw JSON-RPC-over-stdio transport. It never starts itself on send."""

    # MCP tool schemas and resource payloads routinely exceed one 64 KiB
    # JSON-RPC line. Keep a finite cap while allowing legitimate responses.
    # The reader limit must be high enough for large tool catalogs, but we do
    # not rely on asyncio.readline() so we are not coupled to its separator cap.
    STREAM_READER_LIMIT = 32 * 1024 * 1024
    STDOUT_RESPONSE_LIMIT = 32 * 1024 * 1024
    STDERR_TAIL_LINES = 128
    STDERR_LINE_BYTES = 1024

    def __init__(
        self,
        command: str,
        command_args: Optional[List[str]] = None,
        *,
        working_dir: Optional[str] = None,
        env_vars: Optional[Dict[str, str]] = None,
    ):
        self.command = command
        self.command_args = command_args or []
        self.working_dir = working_dir
        self.env_vars = env_vars or {}
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._io_lock = asyncio.Lock()
        self._lifecycle_lock = asyncio.Lock()
        self._stderr_task: Optional[asyncio.Task[None]] = None
        self._close_task: Optional[asyncio.Task[None]] = None
        self._closing = False
        self._stderr_tail: Deque[str] = deque(maxlen=self.STDERR_TAIL_LINES)
        self._stdout_buffer = bytearray()

    @property
    def pid(self) -> int | None:
        return self._proc.pid if self._proc is not None else None

    @property
    def stderr_tail(self) -> tuple[str, ...]:
        """Bounded diagnostics for internal use; callers must not expose it to users."""
        return tuple(self._stderr_tail)

    async def start(self) -> None:
        async with self._lifecycle_lock:
            if self._closing:
                raise RuntimeError("STDIO transport is shutting down")
            if self.is_running():
                return
            env = _minimal_subprocess_env(self.env_vars)
            spawn = asyncio.ensure_future(
                asyncio.create_subprocess_exec(
                    self.command,
                    *self.command_args,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=self.working_dir,
                    env=env,
                    limit=self.STREAM_READER_LIMIT,
                    creationflags=_windows_no_window_flags(),
                )
            )
            try:
                self._proc = await asyncio.shield(spawn)
            except asyncio.CancelledError:
                # A cancelled caller (e.g. pool startup_timeout) must not lose
                # the process handle mid-spawn: the OS process may already
                # exist even though this await never returned. Wait for the
                # shielded spawn to actually finish so close() always has a
                # real process to reap instead of orphaning it.
                self._proc = await spawn
                raise
            self._stdout_buffer.clear()
            self._stderr_task = asyncio.create_task(self._read_stderr())

    async def _read_stderr(self) -> None:
        proc = self._proc
        if proc is None or proc.stderr is None:
            return
        try:
            while chunk := await proc.stderr.read(4096):
                for line in chunk.splitlines() or [chunk]:
                    self._stderr_tail.append(
                        line[: self.STDERR_LINE_BYTES].decode("utf-8", errors="replace")
                    )
        except (asyncio.CancelledError, Exception):
            # Stderr is diagnostic-only. Never surface child output because it can contain secrets.
            return

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    async def send_request(self, payload: Dict[str, Any], timeout: float) -> Dict[str, Any]:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        async with self._io_lock:
            proc = self._proc
            if self._closing or proc is None or proc.returncode is not None:
                raise RuntimeError("STDIO transport process is not running")
            if proc.stdin is None or proc.stdout is None:
                raise RuntimeError("STDIO transport process is not available")
            proc.stdin.write((json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"))
            await proc.stdin.drain()
            raw = await self._read_stdout_line(proc, timeout=timeout)
            if not raw:
                raise RuntimeError("STDIO transport returned empty response")
            response = json.loads(raw.decode("utf-8"))
            if not isinstance(response, dict):
                raise ValueError("STDIO transport returned a non-object JSON-RPC response")
            return response

    async def _read_stdout_line(
        self, proc: asyncio.subprocess.Process, *, timeout: float
    ) -> bytes:
        """Read a single newline-delimited JSON-RPC message without readline() limits."""
        if proc.stdout is None:
            raise RuntimeError("STDIO transport process is not available")

        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            newline_index = self._stdout_buffer.find(b"\n")
            if newline_index != -1:
                line = bytes(self._stdout_buffer[: newline_index + 1])
                del self._stdout_buffer[: newline_index + 1]
                return line
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError()
            chunk = await asyncio.wait_for(proc.stdout.read(4096), timeout=remaining)
            if not chunk:
                line = bytes(self._stdout_buffer)
                self._stdout_buffer.clear()
                return line
            self._stdout_buffer.extend(chunk)
            if len(self._stdout_buffer) > self.STDOUT_RESPONSE_LIMIT:
                raise RuntimeError(
                    "STDIO transport response exceeded the configured size limit "
                    f"of {self.STDOUT_RESPONSE_LIMIT} bytes"
                )

    async def health_check(self) -> bool:
        try:
            await self.send_request(
                {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}}, timeout=5
            )
            return True
        except Exception:
            return False

    async def close(self, timeout: float = 5.0) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        async with self._lifecycle_lock:
            task = self._close_task
            if task is None:
                self._closing = True
                # A close must wait for active request I/O before it snapshots
                # the process. New requests observe ``_closing`` and fail.
                async with self._io_lock:
                    proc = self._proc
                    stderr_task, self._stderr_task = self._stderr_task, None
                if proc is None or proc.returncode is not None:
                    self._proc, self._closing = None, False
                    return
                task = asyncio.create_task(self._shutdown_process(proc, stderr_task, timeout))
                self._close_task = task
        await asyncio.shield(task)

    async def _shutdown_process(
        self,
        proc: asyncio.subprocess.Process,
        stderr_task: Optional[asyncio.Task[None]],
        timeout: float,
    ) -> None:
        """Reap one process even when the caller cancelling close goes away."""
        try:
            if stderr_task is not None:
                stderr_task.cancel()
                with suppress(asyncio.CancelledError):
                    await stderr_task
            if proc.stdin is not None:
                proc.stdin.close()
            try:
                await asyncio.wait_for(proc.wait(), timeout=min(timeout, 1.0))
                return
            except asyncio.TimeoutError:
                with suppress(ProcessLookupError):
                    proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=timeout)
                return
            except asyncio.TimeoutError:
                if sys.platform == "win32" and proc.pid is not None:
                    try:
                        killer = await asyncio.create_subprocess_exec(
                            "taskkill",
                            "/PID",
                            str(proc.pid),
                            "/T",
                            "/F",
                            stdout=asyncio.subprocess.DEVNULL,
                            stderr=asyncio.subprocess.DEVNULL,
                            creationflags=_windows_no_window_flags(),
                        )
                        await killer.wait()
                    except ProcessLookupError:
                        pass
                else:
                    with suppress(ProcessLookupError):
                        proc.kill()
                with suppress(ProcessLookupError):
                    await proc.wait()
        finally:
            async with self._lifecycle_lock:
                if self._proc is proc:
                    self._proc = None
                self._stdout_buffer.clear()
                self._close_task = None
                self._closing = False


# Compatibility exports: the stable worker API was historically colocated here.
# Imported last to avoid a transport/worker import cycle.
from ..stdio_worker import ManagedStdioWorker, MCPWorkerProtocol, WorkerState  # noqa: E402
