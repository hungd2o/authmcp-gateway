"""STDIO transport for MCP backends."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Dict, List, Optional

from .base import McpTransport

logger = logging.getLogger(__name__)


class StdioTransport(McpTransport):
    """STDIO transport that manages a backend subprocess."""

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
        self._stderr_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Start subprocess if not running."""
        if self._proc and self._proc.returncode is None:
            return

        env = os.environ.copy()
        env.update(self.env_vars)

        self._proc = await asyncio.create_subprocess_exec(
            self.command,
            *self.command_args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=self.working_dir,
            env=env,
        )
        self._stderr_task = asyncio.create_task(self._read_stderr())

    async def _read_stderr(self) -> None:
        if not self._proc or not self._proc.stderr:
            return
        try:
            while True:
                line = await self._proc.stderr.readline()
                if not line:
                    break
                logger.debug("STDIO MCP stderr: %s", line.decode("utf-8", errors="replace").rstrip())
        except Exception as e:
            logger.debug("STDIO stderr reader stopped: %s", e)

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    async def send_request(self, payload: Dict[str, Any], timeout: float) -> Dict[str, Any]:
        # auto-start / auto-restart behavior
        if not self.is_running():
            await self.start()

        if not self._proc or not self._proc.stdin or not self._proc.stdout:
            raise RuntimeError("STDIO transport process is not available")

        async with self._io_lock:
            data = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
            self._proc.stdin.write(data)
            await self._proc.stdin.drain()

            raw = await asyncio.wait_for(self._proc.stdout.readline(), timeout=timeout)
            if not raw:
                raise RuntimeError("STDIO transport returned empty response")
            return json.loads(raw.decode("utf-8"))

    async def health_check(self) -> bool:
        try:
            if not self.is_running():
                return False
            await self.send_request(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "ping",
                    "params": {},
                },
                timeout=5,
            )
            return True
        except Exception:
            return False

    async def close(self) -> None:
        if self._stderr_task:
            self._stderr_task.cancel()
            try:
                await self._stderr_task
            except asyncio.CancelledError:
                pass
            self._stderr_task = None

        if not self._proc:
            return

        if self._proc.returncode is None:
            self._proc.terminate()
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._proc.kill()
                await self._proc.wait()
        self._proc = None
