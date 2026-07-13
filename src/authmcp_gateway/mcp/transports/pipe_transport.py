"""Named pipe / Unix socket transport for MCP backends."""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Dict

from .base import McpTransport


class PipeTransport(McpTransport):
    """Named pipe transport implementation.

    On Unix, uses Unix domain sockets via ``asyncio.open_unix_connection``.
    On Windows, falls back to opening ``\\\\.\\pipe\\name`` as a stream path.
    """

    def __init__(self, pipe_path: str):
        self.pipe_path = pipe_path

    async def send_request(self, payload: Dict[str, Any], timeout: float) -> Dict[str, Any]:
        if os.name == "nt":
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.pipe_path),
                timeout=timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(self.pipe_path),
                timeout=timeout,
            )

        try:
            writer.write((json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"))
            await writer.drain()
            raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if not raw:
                raise RuntimeError("Pipe transport returned empty response")
            return json.loads(raw.decode("utf-8"))
        finally:
            writer.close()
            await writer.wait_closed()

    async def health_check(self) -> bool:
        try:
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
        return None
