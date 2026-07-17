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

    # Keep a finite reader limit so large MCP responses do not trip asyncio's
    # default 32 MB line cap on named-pipe / socket transports.
    STREAM_READER_LIMIT = 32 * 1024 * 1024

    def __init__(self, pipe_path: str):
        self.pipe_path = pipe_path

    async def send_request(self, payload: Dict[str, Any], timeout: float) -> Dict[str, Any]:
        if os.name == "nt":
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.pipe_path, limit=self.STREAM_READER_LIMIT),
                timeout=timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(self.pipe_path, limit=self.STREAM_READER_LIMIT),
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
