"""Background process manager for STDIO MCP servers."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict

from .transports.stdio_transport import StdioTransport

logger = logging.getLogger(__name__)


class StdioProcessManager:
    """Manage lifecycle of STDIO MCP subprocess transports."""

    def __init__(self):
        self._transports: Dict[int, StdioTransport] = {}

    async def start_server(self, server_id: int, server_config: Dict[str, Any]) -> None:
        """Start (or restart) STDIO server process for given server ID."""
        command = server_config.get("command")
        if not command:
            raise ValueError("STDIO server requires 'command'")

        transport = self._transports.get(server_id)
        if transport is None:
            transport = StdioTransport(
                command=command,
                command_args=server_config.get("command_args") or [],
                working_dir=server_config.get("working_dir"),
                env_vars=server_config.get("env_vars") or {},
            )
            self._transports[server_id] = transport
        await transport.start()

    async def stop_server(self, server_id: int) -> None:
        """Stop STDIO server process if running."""
        transport = self._transports.get(server_id)
        if transport is None:
            return
        await transport.close()

    async def restart_server(self, server_id: int) -> None:
        """Restart STDIO process for server ID."""
        transport = self._transports.get(server_id)
        if transport is None:
            raise ValueError(f"No STDIO transport for server {server_id}")
        await transport.close()
        await transport.start()

    def get_status(self, server_id: int) -> str:
        """Get process status for server ID."""
        transport = self._transports.get(server_id)
        if transport is None:
            return "stopped"
        return "running" if transport.is_running() else "stopped"

    def list_running(self) -> Dict[int, str]:
        """Return statuses for managed STDIO servers."""
        return {server_id: self.get_status(server_id) for server_id in self._transports}

    def get_transport(self, server_id: int) -> StdioTransport | None:
        """Return managed STDIO transport by server ID."""
        return self._transports.get(server_id)

    async def stop_all(self) -> None:
        """Stop all managed STDIO transports."""
        await asyncio.gather(*(transport.close() for transport in self._transports.values()))


_process_manager: StdioProcessManager | None = None


def initialize_process_manager() -> StdioProcessManager:
    """Initialize and return singleton process manager."""
    global _process_manager
    if _process_manager is None:
        _process_manager = StdioProcessManager()
    return _process_manager


def get_process_manager() -> StdioProcessManager:
    """Get singleton process manager."""
    if _process_manager is None:
        raise RuntimeError("Process manager not initialized")
    return _process_manager
