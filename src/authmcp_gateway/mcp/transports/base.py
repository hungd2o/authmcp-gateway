"""Transport abstraction for MCP backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict


class McpTransport(ABC):
    """Base transport interface for MCP JSON-RPC communication."""

    @abstractmethod
    async def send_request(self, payload: Dict[str, Any], timeout: float) -> Dict[str, Any]:
        """Send JSON-RPC payload and return parsed JSON response."""

    @abstractmethod
    async def health_check(self) -> bool:
        """Perform lightweight liveness check for transport."""

    @abstractmethod
    async def close(self) -> None:
        """Release transport resources."""
