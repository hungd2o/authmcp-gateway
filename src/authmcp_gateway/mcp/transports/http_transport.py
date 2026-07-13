"""HTTP transport for MCP backend communication."""

from __future__ import annotations

from typing import Any, Dict, Optional

import httpx

from .base import McpTransport


class HttpTransport(McpTransport):
    """HTTP JSON-RPC transport implementation."""

    def __init__(
        self,
        server_url: str,
        headers: Dict[str, str],
        *,
        client: Optional[httpx.AsyncClient] = None,
        owns_client: bool = False,
    ):
        self.server_url = server_url
        self.headers = headers
        self._client = client
        self._owns_client = owns_client

    async def _get_client(self, timeout: float) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=timeout)
            self._owns_client = True
        return self._client

    async def send_request(self, payload: Dict[str, Any], timeout: float) -> Dict[str, Any]:
        client = await self._get_client(timeout)
        response = await client.post(
            self.server_url,
            json=payload,
            headers=self.headers,
            timeout=timeout,
        )
        response.raise_for_status()

        from authmcp_gateway.mcp.proxy import parse_sse_response

        return parse_sse_response(response)

    async def health_check(self) -> bool:
        try:
            data = await self.send_request(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {},
                },
                timeout=10,
            )
            return isinstance(data, dict) and ("result" in data or "error" in data)
        except Exception:
            return False

    async def close(self) -> None:
        if self._owns_client and self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
