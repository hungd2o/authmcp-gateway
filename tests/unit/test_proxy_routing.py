import pytest

from authmcp_gateway.mcp.proxy import McpProxy


@pytest.mark.asyncio
async def test_proxy_jsonrpc_uses_transport_for_stdio(db_path):
    proxy = McpProxy(db_path)

    class FakeTransport:
        async def send_request(self, payload, timeout):
            assert payload["method"] == "ping"
            assert timeout == 12
            return {"jsonrpc": "2.0", "id": payload["id"], "result": {"ok": True}}

        async def health_check(self):
            return True

        async def close(self):
            return None

    async def fake_get_transport(server, headers):
        assert server["transport_type"] == "stdio"
        return FakeTransport()

    proxy._get_transport = fake_get_transport  # type: ignore[method-assign]

    result = await proxy._proxy_jsonrpc(
        {
            "id": 1,
            "name": "stdio-server",
            "transport_type": "stdio",
            "timeout": 12,
            "approval_state": "approved",
        },
        "ping",
        {},
    )

    assert result["result"]["ok"] is True
