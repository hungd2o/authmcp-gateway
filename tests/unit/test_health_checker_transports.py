import pytest

from authmcp_gateway.mcp.health import HealthChecker


@pytest.mark.asyncio
async def test_health_checker_stdio_transport_online(db_path, monkeypatch):
    checker = HealthChecker(db_path)

    class FakeTransport:
        async def send_request(self, payload, timeout):
            assert payload["method"] == "tools/list"
            return {"result": {"tools": [{"name": "a"}]}}

    class FakeManager:
        async def start_server(self, server_id, server):
            return None

        def get_transport(self, server_id):
            return FakeTransport()

    monkeypatch.setattr("authmcp_gateway.mcp.health.get_process_manager", lambda: FakeManager())

    result = await checker.check_server(
        {
            "id": 1,
            "name": "stdio",
            "url": "",
            "transport_type": "stdio",
            "command": "python",
            "enabled": 1,
        }
    )

    assert result["status"] == "online"
    assert result["tools_count"] == 1
