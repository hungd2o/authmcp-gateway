import asyncio

import pytest

from authmcp_gateway.mcp.health import HealthChecker
from authmcp_gateway.mcp.store import create_mcp_server, get_mcp_server, init_mcp_database


@pytest.mark.asyncio
async def test_health_checker_stdio_transport_online(db_path, monkeypatch):
    init_mcp_database(db_path)
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


@pytest.mark.asyncio
async def test_health_checker_stdio_transport_timeout_returns_offline(db_path, monkeypatch):
    init_mcp_database(db_path)
    checker = HealthChecker(db_path)
    server_id = create_mcp_server(
        db_path,
        name="stdio-timeout",
        url="",
        transport_type="stdio",
        command="python",
    )

    class FakeTransport:
        async def send_request(self, payload, timeout):
            raise asyncio.TimeoutError

    class FakeManager:
        async def start_server(self, server_id, server):
            return None

        def get_transport(self, server_id):
            return FakeTransport()

    monkeypatch.setattr("authmcp_gateway.mcp.health.get_process_manager", lambda: FakeManager())

    result = await checker.check_server(
        {
            "id": server_id,
            "name": "stdio-timeout",
            "url": "",
            "transport_type": "stdio",
            "command": "python",
            "enabled": 1,
        }
    )

    assert result["status"] == "offline"
    assert result["error"] == "Timeout after 10s"
    server = get_mcp_server(db_path, server_id)
    assert server["status"] == "offline"
    assert server["last_error"] == "Timeout after 10s"
