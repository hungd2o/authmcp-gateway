import asyncio

import pytest

from authmcp_gateway.mcp.health import HealthChecker
from authmcp_gateway.mcp.store import create_mcp_server, get_mcp_server, init_mcp_database


class _FakeLease:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.released = False
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        self.released = True

    async def send_request(self, method, params, *, timeout):
        self.calls.append((method, params, timeout))
        if self.error:
            raise self.error
        return self.response


@pytest.mark.asyncio
async def test_health_checker_stdio_transport_online(db_path, monkeypatch):
    init_mcp_database(db_path)
    checker = HealthChecker(db_path)

    class FakeManager:
        def __init__(self):
            self.lease = _FakeLease({"result": {"tools": [{"name": "a"}]}})
            self.acquires = []

        def status_detail(self, _server_id):
            return {"state": "running", "workers": {"ready": 2}, "max_workers": 2}

        async def acquire(self, server_id, *, purpose, timeout):
            self.acquires.append((server_id, purpose, timeout))
            return self.lease

    manager = FakeManager()
    monkeypatch.setattr("authmcp_gateway.mcp.health.get_process_manager", lambda: manager)

    result = await checker.check_server(
        {
            "id": 1,
            "name": "stdio",
            "url": "",
            "transport_type": "stdio",
            "command": "python",
            "enabled": 1,
            "approval_state": "approved",
        }
    )

    assert result["status"] == "online"
    assert result["tools_count"] == 1
    assert manager.acquires == [(1, "health", 1.0)]
    assert manager.lease.calls == [("tools/list", {}, 10.0)]
    assert manager.lease.released is True


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

    class FakeManager:
        def __init__(self):
            self.lease = _FakeLease(error=asyncio.TimeoutError())

        def status_detail(self, _server_id):
            return {"state": "running", "workers": {"ready": 2}, "max_workers": 2}

        async def acquire(self, _server_id, *, purpose, timeout):
            assert purpose == "health"
            assert timeout == 1.0
            return self.lease

    manager = FakeManager()
    monkeypatch.setattr("authmcp_gateway.mcp.health.get_process_manager", lambda: manager)

    result = await checker.check_server(
        {
            "id": server_id,
            "name": "stdio-timeout",
            "url": "",
            "transport_type": "stdio",
            "command": "python",
            "enabled": 1,
            "approval_state": "approved",
        }
    )

    assert result["status"] == "offline"
    assert result["error"] == "Timeout after 10s"
    server = get_mcp_server(db_path, server_id)
    assert server["status"] == "offline"
    assert server["last_error"] == "Timeout after 10s"
    assert manager.lease.released is True


@pytest.mark.asyncio
async def test_health_checker_stdio_uses_short_low_priority_lease_without_starting_server(
    db_path, monkeypatch
):
    init_mcp_database(db_path)
    checker = HealthChecker(db_path, timeout=12)

    class FakeManager:
        def __init__(self):
            self.acquires = []

        async def start_server(self, *_args):
            raise AssertionError("health checks must not eagerly start STDIO servers")

        def status_detail(self, _server_id):
            return {"state": "stopped", "workers": {}, "max_workers": 1}

        async def acquire(self, server_id, *, purpose, timeout):
            self.acquires.append((server_id, purpose, timeout))
            raise RuntimeError("STDIO server 7 is not configured")

    manager = FakeManager()
    monkeypatch.setattr("authmcp_gateway.mcp.health.get_process_manager", lambda: manager)

    result = await checker.check_server(
        {
            "id": 7,
            "name": "lazy-stdio",
            "url": "",
            "transport_type": "stdio",
            "command": "python",
            "enabled": True,
            "approval_state": "approved",
        }
    )

    assert result["status"] == "deferred"
    assert result["detail"] == "STDIO pool is lazy and has not started"
    assert manager.acquires == []


@pytest.mark.asyncio
async def test_health_checker_skips_pending_servers(db_path, monkeypatch):
    checker = HealthChecker(db_path)
    monkeypatch.setattr(
        "authmcp_gateway.mcp.health.list_mcp_servers",
        lambda *_args, **_kwargs: [
            {"id": 1, "name": "approved", "approval_state": "approved"},
            {"id": 2, "name": "pending", "approval_state": "pending"},
        ],
    )
    seen = []

    async def fake_check_server(server):
        seen.append(server["id"])
        return {"server_id": server["id"], "status": "online"}

    monkeypatch.setattr(checker, "check_server", fake_check_server)
    await checker.check_all_servers()
    assert seen == [1]
