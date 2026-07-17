import asyncio
import json
import sys
from types import SimpleNamespace

import pytest
from starlette.requests import Request

from authmcp_gateway.admin import mcp_servers_api
from authmcp_gateway.mcp.process_manager import StdioProcessManager
from authmcp_gateway.mcp.proxy import McpProxy


def _request(method: str, path: str, path_params: dict, runtime, body: bytes = b""):
    async def _receive():
        return {"type": "http.request", "body": body, "more_body": False}

    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": [(b"content-type", b"application/json")] if body else [],
        "query_string": b"",
        "path_params": path_params,
        "app": SimpleNamespace(state=SimpleNamespace(mcp_runtime=runtime)),
    }
    return Request(scope, _receive)


def _stdio_server_config():
    return {
        "command": sys.executable,
        "command_args": [
            "-u",
            "-c",
            (
                "import json,sys\n"
                "for line in sys.stdin:\n"
                " req=json.loads(line)\n"
                " print(json.dumps({'jsonrpc':'2.0','id':req.get('id'),'result':{'ok':True}}), flush=True)\n"
            ),
        ],
    }


@pytest.mark.asyncio
async def test_blocked_stdio_manager_rejects_send_and_restart():
    manager = StdioProcessManager()
    try:
        await manager.start_server(11, _stdio_server_config())

        response = await manager.send_request(
            11,
            {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}},
            timeout=5,
        )
        assert response["result"]["ok"] is True

        await manager.block_server(11)
        assert manager.is_blocked(11) is True
        assert manager.get_status(11) == "running"

        with pytest.raises(PermissionError, match="blocked"):
            await manager.send_request(
                11,
                {"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {}},
                timeout=5,
            )
        with pytest.raises(PermissionError, match="blocked"):
            await manager.restart_server(11)
    finally:
        await manager.stop_all()


@pytest.mark.asyncio
async def test_block_and_stop_leaves_transport_stopped():
    manager = StdioProcessManager()
    try:
        await manager.start_server(12, _stdio_server_config())
        assert manager.get_status(12) == "running"

        await manager.block_and_stop_server(12)
        assert manager.is_blocked(12) is True
        assert manager.get_status(12) == "stopped"
    finally:
        await manager.stop_all()


@pytest.mark.asyncio
async def test_block_waits_for_inflight_send_then_rejects_new_requests():
    manager = StdioProcessManager()
    started = asyncio.Event()
    release = asyncio.Event()
    block_task = None

    class FakeTransport:
        def is_running(self):
            return True

        async def send_request(self, payload, timeout):
            started.set()
            await release.wait()
            return {"jsonrpc": "2.0", "id": payload["id"], "result": {"ok": True}}

        async def close(self):
            return None

    manager._transports[22] = FakeTransport()

    send_task = asyncio.create_task(
        manager.send_request(22, {"jsonrpc": "2.0", "id": 1, "method": "ping"}, timeout=5)
    )
    try:
        await started.wait()
        block_task = asyncio.create_task(manager.block_server(22))
        await asyncio.sleep(0)
        assert manager.is_blocked(22) is True
        assert not send_task.done()

        release.set()
        assert (await send_task)["result"]["ok"] is True
        await block_task
        assert manager.is_blocked(22) is True

        with pytest.raises(PermissionError, match="blocked"):
            await manager.send_request(
                22, {"jsonrpc": "2.0", "id": 2, "method": "ping"}, timeout=5
            )
    finally:
        release.set()
        if not send_task.done():
            await send_task
        if block_task is not None and not block_task.done():
            await block_task
        await manager.stop_all()


@pytest.mark.asyncio
async def test_proxy_rejects_blocked_stdio_transport_even_when_cached(monkeypatch):
    proxy = McpProxy("/tmp/unused.db")
    proxy._process_manager = SimpleNamespace(is_blocked=lambda _server_id: True)

    class FakeTransport:
        async def send_request(self, payload, timeout):
            raise AssertionError("cached transport must not be used")

    proxy._transports[33] = FakeTransport()

    server = {
        "id": 33,
        "name": "stdio-srv",
        "transport_type": "stdio",
        "approval_state": "approved",
        "enabled": True,
        "command": sys.executable,
    }

    with pytest.raises(PermissionError, match="blocked"):
        await proxy._get_transport(server, {})


@pytest.mark.asyncio
async def test_update_mcp_server_rejects_non_boolean_enabled(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    runtime = SimpleNamespace(proxy=None, process_manager=None)
    request = _request(
        "POST",
        "/admin/api/mcp-servers/44",
        {"server_id": "44"},
        runtime,
        body=json.dumps({"enabled": "false"}).encode("utf-8"),
    )
    monkeypatch.setattr(mcp_servers_api, "get_config", lambda _req: DummyConfig())
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.get_mcp_server",
        lambda *_args, **_kwargs: {
            "id": 44,
            "name": "srv",
            "approval_state": "approved",
            "enabled": True,
            "transport_type": "stdio",
            "command": "python",
            "command_args": [],
            "env_vars": {},
        },
    )
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.update_mcp_server",
        lambda *_args, **_kwargs: pytest.fail("update_mcp_server should not be called"),
    )

    response = await mcp_servers_api.api_update_mcp_server(request)

    assert response.status_code == 400
    payload = json.loads(response.body.decode("utf-8"))
    assert "enabled must be a JSON boolean" in payload["error"]
