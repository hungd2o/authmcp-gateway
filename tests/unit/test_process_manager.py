import sys

import pytest

from authmcp_gateway.mcp.process_manager import StdioProcessManager
from authmcp_gateway.mcp.stdio_worker import WorkerState


def _server_config():
    return {
        "command": sys.executable,
        "command_args": [
            "-u",
            "-c",
            (
                "import json,sys\n"
                "for line in sys.stdin:\n"
                " req=json.loads(line)\n"
                " print(json.dumps({'jsonrpc':'2.0','id':req.get('id'),'result':{'tools':[]}}), flush=True)\n"
            ),
        ],
    }


@pytest.mark.asyncio
async def test_process_manager_start_stop_and_status():
    manager = StdioProcessManager()

    await manager.start_server(1, _server_config())
    assert manager.get_status(1) == "running"

    await manager.stop_server(1)
    assert manager.get_status(1) == "stopped"


@pytest.mark.asyncio
async def test_acquire_lease_runs_request_and_releases_worker():
    manager = StdioProcessManager()
    try:
        await manager.start_server(2, _server_config())

        async with await manager.acquire(2, purpose="request") as lease:
            assert lease.worker.state is WorkerState.BUSY
            response = await lease.send_request("tools/list", {}, timeout=5)
            assert response["result"] == {"tools": []}

        detail = manager.status_detail(2)
        assert detail["workers"]["busy"] == 0
        assert detail["workers"]["ready"] == 1
    finally:
        await manager.stop_all()


@pytest.mark.asyncio
async def test_probe_tools_uses_a_managed_worker():
    manager = StdioProcessManager()
    try:
        await manager.start_server(5, _server_config())

        assert await manager.probe_tools(5, timeout=5) == 0
        assert manager.status_detail(5)["workers"]["ready"] == 1
    finally:
        await manager.stop_all()


@pytest.mark.asyncio
async def test_proxy_starts_stdio_pool_only_when_the_first_request_arrives():
    from authmcp_gateway.mcp.proxy import McpProxy

    manager = StdioProcessManager()
    proxy = McpProxy("/tmp/unused.db", process_manager=manager)
    server = {
        "id": 3,
        "name": "lazy",
        "transport_type": "stdio",
        "approval_state": "approved",
        **_server_config(),
    }
    try:
        assert manager.get_status(3) == "stopped"

        response = await proxy._proxy_jsonrpc(server, "tools/list", {})

        assert response["result"] == {"tools": []}
        assert manager.get_status(3) == "running"
    finally:
        await manager.stop_all()


def test_status_detail_exposes_runtime_counters_without_sensitive_configuration():
    manager = StdioProcessManager()

    detail = manager.status_detail(4)

    assert detail == {"server_id": 4, "state": "stopped", "generation": 0, "workers": {}}
    assert not ({"command", "command_args", "env_vars", "working_dir"} & detail.keys())


@pytest.mark.asyncio
async def test_get_status_detail_exposes_live_worker_snapshot_and_restart_count():
    manager = StdioProcessManager()
    try:
        await manager.start_server(6, _server_config())
        first = manager.get_status_detail(6)

        assert first["aggregate"] == "running"
        assert first["pool_size"] == 1
        assert first["restart_count"] == 0
        assert first["workers"][0]["pid"] is not None
        assert first["workers"][0]["uptime_secs"] is not None
        assert not ({"command", "command_args", "env_vars", "working_dir"} & first.keys())

        await manager.stop_server(6)
        await manager.start_server(6, _server_config())
        second = manager.get_status_detail(6)

        assert second["aggregate"] == "running"
        assert second["restart_count"] == 1
    finally:
        await manager.stop_all()


@pytest.mark.asyncio
async def test_live_status_detail_exposes_safe_worker_operations_data():
    manager = StdioProcessManager()
    try:
        await manager.start_server(8, _server_config())

        detail = manager.get_status_detail(8)

        assert detail["aggregate"] == "running"
        assert detail["generation"] == 1
        assert detail["max_workers"] >= 1
        assert detail["workers"][0]["pid"] is not None
        assert detail["workers"][0]["uptime_secs"] is not None
        assert not ({"command", "command_args", "env_vars", "working_dir"} & detail.keys())
    finally:
        await manager.stop_all()


@pytest.mark.asyncio
async def test_live_status_detail_reports_dead_workers_as_failed():
    manager = StdioProcessManager()
    try:
        await manager.start_server(9, _server_config())
        process = manager._pools[9].workers[0].transport._proc
        assert process is not None
        process.terminate()
        await process.wait()

        detail = manager.get_status_detail(9)

        assert detail["aggregate"] == "failed"
        assert detail["workers"][0]["state"] == "dead"
        assert detail["workers"][0]["last_exit_code"] not in {None, 0}
    finally:
        await manager.stop_all()
