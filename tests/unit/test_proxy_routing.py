import pytest

from authmcp_gateway.mcp.proxy import McpProxy
from authmcp_gateway.mcp.process_manager import StdioProcessManager


@pytest.mark.asyncio
async def test_proxy_jsonrpc_uses_injected_manager_for_stdio(db_path):
    manager = StdioProcessManager()
    proxy = McpProxy(db_path, process_manager=manager)

    server = {
        "id": 1,
        "name": "stdio-server",
        "transport_type": "stdio",
        "timeout": 12,
        "approval_state": "approved",
        "command": "python",
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

    try:
        result = await proxy._proxy_jsonrpc(server, "ping", {})
        assert result["result"]["ok"] is True
        assert manager.get_status(server["id"]) == "running"
    finally:
        await manager.stop_all()
