import sys

import pytest

from authmcp_gateway.mcp.process_manager import StdioProcessManager


@pytest.mark.asyncio
async def test_process_manager_start_stop_and_status():
    manager = StdioProcessManager()

    server_config = {
        "command": sys.executable,
        "command_args": [
            "-u",
            "-c",
            (
                "import json,sys\n"
                "for line in sys.stdin:\n"
                " req=json.loads(line)\n"
                " print(json.dumps({'jsonrpc':'2.0','id':req.get('id'),'result':{}}), flush=True)\n"
            ),
        ],
    }

    await manager.start_server(1, server_config)
    assert manager.get_status(1) == "running"

    await manager.stop_server(1)
    assert manager.get_status(1) == "stopped"
