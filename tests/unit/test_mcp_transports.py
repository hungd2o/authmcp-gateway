import asyncio
import os
import sys

import pytest

from authmcp_gateway.mcp.transports.pipe_transport import PipeTransport
from authmcp_gateway.mcp.transports.stdio_transport import StdioTransport


@pytest.mark.asyncio
async def test_stdio_transport_send_request_roundtrip():
    transport = StdioTransport(
        command=sys.executable,
        command_args=[
            "-u",
            "-c",
            (
                "import json,sys\n"
                "for line in sys.stdin:\n"
                " req=json.loads(line)\n"
                " out={'jsonrpc':'2.0','id':req.get('id'),'result':{'ok':True}}\n"
                " print(json.dumps(out), flush=True)\n"
            ),
        ],
    )

    data = await transport.send_request(
        {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}},
        timeout=5,
    )

    assert data["result"]["ok"] is True
    await transport.close()


@pytest.mark.asyncio
@pytest.mark.skipif(os.name == "nt", reason="Unix domain socket test")
async def test_pipe_transport_unix_socket_roundtrip(tmp_path):
    socket_path = str(tmp_path / "mcp.sock")

    async def handler(reader, writer):
        raw = await reader.readline()
        _ = raw.decode("utf-8")
        writer.write(b'{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}\n')
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_unix_server(handler, path=socket_path)
    try:
        transport = PipeTransport(socket_path)
        data = await transport.send_request(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            timeout=5,
        )
        assert "result" in data
        assert data["result"]["tools"] == []
        await transport.close()
    finally:
        server.close()
        await server.wait_closed()
