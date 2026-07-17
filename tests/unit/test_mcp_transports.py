import asyncio
import os
import sys

import pytest

from authmcp_gateway.mcp.transports import pipe_transport as pipe_transport_module
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
    try:
        await transport.start()
        data = await transport.send_request(
            {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}},
            timeout=5,
        )

        assert data["result"]["ok"] is True
    finally:
        await transport.close()


@pytest.mark.asyncio
async def test_stdio_transport_handles_large_single_line_response():
    large_value = "x" * (5 * 1024 * 1024)
    transport = StdioTransport(
        command=sys.executable,
        command_args=[
            "-u",
            "-c",
                (
                    "import json,sys\n"
                    "payload='x'*(5*1024*1024)\n"
                    "for line in sys.stdin:\n"
                    " req=json.loads(line)\n"
                    " out={'jsonrpc':'2.0','id':req.get('id'),'result':{'blob':payload}}\n"
                    " print(json.dumps(out), flush=True)\n"
                ),
        ],
    )
    try:
        await transport.start()
        data = await transport.send_request(
            {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}},
            timeout=5,
        )

        assert data["result"]["blob"] == large_value
    finally:
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


class _FakePipeReader:
    def __init__(self, raw: bytes):
        self._raw = raw

    async def readline(self):
        return self._raw


class _FakePipeWriter:
    def __init__(self):
        self.buffer = bytearray()

    def write(self, data: bytes):
        self.buffer.extend(data)

    async def drain(self):
        return None

    def close(self):
        return None

    async def wait_closed(self):
        return None


@pytest.mark.asyncio
async def test_pipe_transport_passes_reader_limit(monkeypatch):
    large_value = "x" * (128 * 1024)
    response = (
        '{"jsonrpc":"2.0","id":1,"result":{"blob":"'
        + large_value
        + '"}}\n'
    ).encode("utf-8")
    captured = {}

    async def fake_open_connection(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return _FakePipeReader(response), _FakePipeWriter()

    async def fake_open_unix_connection(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return _FakePipeReader(response), _FakePipeWriter()

    if pipe_transport_module.os.name == "nt":
        monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    else:
        monkeypatch.setattr(asyncio, "open_unix_connection", fake_open_unix_connection)

    transport = PipeTransport("pipe://demo")
    data = await transport.send_request(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        timeout=5,
    )

    assert captured["kwargs"]["limit"] == transport.STREAM_READER_LIMIT
    assert data["result"]["blob"] == large_value
