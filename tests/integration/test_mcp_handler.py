"""Tests for `mcp/handler.py` — JSON-RPC dispatcher with a mocked proxy.

The handler is a thin layer over `McpProxy`: it parses the JSON-RPC
envelope, dispatches to the right `_handle_*` method, formats the
response, and translates exceptions into JSON-RPC error codes. We mock
`McpProxy` whole — none of these tests need real httpx, real backends,
or real DB beyond the `mcp_db` fixture for `_log_mcp` writes.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from starlette.requests import Request

from authmcp_gateway.mcp import store
from authmcp_gateway.mcp.handler import McpHandler
from authmcp_gateway.mcp.proxy import (
    PromptNotFoundError,
    ResourceNotFoundError,
    ToolNotFoundError,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mcp_db(initialized_db):
    """auth + mcp tables ready (so _log_mcp writes don't crash)."""
    store.init_mcp_database(initialized_db)
    return initialized_db


@pytest.fixture
def fake_proxy():
    """A McpProxy stand-in where every async method is an AsyncMock."""
    proxy = MagicMock()
    proxy.get_aggregated_capabilities = AsyncMock(return_value={"tools": {}, "resources": {}})
    proxy.list_tools = AsyncMock(return_value=[])
    proxy.call_tool = AsyncMock()
    proxy.list_resources = AsyncMock(return_value=[])
    proxy.read_resource = AsyncMock()
    proxy.list_resource_templates = AsyncMock(return_value=[])
    proxy.list_prompts = AsyncMock(return_value=[])
    proxy.get_prompt = AsyncMock()
    proxy.complete = AsyncMock()
    return proxy


@pytest.fixture
def handler(mcp_db, fake_proxy):
    return McpHandler(db_path=mcp_db, proxy=fake_proxy)


def _make_request(*, body: dict, path: str = "/mcp") -> Request:
    """Build a Starlette Request with a stubbed json() method."""
    raw_headers = [(b"content-type", b"application/json")]
    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": raw_headers,
        "client": ("127.0.0.1", 12345),
        "state": {},
    }
    request = Request(scope)
    request.json = AsyncMock(return_value=body)  # type: ignore[assignment]
    return request


def _body(response) -> dict:
    return json.loads(response.body)


# ---------------------------------------------------------------------------
# handle_request — dispatch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatch_initialize(handler, fake_proxy):
    fake_proxy.get_aggregated_capabilities.return_value = {"tools": {}, "prompts": {}}

    response = await handler.handle_request(
        _make_request(body={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    )
    body = _body(response)
    assert body["id"] == 1
    assert body["result"]["protocolVersion"] == "2025-03-26"
    assert body["result"]["capabilities"] == {"tools": {}, "prompts": {}}
    assert body["result"]["serverInfo"]["name"] == "authmcp-gateway"


@pytest.mark.asyncio
async def test_dispatch_initialize_with_server_name_uses_server_name_as_display(handler):
    response = await handler.handle_request(
        _make_request(body={"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
        server_name="github",
    )
    body = _body(response)
    assert body["result"]["serverInfo"]["name"] == "github"


@pytest.mark.asyncio
async def test_dispatch_initialize_degrades_on_proxy_discovery_error(handler, fake_proxy):
    """If capability discovery raises, handler returns a default {tools: {}}."""
    import sqlite3

    fake_proxy.get_aggregated_capabilities.side_effect = sqlite3.OperationalError("db gone")
    response = await handler.handle_request(
        _make_request(body={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    )
    body = _body(response)
    assert body["result"]["capabilities"] == {"tools": {}}


@pytest.mark.asyncio
async def test_dispatch_ping_returns_empty_result(handler):
    response = await handler.handle_request(
        _make_request(body={"jsonrpc": "2.0", "id": 7, "method": "ping"})
    )
    body = _body(response)
    assert body == {"jsonrpc": "2.0", "id": 7, "result": {}}


@pytest.mark.asyncio
async def test_dispatch_notifications_initialized_with_id_returns_200_empty(handler):
    response = await handler.handle_request(
        _make_request(body={"jsonrpc": "2.0", "id": 99, "method": "notifications/initialized"})
    )
    body = _body(response)
    assert body == {"jsonrpc": "2.0", "id": 99, "result": {}}


@pytest.mark.asyncio
async def test_dispatch_notifications_initialized_without_id_returns_204(handler):
    response = await handler.handle_request(
        _make_request(body={"jsonrpc": "2.0", "method": "notifications/initialized"})
    )
    assert response.status_code == 204
    assert response.body == b""


@pytest.mark.asyncio
async def test_dispatch_other_notification_without_id_returns_204_no_body(handler):
    """Any non-`initialized` notification (no id) takes the catch-all branch.
    HTTP 204 must not carry a body — uvicorn/h11 raises LocalProtocolError if
    we declare Content-Length and then send bytes. Regression for a real
    incident triggered by a client sending `notifications/cancelled`."""
    response = await handler.handle_request(
        _make_request(body={"jsonrpc": "2.0", "method": "notifications/cancelled"})
    )
    assert response.status_code == 204
    assert response.body == b""


@pytest.mark.asyncio
async def test_dispatch_logging_setlevel_returns_empty_result(handler):
    response = await handler.handle_request(
        _make_request(
            body={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "logging/setLevel",
                "params": {"level": "debug"},
            }
        )
    )
    body = _body(response)
    assert body["result"] == {}


@pytest.mark.asyncio
async def test_dispatch_unknown_namespaced_method_returns_method_not_found(handler):
    response = await handler.handle_request(
        _make_request(body={"jsonrpc": "2.0", "id": 1, "method": "unknown/method"})
    )
    body = _body(response)
    assert body["error"]["code"] == -32601
    assert "Method not found" in body["error"]["message"]


@pytest.mark.asyncio
async def test_dispatch_codex_style_direct_call_routes_to_tool_call(handler, fake_proxy):
    """Non-namespaced unknown method (no `/`) is routed to tools/call (Codex compat)."""
    fake_proxy.call_tool.return_value = ({"result": {"content": "hi"}}, {"id": 1})

    response = await handler.handle_request(
        _make_request(
            body={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "do_thing",
                "params": {"x": 1},
            }
        )
    )
    body = _body(response)
    assert body["id"] == 1
    assert body["result"] == {"content": "hi"}

    # Verify the call was routed with the method name as tool_name
    call_kwargs = fake_proxy.call_tool.call_args.kwargs
    assert call_kwargs["tool_name"] == "do_thing"


@pytest.mark.asyncio
async def test_dispatch_top_level_exception_returns_minus_32603(handler, fake_proxy):
    """Unexpected exception in any handler is caught at the top and surfaces as -32603."""
    fake_proxy.list_tools.side_effect = RuntimeError("boom")

    response = await handler.handle_request(
        _make_request(body={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    )
    body = _body(response)
    assert body["error"]["code"] == -32603


@pytest.mark.asyncio
async def test_dispatch_handles_invalid_json_body(handler):
    """request.json() raising surfaces as -32603 internal error."""
    request = _make_request(body={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    request.json = AsyncMock(side_effect=json.JSONDecodeError("invalid", "", 0))

    response = await handler.handle_request(request)
    body = _body(response)
    assert body["error"]["code"] == -32603


# ---------------------------------------------------------------------------
# tools/list
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tools_list_strips_internal_fields_and_keeps_annotations(handler, fake_proxy):
    fake_proxy.list_tools.return_value = [
        {
            "name": "search",
            "description": "Search the KB",
            "inputSchema": {"type": "object"},
            "annotations": {"readOnly": True},
            "_server_id": 7,  # internal — must NOT round-trip
            "_server_name": "rag",
        },
    ]

    response = await handler.handle_request(
        _make_request(body={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    )
    body = _body(response)
    tools = body["result"]["tools"]
    assert len(tools) == 1
    t = tools[0]
    assert t["name"] == "search"
    assert t["description"] == "Search the KB"
    assert t["annotations"] == {"readOnly": True}
    # internals stripped
    assert "_server_id" not in t
    assert "_server_name" not in t


# ---------------------------------------------------------------------------
# tools/call
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tools_call_missing_name_returns_invalid_params(handler):
    response = await handler.handle_request(
        _make_request(body={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}})
    )
    body = _body(response)
    assert body["error"]["code"] == -32602
    assert "name" in body["error"]["message"].lower()


@pytest.mark.asyncio
async def test_tools_call_happy_path(handler, fake_proxy):
    fake_proxy.call_tool.return_value = (
        {"result": {"content": [{"type": "text", "text": "ok"}]}},
        {"id": 7, "name": "rag"},
    )

    response = await handler.handle_request(
        _make_request(
            body={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "search", "arguments": {"q": "hello"}},
            }
        )
    )
    body = _body(response)
    assert body["result"] == {"content": [{"type": "text", "text": "ok"}]}


@pytest.mark.asyncio
async def test_tools_call_propagates_backend_error_object(handler, fake_proxy):
    fake_proxy.call_tool.return_value = (
        {"error": {"code": -32000, "message": "backend exploded"}},
        {"id": 7},
    )

    response = await handler.handle_request(
        _make_request(
            body={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "search", "arguments": {}},
            }
        )
    )
    body = _body(response)
    assert body["error"]["message"] == "backend exploded"


@pytest.mark.asyncio
async def test_tools_call_invalid_response_returns_minus_32603(handler, fake_proxy):
    """Backend response with neither `result` nor `error` is treated as malformed."""
    fake_proxy.call_tool.return_value = ({"unexpected": "shape"}, {"id": 7})

    response = await handler.handle_request(
        _make_request(
            body={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "search", "arguments": {}},
            }
        )
    )
    body = _body(response)
    assert body["error"]["code"] == -32603


@pytest.mark.asyncio
async def test_tools_call_tool_not_found_returns_minus_32601(handler, fake_proxy):
    fake_proxy.call_tool.side_effect = ToolNotFoundError("no such tool: x")

    response = await handler.handle_request(
        _make_request(
            body={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "x", "arguments": {}},
            }
        )
    )
    body = _body(response)
    assert body["error"]["code"] == -32601


@pytest.mark.asyncio
async def test_tools_call_permission_error_returns_minus_32000(handler, fake_proxy):
    fake_proxy.call_tool.side_effect = PermissionError("user 5 cannot access server 7")

    response = await handler.handle_request(
        _make_request(
            body={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "x", "arguments": {}},
            }
        )
    )
    body = _body(response)
    assert body["error"]["code"] == -32000


@pytest.mark.asyncio
async def test_tools_call_value_error_returns_invalid_params(handler, fake_proxy):
    fake_proxy.call_tool.side_effect = ValueError("argument schema mismatch")

    response = await handler.handle_request(
        _make_request(
            body={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "x", "arguments": {}},
            }
        )
    )
    body = _body(response)
    assert body["error"]["code"] == -32602


# ---------------------------------------------------------------------------
# resources/*
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resources_list_returns_proxy_payload(handler, fake_proxy):
    fake_proxy.list_resources.return_value = [{"uri": "file:///x.md", "name": "x", "_server_id": 1}]
    response = await handler.handle_request(
        _make_request(body={"jsonrpc": "2.0", "id": 1, "method": "resources/list"})
    )
    body = _body(response)
    # _server_id is preserved in resources/list (handler doesn't filter it)
    assert "uri" in body["result"]["resources"][0]


@pytest.mark.asyncio
async def test_resources_read_missing_uri_returns_invalid_params(handler):
    response = await handler.handle_request(
        _make_request(
            body={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "resources/read",
                "params": {},
            }
        )
    )
    body = _body(response)
    assert body["error"]["code"] == -32602


@pytest.mark.asyncio
async def test_resources_read_happy_path(handler, fake_proxy):
    fake_proxy.read_resource.return_value = (
        {"result": {"contents": [{"uri": "file:///x", "text": "hi"}]}},
        {"id": 7},
    )
    response = await handler.handle_request(
        _make_request(
            body={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "resources/read",
                "params": {"uri": "file:///x"},
            }
        )
    )
    body = _body(response)
    assert body["result"]["contents"][0]["text"] == "hi"


@pytest.mark.asyncio
async def test_resources_read_resource_not_found(handler, fake_proxy):
    fake_proxy.read_resource.side_effect = ResourceNotFoundError("no such resource")
    response = await handler.handle_request(
        _make_request(
            body={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "resources/read",
                "params": {"uri": "file:///nope"},
            }
        )
    )
    body = _body(response)
    assert body["error"]["code"] == -32602


@pytest.mark.asyncio
async def test_resource_templates_list_strips_underscore_fields(handler, fake_proxy):
    fake_proxy.list_resource_templates.return_value = [
        {
            "uriTemplate": "file:///{name}",
            "name": "files",
            "_server_id": 1,
            "_internal": "x",
        }
    ]
    response = await handler.handle_request(
        _make_request(body={"jsonrpc": "2.0", "id": 1, "method": "resources/templates/list"})
    )
    body = _body(response)
    template = body["result"]["resourceTemplates"][0]
    assert "uriTemplate" in template
    assert "_server_id" not in template
    assert "_internal" not in template


# ---------------------------------------------------------------------------
# prompts/*
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_prompts_list_returns_proxy_payload(handler, fake_proxy):
    fake_proxy.list_prompts.return_value = [{"name": "summarize"}]
    response = await handler.handle_request(
        _make_request(body={"jsonrpc": "2.0", "id": 1, "method": "prompts/list"})
    )
    body = _body(response)
    assert body["result"]["prompts"] == [{"name": "summarize"}]


@pytest.mark.asyncio
async def test_prompts_get_missing_name_returns_invalid_params(handler):
    response = await handler.handle_request(
        _make_request(
            body={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "prompts/get",
                "params": {},
            }
        )
    )
    body = _body(response)
    assert body["error"]["code"] == -32602


@pytest.mark.asyncio
async def test_prompts_get_happy_path(handler, fake_proxy):
    fake_proxy.get_prompt.return_value = (
        {"result": {"messages": [{"role": "user", "content": "hi"}]}},
        {"id": 7},
    )
    response = await handler.handle_request(
        _make_request(
            body={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "prompts/get",
                "params": {"name": "summarize", "arguments": {"topic": "x"}},
            }
        )
    )
    body = _body(response)
    assert body["result"]["messages"][0]["role"] == "user"


@pytest.mark.asyncio
async def test_prompts_get_prompt_not_found(handler, fake_proxy):
    fake_proxy.get_prompt.side_effect = PromptNotFoundError("no prompt: x")
    response = await handler.handle_request(
        _make_request(
            body={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "prompts/get",
                "params": {"name": "x"},
            }
        )
    )
    body = _body(response)
    assert body["error"]["code"] == -32602


# ---------------------------------------------------------------------------
# completion/complete
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_completion_missing_params_returns_invalid_params(handler):
    response = await handler.handle_request(
        _make_request(
            body={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "completion/complete",
                "params": {"ref": "x"},  # missing argument
            }
        )
    )
    body = _body(response)
    assert body["error"]["code"] == -32602
    assert "argument" in body["error"]["message"].lower()


@pytest.mark.asyncio
async def test_completion_happy_path(handler, fake_proxy):
    fake_proxy.complete.return_value = (
        {"result": {"completion": {"values": ["alpha", "beta"]}}},
        {"id": 7},
    )
    response = await handler.handle_request(
        _make_request(
            body={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "completion/complete",
                "params": {
                    "ref": {"type": "ref/prompt", "name": "x"},
                    "argument": {"name": "topic", "value": "a"},
                },
            }
        )
    )
    body = _body(response)
    assert body["result"]["completion"]["values"] == ["alpha", "beta"]


# ---------------------------------------------------------------------------
# _error_response shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_error_response_uses_jsonrpc_error_envelope(handler):
    """Spot-check the error envelope shape via a trigger we already have."""
    response = await handler.handle_request(
        _make_request(
            body={
                "jsonrpc": "2.0",
                "id": 42,
                "method": "tools/call",
                "params": {},  # missing name → -32602
            }
        )
    )
    body = _body(response)
    assert body == {
        "jsonrpc": "2.0",
        "id": 42,
        "error": {
            "code": -32602,
            "message": "Missing required parameter: name",
        },
    }
    # Even error responses use HTTP 200 (JSON-RPC convention).
    assert response.status_code == 200


# Quiet unused-import warning for SimpleNamespace if linter flags it.
_ = SimpleNamespace
