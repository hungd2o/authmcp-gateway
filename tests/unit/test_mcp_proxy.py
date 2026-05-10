from datetime import datetime, timedelta, timezone

import pytest

from authmcp_gateway.mcp.proxy import McpProxy


def test_get_execution_policy_reads_standard_annotations(db_path):
    proxy = McpProxy(db_path)

    policy = proxy._get_execution_policy(
        {
            "annotations": {
                "readOnlyHint": False,
                "idempotentHint": True,
            }
        }
    )

    assert policy["mutation"] is True
    assert policy["idempotency"] == "supported"
    assert policy["retry"] == "safe_with_idempotency"
    assert policy["timeout_ms"] is None


def test_get_execution_policy_reads_read_only_annotation_as_safe(db_path):
    proxy = McpProxy(db_path)

    policy = proxy._get_execution_policy(
        {
            "annotations": {
                "readOnlyHint": True,
            }
        }
    )

    assert policy["mutation"] is False
    assert policy["idempotency"] == "unsupported"
    assert policy["retry"] == "safe"


def test_get_execution_policy_uses_meta_execution_as_extension(db_path):
    proxy = McpProxy(db_path)

    policy = proxy._get_execution_policy(
        {
            "annotations": {
                "destructiveHint": True,
            },
            "_meta": {
                "execution": {
                    "idempotency": "supported",
                    "retry": "safe_with_idempotency",
                    "timeout_ms": 90000,
                }
            },
        }
    )

    assert policy["mutation"] is True
    assert policy["idempotency"] == "supported"
    assert policy["retry"] == "safe_with_idempotency"
    assert policy["timeout_ms"] == 90000


def test_get_execution_policy_falls_back_conservatively_on_invalid_metadata(db_path):
    proxy = McpProxy(db_path)

    policy = proxy._get_execution_policy(
        {
            "_meta": {
                "execution": {
                    "mutation": "yes",
                    "idempotency": "broken",
                    "retry": "sometimes",
                }
            }
        }
    )

    assert policy["mutation"] is None
    assert policy["idempotency"] == "unsupported"
    assert policy["retry"] == "never"
    assert policy["timeout_ms"] is None


def test_prepare_tool_arguments_generates_idempotency_key_for_supported_tool(db_path):
    proxy = McpProxy(db_path)

    prepared, key, generated = proxy._prepare_tool_arguments(
        {
            "mutation": True,
            "idempotency": "supported",
            "retry": "safe_with_idempotency",
            "timeout_ms": 90000,
        },
        {"message": "hi"},
    )

    assert generated is True
    assert key
    assert prepared["idempotency_key"] == key


def test_prepare_tool_arguments_reuses_existing_idempotency_key(db_path):
    proxy = McpProxy(db_path)

    prepared, key, generated = proxy._prepare_tool_arguments(
        {
            "mutation": True,
            "idempotency": "supported",
            "retry": "safe_with_idempotency",
            "timeout_ms": 120000,
        },
        {"idempotency_key": "req-123", "caption": "file"},
    )

    assert generated is False
    assert key == "req-123"
    assert prepared["idempotency_key"] == "req-123"


def test_prepare_tool_arguments_does_not_add_key_for_unsupported_tool(db_path):
    proxy = McpProxy(db_path)

    prepared, key, generated = proxy._prepare_tool_arguments(
        {
            "mutation": False,
            "idempotency": "unsupported",
            "retry": "safe",
            "timeout_ms": 30000,
        },
        {"limit": 5},
    )

    assert generated is False
    assert key is None
    assert "idempotency_key" not in prepared


def test_prepare_tool_arguments_does_not_add_key_for_safe_read_only_tool(db_path):
    proxy = McpProxy(db_path)

    prepared, key, generated = proxy._prepare_tool_arguments(
        {
            "mutation": False,
            "idempotency": "supported",
            "retry": "safe",
            "timeout_ms": None,
        },
        {"limit": 5},
    )

    assert generated is False
    assert key is None
    assert "idempotency_key" not in prepared


def test_should_retry_tool_call_requires_idempotency_contract(db_path):
    proxy = McpProxy(db_path)

    assert (
        proxy._should_retry_tool_call(
            {
                "mutation": True,
                "idempotency": "supported",
                "retry": "safe_with_idempotency",
                "timeout_ms": 90000,
            },
            {"idempotency_key": "abc"},
        )
        is True
    )
    assert (
        proxy._should_retry_tool_call(
            {
                "mutation": True,
                "idempotency": "supported",
                "retry": "safe_with_idempotency",
                "timeout_ms": 90000,
            },
            {},
        )
        is False
    )
    assert (
        proxy._should_retry_tool_call(
            {
                "mutation": False,
                "idempotency": "unsupported",
                "retry": "safe",
                "timeout_ms": 30000,
            },
            {},
        )
        is True
    )


def test_build_dedup_key_prefers_idempotency_key(db_path):
    proxy = McpProxy(db_path)
    server = {"id": 8}

    key = proxy._build_dedup_key(
        server,
        "send_message",
        {
            "idempotency_key": "idem-1",
            "client_request_id": "client-1",
            "recipient_jid": "123@s.whatsapp.net",
            "message": "hello",
        },
    )

    assert key == "8:send_message:idem:idem-1"


@pytest.mark.asyncio
async def test_list_tools_applies_prefixes_on_aggregated_endpoint(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    servers = [
        {"id": 1, "name": "RAG Home", "tool_prefix": "rag_"},
        {"id": 2, "name": "WhatsApp", "tool_prefix": "wa_"},
    ]

    def fake_get_servers(user_id=None, server_name=None):
        assert server_name is None
        return servers

    async def fake_fetch_tools_from_server(server):
        if server["id"] == 1:
            return [{"name": "search", "description": "Search docs", "inputSchema": {}}]
        if server["id"] == 2:
            return [{"name": "send_message", "description": "Send message", "inputSchema": {}}]
        return []

    monkeypatch.setattr(proxy, "_get_servers", fake_get_servers)
    monkeypatch.setattr(proxy, "_fetch_tools_from_server", fake_fetch_tools_from_server)

    tools = await proxy.list_tools()

    assert [tool["name"] for tool in tools] == ["rag_search", "wa_send_message"]


@pytest.mark.asyncio
async def test_list_tools_keeps_raw_names_on_server_specific_endpoint(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    server = {"id": 1, "name": "RAG Home", "tool_prefix": "rag_"}

    def fake_get_servers(user_id=None, server_name=None):
        assert server_name == "raghome"
        return [server]

    async def fake_fetch_tools_from_server(_server):
        return [{"name": "search", "description": "Search docs", "inputSchema": {}}]

    monkeypatch.setattr(proxy, "_get_servers", fake_get_servers)
    monkeypatch.setattr(proxy, "_fetch_tools_from_server", fake_fetch_tools_from_server)

    tools = await proxy.list_tools(server_name="raghome")

    assert [tool["name"] for tool in tools] == ["search"]


@pytest.mark.asyncio
async def test_call_tool_strips_prefix_before_backend_request(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    server = {"id": 2, "name": "WhatsApp", "tool_prefix": "wa_"}
    proxy._tools_cache[2] = [
        {
            "name": "send_message",
            "description": "Send message",
            "inputSchema": {},
            "annotations": {"readOnlyHint": False},
        }
    ]

    async def fake_route_tool_to_server(tool_name, user_id=None, server_name=None):
        assert tool_name == "wa_send_message"
        assert server_name is None
        return server

    captured = {}

    async def fake_proxy_jsonrpc(
        target_server,
        method,
        params=None,
        allow_retry=True,
        timeout_override_ms=None,
    ):
        captured["server"] = target_server
        captured["method"] = method
        captured["params"] = params
        captured["allow_retry"] = allow_retry
        captured["timeout_override_ms"] = timeout_override_ms
        return {"result": {"content": [], "isError": False}}

    monkeypatch.setattr(proxy, "_route_tool_to_server", fake_route_tool_to_server)
    monkeypatch.setattr(proxy, "_proxy_jsonrpc", fake_proxy_jsonrpc)

    data, routed_server = await proxy.call_tool("wa_send_message", {"message": "hi"})

    assert routed_server == server
    assert data["result"]["_meta"]["tool_name"] == "wa_send_message"
    assert captured["server"] == server
    assert captured["method"] == "tools/call"
    assert captured["params"]["name"] == "send_message"
    assert captured["params"]["arguments"] == {"message": "hi"}


@pytest.mark.asyncio
async def test_fetch_resources_skips_when_capability_not_advertised(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    server = {"id": 8, "name": "WhatsApp", "url": "http://example.test/mcp"}

    async def fake_ensure_session(_server):
        proxy._capabilities_cache[8] = {"tools": {}}

    called = False

    async def fake_proxy_jsonrpc(*args, **kwargs):
        nonlocal called
        called = True
        return {"result": {"resources": [{"uri": "resource://unexpected"}]}}

    monkeypatch.setattr(proxy, "_ensure_session", fake_ensure_session)
    monkeypatch.setattr(proxy, "_proxy_jsonrpc", fake_proxy_jsonrpc)

    resources = await proxy._fetch_resources_from_server(server)

    assert resources == []
    assert called is False
    assert proxy._resources_cache[8] == []


@pytest.mark.asyncio
async def test_fetch_resources_calls_backend_when_capability_advertised(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    server = {"id": 8, "name": "WhatsApp", "url": "http://example.test/mcp"}

    async def fake_ensure_session(_server):
        proxy._capabilities_cache[8] = {"tools": {}, "resources": {}}

    called = False

    async def fake_proxy_jsonrpc(_server, method, params=None, **kwargs):
        nonlocal called
        called = True
        assert method == "resources/list"
        return {"result": {"resources": [{"uri": "resource://one"}]}}

    monkeypatch.setattr(proxy, "_ensure_session", fake_ensure_session)
    monkeypatch.setattr(proxy, "_proxy_jsonrpc", fake_proxy_jsonrpc)

    resources = await proxy._fetch_resources_from_server(server)

    assert called is True
    assert len(resources) == 1
    assert resources[0]["uri"] == "resource://one"
    assert resources[0]["_server_id"] == 8
    assert resources[0]["_server_name"] == "WhatsApp"


@pytest.mark.asyncio
async def test_fetch_capabilities_uses_cached_value_even_after_ttl(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    server = {"id": 8, "name": "WhatsApp", "url": "http://example.test/mcp"}
    proxy._capabilities_cache[8] = {"tools": {}, "resources": {}}
    proxy._cache_timestamp[8] = datetime.now(timezone.utc) - timedelta(hours=1)

    called = False

    async def fake_proxy_jsonrpc(*args, **kwargs):
        nonlocal called
        called = True
        return {"result": {"capabilities": {"tools": {}}}}

    monkeypatch.setattr(proxy, "_proxy_jsonrpc", fake_proxy_jsonrpc)

    caps = await proxy._fetch_capabilities_from_server(server)

    assert caps == {"tools": {}, "resources": {}}
    assert called is False


@pytest.mark.asyncio
async def test_fetch_capabilities_avoids_initialize_when_session_exists(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    server = {"id": 8, "name": "WhatsApp", "url": "http://example.test/mcp"}
    proxy._session_ids[8] = "session-123"

    called = False

    async def fake_proxy_jsonrpc(*args, **kwargs):
        nonlocal called
        called = True
        return {"result": {"capabilities": {"tools": {}}}}

    monkeypatch.setattr(proxy, "_proxy_jsonrpc", fake_proxy_jsonrpc)

    caps = await proxy._fetch_capabilities_from_server(server)

    assert caps == {"tools": {}}
    assert called is False


@pytest.mark.asyncio
async def test_fetch_capabilities_handles_already_initialized_as_non_fatal(db_path, monkeypatch):
    proxy = McpProxy(db_path)
    server = {"id": 8, "name": "WhatsApp", "url": "http://example.test/mcp"}

    async def fake_proxy_jsonrpc(*args, **kwargs):
        raise RuntimeError("Invalid Request: Server already initialized")

    monkeypatch.setattr(proxy, "_proxy_jsonrpc", fake_proxy_jsonrpc)

    caps = await proxy._fetch_capabilities_from_server(server)

    assert caps == {"tools": {}}
