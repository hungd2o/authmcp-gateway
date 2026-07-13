import json
import sys
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from authmcp_gateway.mcp import proxy as proxy_module
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


def test_get_servers_filters_unapproved(monkeypatch, db_path):
    proxy = McpProxy(db_path)
    monkeypatch.setattr(
        "authmcp_gateway.mcp.proxy.list_mcp_servers",
        lambda *_args, **_kwargs: [
            {"id": 1, "name": "approved", "approval_state": "approved"},
            {"id": 2, "name": "pending", "approval_state": "pending"},
        ],
    )
    servers = proxy._get_servers()
    assert [s["id"] for s in servers] == [1]


@pytest.mark.asyncio
async def test_execute_virtual_tool_http_call_supports_path_query_and_headers(monkeypatch, db_path):
    proxy = McpProxy(db_path)
    virtual_tool = {
        "name": "virt_http",
        "approval_state": "approved",
        "mcp_server_id": 7,
        "execution_type": "http_call",
        "config": {
            "request": {
                "method": "GET",
                "url": "https://api.example.com/users/{{arguments.user_id}}",
                "headers": {"X-Token": "{{arguments.token}}"},
                "query": {"limit": "{{arguments.limit}}", "active": "{{arguments.active}}"},
            }
        },
    }
    source_server = {"id": 7, "name": "srv", "approval_state": "approved", "timeout": 9}
    captured = {}

    monkeypatch.setattr(
        "authmcp_gateway.mcp.proxy.get_mcp_server", lambda *_args, **_kwargs: source_server
    )

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def request(self, method, url, json=None, params=None, headers=None):
            captured["method"] = method
            captured["url"] = url
            captured["json"] = json
            captured["params"] = params
            captured["headers"] = headers
            return httpx.Response(
                200,
                json={"ok": True},
                headers={"content-type": "application/json"},
                request=httpx.Request(method, url),
            )

    monkeypatch.setattr(proxy_module.httpx, "AsyncClient", FakeAsyncClient)

    result = await proxy._execute_virtual_tool(
        virtual_tool,
        {"user_id": "abc/123", "token": "secret", "limit": 25, "active": True},
        None,
        None,
    )

    assert captured["method"] == "GET"
    assert captured["url"] == "https://api.example.com/users/abc%2F123"
    assert captured["json"] is None
    assert captured["params"] == {"limit": "25", "active": "true"}
    assert captured["headers"]["X-Token"] == "secret"
    assert result["result"]["isError"] is False


@pytest.mark.asyncio
async def test_execute_virtual_tool_http_call_uses_body_template(monkeypatch, db_path):
    proxy = McpProxy(db_path)
    virtual_tool = {
        "name": "virt_http_post",
        "approval_state": "approved",
        "mcp_server_id": 7,
        "execution_type": "http_call",
        "config": {
            "request": {
                "method": "POST",
                "url": "https://api.example.com/messages",
                "body": {"message": "{{arguments.text}}", "meta": "{{arguments.meta}}"},
            }
        },
    }
    source_server = {"id": 7, "name": "srv", "approval_state": "approved", "timeout": 9}
    captured = {}

    monkeypatch.setattr(
        "authmcp_gateway.mcp.proxy.get_mcp_server", lambda *_args, **_kwargs: source_server
    )

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def request(self, method, url, json=None, params=None, headers=None):
            captured["json"] = json
            captured["params"] = params
            return httpx.Response(
                200,
                text="ok",
                headers={"content-type": "text/plain"},
                request=httpx.Request(method, url),
            )

    monkeypatch.setattr(proxy_module.httpx, "AsyncClient", FakeAsyncClient)

    result = await proxy._execute_virtual_tool(
        virtual_tool,
        {"text": "hello", "meta": {"source": "ui"}},
        None,
        None,
    )

    assert captured["params"] is None
    assert captured["json"] == {"message": "hello", "meta": {"source": "ui"}}
    assert result["result"]["content"][0]["text"] == "ok"


@pytest.mark.asyncio
async def test_execute_virtual_tool_stdio_call_uses_simple_command(monkeypatch, db_path):
    proxy = McpProxy(db_path)
    virtual_tool = {
        "name": "virt_stdio",
        "approval_state": "approved",
        "mcp_server_id": 7,
        "execution_type": "stdio_call",
        "config": {
            "command": "python",
            "command_args": ["script.py"],
            "working_dir": "/tmp/tool",
            "env_vars": {"MODE": "test"},
        },
    }
    source_server = {"id": 7, "name": "srv", "approval_state": "approved", "timeout": 9}

    monkeypatch.setattr(
        "authmcp_gateway.mcp.proxy.get_mcp_server", lambda *_args, **_kwargs: source_server
    )

    captured = {}

    async def fake_run_virtual_process_command(command_config, *, stdin_text, timeout):
        captured["command_config"] = command_config
        captured["stdin_text"] = stdin_text
        captured["timeout"] = timeout
        return {"returncode": 0, "stdout": json.dumps({"ok": True}), "stderr": ""}

    monkeypatch.setattr(proxy, "_run_virtual_process_command", fake_run_virtual_process_command)

    result = await proxy._execute_virtual_tool(virtual_tool, {"query": "hello"}, None, None)

    assert captured["command_config"]["command"] == "python"
    assert captured["command_config"]["command_args"] == ["script.py"]
    assert captured["stdin_text"] == json.dumps({"query": "hello"}, ensure_ascii=False)
    assert captured["timeout"] == 9
    assert result["result"]["isError"] is False
    assert result["result"]["_meta"]["execution_type"] == "stdio_call"


@pytest.mark.asyncio
async def test_execute_virtual_tool_stdio_call_resolves_args_env_and_stdin(monkeypatch, db_path):
    proxy = McpProxy(db_path)
    virtual_tool = {
        "name": "virt_stdio_template",
        "approval_state": "approved",
        "mcp_server_id": 7,
        "execution_type": "stdio_call",
        "config": {
            "command": "node",
            "command_args": ["cli.js", "--token", "{{arguments.token}}", "{{arguments.position}}"],
            "working_dir": "/tmp/tool",
            "env_vars": {"AUTH_TOKEN": "{{arguments.token}}"},
            "stdin": {"mode": "template", "template": {"query": "{{arguments.query}}"}},
        },
    }
    source_server = {"id": 7, "name": "srv", "approval_state": "approved", "timeout": 9}

    monkeypatch.setattr(
        "authmcp_gateway.mcp.proxy.get_mcp_server", lambda *_args, **_kwargs: source_server
    )

    captured = {}

    async def fake_run_virtual_process_command(command_config, *, stdin_text, timeout):
        captured["command_config"] = command_config
        captured["stdin_text"] = stdin_text
        captured["timeout"] = timeout
        return {"returncode": 0, "stdout": json.dumps({"ok": True}), "stderr": ""}

    monkeypatch.setattr(proxy, "_run_virtual_process_command", fake_run_virtual_process_command)

    await proxy._execute_virtual_tool(
        virtual_tool,
        {"token": "abc123", "position": "first", "query": "hello"},
        None,
        None,
    )

    assert captured["command_config"]["command_args"] == ["cli.js", "--token", "abc123", "first"]
    assert captured["command_config"]["env_vars"] == {"AUTH_TOKEN": "abc123"}
    assert captured["stdin_text"] == json.dumps({"query": "hello"}, ensure_ascii=False)
    assert captured["timeout"] == 9


@pytest.mark.asyncio
async def test_execute_virtual_tool_rejects_missing_template_values(monkeypatch, db_path):
    proxy = McpProxy(db_path)
    virtual_tool = {
        "name": "virt_missing",
        "approval_state": "approved",
        "mcp_server_id": 7,
        "execution_type": "stdio_call",
        "config": {
            "command": "python",
            "command_args": ["script.py", "{{arguments.token}}"],
        },
    }
    source_server = {"id": 7, "name": "srv", "approval_state": "approved", "timeout": 9}

    monkeypatch.setattr(
        "authmcp_gateway.mcp.proxy.get_mcp_server", lambda *_args, **_kwargs: source_server
    )

    with pytest.raises(ValueError, match="Template references missing value"):
        await proxy._execute_virtual_tool(virtual_tool, {"query": "hello"}, None, None)


@pytest.mark.asyncio
async def test_execute_virtual_tool_pipeline_call_chains_step_outputs(monkeypatch, db_path):
    proxy = McpProxy(db_path)
    virtual_tool = {
        "name": "virt_pipeline",
        "approval_state": "approved",
        "mcp_server_id": 7,
        "execution_type": "pipeline_call",
        "config": {
            "steps": [
                {"command": "python", "command_args": ["first.py"]},
                {"command": "jq", "command_args": [".result"]},
            ],
            "working_dir": "/tmp/pipeline",
            "env_vars": {"MODE": "test"},
        },
    }
    source_server = {"id": 7, "name": "srv", "approval_state": "approved", "timeout": 5}

    monkeypatch.setattr(
        "authmcp_gateway.mcp.proxy.get_mcp_server", lambda *_args, **_kwargs: source_server
    )

    calls = []

    async def fake_run_virtual_process_command(command_config, *, stdin_text, timeout):
        calls.append((command_config, stdin_text, timeout))
        if len(calls) == 1:
            return {"returncode": 0, "stdout": '{"result":"step-one"}', "stderr": ""}
        return {"returncode": 0, "stdout": '"step-one"', "stderr": ""}

    monkeypatch.setattr(proxy, "_run_virtual_process_command", fake_run_virtual_process_command)

    result = await proxy._execute_virtual_tool(virtual_tool, {"query": "hello"}, None, None)

    assert len(calls) == 2
    assert calls[0][0]["working_dir"] == "/tmp/pipeline"
    assert calls[0][0]["env_vars"] == {"MODE": "test"}
    assert calls[0][1] == json.dumps({"query": "hello"}, ensure_ascii=False)
    assert calls[1][1] == '{"result":"step-one"}'
    assert result["result"]["_meta"]["execution_type"] == "pipeline_call"
    assert result["result"]["content"][0]["text"] == "step-one"


@pytest.mark.asyncio
async def test_run_virtual_process_command_truncates_oversized_stdout(monkeypatch, db_path):
    proxy = McpProxy(db_path)
    monkeypatch.setattr(proxy_module, "VIRTUAL_TOOL_MAX_OUTPUT_BYTES", 10)

    result = await proxy._run_virtual_process_command(
        {
            "command": sys.executable,
            "command_args": ["-c", "print('x' * 1000)"],
        },
        stdin_text="",
        timeout=5,
    )

    assert result["truncated"] is True
    assert len(result["stdout"]) <= 10


def test_build_virtual_process_response_notes_truncation(db_path):
    proxy = McpProxy(db_path)

    response = proxy._build_virtual_process_response(
        virtual_tool={"name": "virt_stdio"},
        execution_type="stdio_call",
        result={"returncode": 0, "stdout": "partial-out", "stderr": "", "truncated": True},
    )

    assert "[output truncated at 256KB]" in response["result"]["content"][0]["text"]
