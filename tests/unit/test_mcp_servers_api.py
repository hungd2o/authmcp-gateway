"""Tests for MCP server API payload normalization."""

import json
from types import SimpleNamespace

import pytest
from starlette.requests import Request

from authmcp_gateway.admin import mcp_servers_api
from authmcp_gateway.admin.mcp_servers_api import (
    _normalize_transport_payload,
    _normalize_virtual_tool_config,
)
from authmcp_gateway.mcp import store


def _base_payload(command_args=None, **overrides):
    payload = {
        "name": "demo",
        "transport_type": "stdio",
        "command": "npx",
        "command_args": command_args,
    }
    payload.update(overrides)
    return payload


def _request_with_runtime(method: str, path: str, path_params: dict, runtime):
    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": [],
        "query_string": b"",
        "path_params": path_params,
        "app": SimpleNamespace(state=SimpleNamespace(mcp_runtime=runtime)),
    }
    return Request(scope, _receive)


def test_normalize_command_args_accepts_list_input():
    payload = _normalize_transport_payload(_base_payload(["--flag", 123]))
    assert payload["command_args"] == ["--flag", "123"]


def test_normalize_command_args_accepts_json_array_string():
    payload = _normalize_transport_payload(_base_payload('["--name","my value"]'))
    assert payload["command_args"] == ["--name", "my value"]


def test_normalize_command_args_fallback_parses_shell_like_string():
    payload = _normalize_transport_payload(_base_payload('--name "my value" /tmp'))
    assert payload["command_args"] == ["--name", "my value", "/tmp"]


def test_normalize_command_args_parses_multiline_input():
    payload = _normalize_transport_payload(_base_payload("--name\nmy-value\n/tmp"))
    assert payload["command_args"] == ["--name", "my-value", "/tmp"]


def test_normalize_command_args_ignores_commented_lines_and_segments():
    payload = _normalize_transport_payload(
        _base_payload('--name "my value" # comment\n# ignore\n/tmp')
    )
    assert payload["command_args"] == ["--name", "my value", "/tmp"]


def test_normalize_command_args_accepts_json_array_with_hash_comments():
    payload = _normalize_transport_payload(
        _base_payload(
            '[\n  "--name",\n  "my value", # trailing comment\n  # "/ignored",\n  "/tmp"\n]'
        )
    )
    assert payload["command_args"] == ["--name", "my value", "/tmp"]


def test_normalize_command_args_rejects_invalid_unclosed_quote():
    with pytest.raises(ValueError, match="Invalid command_args"):
        _normalize_transport_payload(_base_payload('--name "unterminated'))


def test_normalize_env_vars_accepts_key_value_lines_and_ignores_comments():
    payload = _normalize_transport_payload(
        _base_payload(
            env_vars="NODE_ENV=production\n# comment only\nAPI_URL=https://example.com # trailing"
        )
    )
    assert payload["env_vars"] == {
        "NODE_ENV": "production",
        "API_URL": "https://example.com",
    }


def test_normalize_env_vars_preserves_hash_inside_quoted_value():
    payload = _normalize_transport_payload(
        _base_payload(env_vars='SECRET="abc # keep"\nTOKEN=value#keep')
    )
    assert payload["env_vars"] == {
        "SECRET": "abc # keep",
        "TOKEN": "value#keep",
    }


def test_normalize_env_vars_rejects_invalid_non_assignment_lines():
    with pytest.raises(ValueError, match="Invalid env_vars line"):
        _normalize_transport_payload(_base_payload(env_vars="NOT_AN_ASSIGNMENT"))


def test_normalize_virtual_tool_config_accepts_stdio_call():
    payload = _normalize_virtual_tool_config(
        "stdio_call",
        {
            "command": "python",
            "command_args": ["--flag", "{{ arguments.query }}"],
            "env_vars": "MODE=test",
            "working_dir": "/tmp/tool",
            "input_schema": {"type": "object"},
            "stdin": {"mode": "template", "template": {"query": "{{arguments.query}}"}},
            "editor_mode": "simple",
        },
    )
    assert payload["command"] == "python"
    assert payload["command_args"] == ["--flag", "{{ arguments.query }}"]
    assert payload["env_vars"] == {"MODE": "test"}
    assert payload["working_dir"] == "/tmp/tool"
    assert payload["stdin"] == {"mode": "template", "template": {"query": "{{arguments.query}}"}}
    assert payload["editor_mode"] == "simple"


def test_normalize_virtual_tool_config_accepts_http_mappings():
    payload = _normalize_virtual_tool_config(
        "http_call",
        {
            "editor_mode": "simple",
            "input_schema": {"type": "object"},
            "request": {
                "method": "GET",
                "url": "https://api.example.com/users/{{arguments.user_id}}",
                "headers": {"X-Token": "{{arguments.token}}"},
                "query": {"limit": "{{arguments.limit}}"},
            },
        },
    )
    assert payload["request"]["query"] == {"limit": "{{arguments.limit}}"}
    assert payload["request"]["headers"]["X-Token"] == "{{arguments.token}}"


def test_normalize_virtual_tool_config_rejects_invalid_templates():
    with pytest.raises(ValueError, match="Invalid template syntax"):
        _normalize_virtual_tool_config(
            "http_call",
            {
                "request": {
                    "method": "GET",
                    "url": "https://api.example.com/users/{{arguments.user_id}",
                }
            },
        )


def test_normalize_virtual_tool_config_accepts_pipeline_call():
    payload = _normalize_virtual_tool_config(
        "pipeline_call",
        {
            "steps": [
                {"command": "python", "command_args": "first.py"},
                {"command": "jq", "command_args": [".result"]},
            ],
            "env_vars": "MODE=test",
            "input_schema": {"type": "object"},
        },
    )
    assert payload["steps"][0]["command_args"] == ["first.py"]
    assert payload["steps"][1]["command_args"] == [".result"]
    assert payload["env_vars"] == {"MODE": "test"}


def test_create_server_defaults_to_pending_and_high_risk_for_stdio(db_path):
    store.init_mcp_database(db_path)
    server_id = store.create_mcp_server(
        db_path=db_path,
        name="stdio-risk",
        url="",
        transport_type="stdio",
        command="python",
    )
    server = store.get_mcp_server(db_path, server_id)
    assert server["approval_state"] == "pending"
    assert server["risk_level"] == "high"


@pytest.mark.asyncio
async def test_api_test_mcp_server_blocks_unapproved(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    request = _request_with_runtime(
        "POST",
        "/admin/api/mcp-servers/1/test",
        {"server_id": "1"},
        runtime=SimpleNamespace(proxy=None, process_manager=None),
    )
    monkeypatch.setattr(mcp_servers_api, "get_config", lambda _req: DummyConfig())
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.get_mcp_server",
        lambda _db, _sid: {"id": 1, "approval_state": "pending", "blocked_reason": "pending"},
    )
    response = await mcp_servers_api.api_test_mcp_server(request)
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_api_test_stdio_server_probes_and_replaces_stale_health(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    class FakeManager:
        async def probe_tools(self, server_id, *, timeout):
            assert (server_id, timeout) == (1, 60)
            return 32

    class FakeRuntime:
        process_manager = FakeManager()

        async def reconcile_server(self, server):
            assert server["id"] == 1

    request = _request_with_runtime(
        "POST", "/admin/api/mcp-servers/1/test", {"server_id": "1"}, runtime=FakeRuntime()
    )
    updates = []
    monkeypatch.setattr(mcp_servers_api, "get_config", lambda _req: DummyConfig())
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.get_mcp_server",
        lambda _db, _sid: {
            "id": 1,
            "transport_type": "stdio",
            "approval_state": "approved",
            "enabled": True,
            "timeout": 60,
        },
    )
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.update_server_health",
        lambda *args, **kwargs: updates.append((args, kwargs)),
    )
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.mark_server_online_if_active", lambda *_args: True
    )

    response = await mcp_servers_api.api_test_mcp_server(request)

    assert json.loads(response.body) == {"status": "online", "tools_count": 32, "error": None}
    assert updates == []


@pytest.mark.asyncio
async def test_process_start_records_its_own_failure(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    class FakeManager:
        def is_blocked(self, _server_id):
            return False

        async def start_server(self, _server_id, _server):
            raise RuntimeError("backend startup failed")

        def get_status(self, _server_id):
            return "stopped"

    request = _request_with_runtime(
        "POST",
        "/admin/api/mcp-servers/1/process/start",
        {"server_id": "1", "action": "start"},
        runtime=SimpleNamespace(proxy=None, process_manager=FakeManager()),
    )
    updates = []
    monkeypatch.setattr(mcp_servers_api, "get_config", lambda _req: DummyConfig())
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.get_mcp_server",
        lambda _db, _sid: {
            "id": 1,
            "transport_type": "stdio",
            "approval_state": "approved",
            "enabled": True,
        },
    )
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.update_server_health",
        lambda *args, **kwargs: updates.append((args, kwargs)),
    )

    response = await mcp_servers_api.api_mcp_server_process_action(request)

    assert response.status_code == 502
    assert json.loads(response.body)["error"] == "backend startup failed"
    assert updates == [(("/tmp/unused.db", 1), {"status": "error", "error": "backend startup failed"})]


@pytest.mark.asyncio
async def test_process_start_probes_and_records_current_health(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    class FakeManager:
        def is_blocked(self, _server_id):
            return False

        async def start_server(self, _server_id, _server):
            return None

        async def probe_tools(self, server_id, *, timeout):
            assert (server_id, timeout) == (1, 60)
            return 32

        def get_status(self, _server_id):
            return "running"

    request = _request_with_runtime(
        "POST",
        "/admin/api/mcp-servers/1/process/start",
        {"server_id": "1", "action": "start"},
        runtime=SimpleNamespace(proxy=None, process_manager=FakeManager()),
    )
    server = {
        "id": 1,
        "transport_type": "stdio",
        "approval_state": "approved",
        "enabled": True,
        "timeout": 60,
    }
    updates = []
    monkeypatch.setattr(mcp_servers_api, "get_config", lambda _req: DummyConfig())
    monkeypatch.setattr("authmcp_gateway.mcp.store.get_mcp_server", lambda _db, _sid: server)
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.update_server_health",
        lambda *args, **kwargs: updates.append((args, kwargs)),
    )
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.mark_server_online_if_active", lambda *_args: True
    )

    response = await mcp_servers_api.api_mcp_server_process_action(request)

    assert response.status_code == 200
    assert json.loads(response.body)["status"] == "running"
    assert updates == []


@pytest.mark.asyncio
async def test_process_start_marks_disabled_server_offline(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    class FakeManager:
        def is_blocked(self, _server_id):
            return False

        async def start_server(self, _server_id, _server):
            return None

        async def probe_tools(self, _server_id, *, timeout):
            assert timeout == 60
            return 32

        def get_status(self, _server_id):
            return "stopped"

    request = _request_with_runtime(
        "POST",
        "/admin/api/mcp-servers/1/process/start",
        {"server_id": "1", "action": "start"},
        runtime=SimpleNamespace(proxy=None, process_manager=FakeManager()),
    )
    server = {
        "id": 1,
        "transport_type": "stdio",
        "approval_state": "approved",
        "enabled": True,
        "timeout": 60,
    }
    updates = []
    monkeypatch.setattr(mcp_servers_api, "get_config", lambda _req: DummyConfig())
    monkeypatch.setattr("authmcp_gateway.mcp.store.get_mcp_server", lambda _db, _sid: server)
    monkeypatch.setattr("authmcp_gateway.mcp.store.mark_server_online_if_active", lambda *_args: False)
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.update_server_health",
        lambda *args, **kwargs: updates.append((args, kwargs)),
    )

    response = await mcp_servers_api.api_mcp_server_process_action(request)

    assert response.status_code == 409
    assert updates == [
        (("/tmp/unused.db", 1), {"status": "offline", "error": "Server is no longer active"})
    ]


@pytest.mark.asyncio
async def test_tools_api_returns_metadata_payload(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    class FakeRuntime:
        def __init__(self):
            self.proxy = self

        async def _fetch_tools_from_server(self, _server):
            return [{"name": "native", "description": "n", "inputSchema": {"type": "object"}}]

    request = _request_with_runtime(
        "GET",
        "/admin/api/mcp-servers/2/tools",
        {"server_id": "2"},
        runtime=FakeRuntime(),
    )
    monkeypatch.setattr(mcp_servers_api, "get_config", lambda _req: DummyConfig())
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.get_mcp_server",
        lambda _db, _sid: {"id": 2, "name": "srv", "approval_state": "approved"},
    )
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.list_virtual_tools",
        lambda *_args, **_kwargs: [
            {
                "name": "virt",
                "description": "v",
                "config": {"input_schema": {"type": "object"}},
                "approval_state": "approved",
                "source_server_name": "srv",
            }
        ],
    )

    monkeypatch.setattr(
        "authmcp_gateway.mcp.proxy.McpProxy",
        lambda *_args, **_kwargs: pytest.fail("McpProxy should not be constructed"),
    )
    response = await mcp_servers_api.api_get_mcp_server_tools(request)
    assert response.status_code == 200
    payload = json.loads(response.body.decode("utf-8"))
    assert len(payload["tools"]) == 2
    assert {tool["tool_type"] for tool in payload["tools"]} == {"native", "virtual"}


@pytest.mark.asyncio
async def test_api_list_mcp_servers_includes_virtual_tools_count(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    class FakeProcessManager:
        def get_status(self, server_id):
            return "running" if server_id == 1 else "stopped"

    request = _request_with_runtime(
        "GET",
        "/admin/api/mcp-servers",
        {},
        runtime=SimpleNamespace(process_manager=FakeProcessManager(), proxy=None),
    )
    monkeypatch.setattr(mcp_servers_api, "get_config", lambda _req: DummyConfig())
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.list_mcp_servers",
        lambda *_args, **_kwargs: [
            {"id": 1, "name": "srv-a", "transport_type": "http", "tools_count": 3},
            {"id": 2, "name": "srv-b", "transport_type": "http", "tools_count": 0},
        ],
    )
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.list_virtual_tools",
        lambda *_args, **_kwargs: [
            {"id": 10, "mcp_server_id": 1, "name": "vt1"},
            {"id": 11, "mcp_server_id": 1, "name": "vt2"},
        ],
    )

    response = await mcp_servers_api.api_list_mcp_servers(request)
    assert response.status_code == 200
    payload = json.loads(response.body.decode("utf-8"))
    servers_by_id = {s["id"]: s for s in payload["servers"]}
    assert servers_by_id[1]["virtual_tools_count"] == 2
    assert servers_by_id[2]["virtual_tools_count"] == 0


@pytest.mark.asyncio
async def test_api_create_virtual_tool_rejects_wrapper_execution_type(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    async def _receive():
        return {
            "type": "http.request",
            "body": json.dumps(
                {"name": "bad", "execution_type": "mcp_wrapper", "config": {}}
            ).encode("utf-8"),
            "more_body": False,
        }

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/admin/api/mcp-servers/2/virtual-tools",
        "headers": [(b"content-type", b"application/json")],
        "query_string": b"",
        "path_params": {"server_id": "2"},
    }
    request = Request(scope, _receive)
    monkeypatch.setattr(mcp_servers_api, "get_config", lambda _req: DummyConfig())
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.get_mcp_server",
        lambda _db, _sid: {"id": 2, "name": "srv", "approval_state": "approved"},
    )

    response = await mcp_servers_api.api_create_virtual_tool(request)

    assert response.status_code == 400
    payload = json.loads(response.body.decode("utf-8"))
    assert "execution_type" in payload["error"]
