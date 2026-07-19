"""Tests for MCP server API payload normalization."""

import json
from pathlib import Path
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


def _request_with_runtime(method: str, path: str, path_params: dict, runtime, body: bytes = b""):
    async def _receive():
        return {"type": "http.request", "body": body, "more_body": False}

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


def test_management_ui_uses_only_fixed_renderers_and_cancellable_polling():
    template = Path("src/authmcp_gateway/templates/admin/mcp_servers.html").read_text(
        encoding="utf-8"
    )

    assert "Gateway-owned Management Modal" in template
    assert "AbortController" in template
    assert "manageSession" in template
    assert "showRuntimeModal" in template
    assert "runtimeWorkerLoadLabel()" in template
    assert "runtimeCapacityPolicyLabel()" in template
    assert "runtimeHealthLabel()" in template
    assert "Process state and the last backend probe are shown separately." in template
    assert "window._manageTrap = trapFocus($el)" in template
    assert "manageTrigger: null" in template
    assert "manageTriggerSelector: ''" in template
    assert "document.querySelector(`#serversList ${triggerSelector}`)" in template
    assert "isManageSessionCurrent(session, serverId)" in template
    assert "signal: signal || this.manageRequestAbort?.signal" in template
    assert "serversLoadGeneration" in template
    assert "Math.min(3, candidates.length)" in template
    assert "const renderServerCards = () =>" in template
    assert "renderServerCards();\n\n                    const availabilityByServer" in template
    assert (
        "void Promise.all(Array.from({length: Math.min(3, candidates.length)}, probeAvailability))"
        in template
    )
    assert "typed_confirmation" in template
    assert "bg-gradient-to-r from-blue-600 via-cyan-600 to-cyan-700" in template
    assert "Tool Details" in template
    assert 'data-action="advanced"' in template
    assert 'data-action="process-start"' in template
    assert 'data-action="process-stop"' in template
    assert 'data-action="process-restart"' in template
    assert 'grid-cols-1 items-start gap-4 lg:grid-cols-2" id="serversList"' in template
    assert template.count("w-full max-w-4xl") == 3
    assert "border-l-4 ${statusStyle.accent} bg-white" in template
    assert "min-h-[104px] border-b border-slate-100 bg-white" in template
    assert "detail: 'Worker process active'" in template
    assert "min-h-[88px] grid-cols-2" in template
    assert "grid-cols-1 gap-2 sm:grid-cols-3" in template
    assert "data-endpoint class=" in template
    assert "button.closest('[data-endpoint]')?.querySelector('[data-path]')" in template
    assert "server-control-cluster" in template
    assert "server-control-grid" in template
    assert "const displayStatus = transport === 'stdio' ? processStatus : status;" in template
    assert (
        "const statusLabel = displayStatus.charAt(0).toUpperCase() + displayStatus.slice(1);"
        in template
    )
    assert "${statusLabel}" in template
    assert "${transport === 'stdio' ? `<span" not in template
    assert "relative min-h-[104px] border-b border-slate-100 bg-white px-4 py-3.5 pr-40" in template
    assert "No description provided" in template
    assert "Manage unavailable" in template
    assert "openRuntime(serverId, trigger)" in template
    assert "openManage(serverId, trigger)" in template
    assert "probeManagement()" in template
    assert "loadManageEntityPage(entity" in template
    assert "const scopedKey" in template
    assert "server.management?.mode === 'adapter'" in template
    assert "Provider support has not been checked" in template
    assert "management?.available" in template
    assert "Management profile" in template
    assert "editManagementProfile" in template
    assert "data.management_profile = this.editManagementProfile" in template
    assert "this.editManagementProfile !== 'none'" in template
    assert "saveManagementProfile()" not in template
    assert "Pending whitelist approval" in template
    assert "Review in Whitelist" in template
    assert "rowManageActions(entity)" in template
    assert "runManageRowAction(action, row)" in template
    assert ':data-lucide="action.icon || defaultManageActionIcon(action)"' in template
    assert "unboundManageActions().length" in template
    assert "definition.enum" in template
    assert "x-html" not in template


def test_whitelist_displays_the_reviewed_management_profile():
    template = Path("src/authmcp_gateway/templates/admin/whitelist.html").read_text(
        encoding="utf-8"
    )
    assert "Management profile:" in template
    assert "managementProfileLabel(server)" in template
    assert "included in the fingerprint" in template


def test_endpoint_copy_looks_up_the_path_within_its_endpoint_container():
    template = Path("src/authmcp_gateway/templates/admin/mcp_servers.html").read_text(
        encoding="utf-8"
    )
    assert "button.closest('[data-endpoint]')?.querySelector('[data-path]')" in template
    assert "const fullUrl = window.location.origin + path;" in template


def test_stdio_card_uses_live_process_state_instead_of_stale_health_status():
    template = Path("src/authmcp_gateway/templates/admin/mcp_servers.html").read_text(
        encoding="utf-8"
    )
    card_renderer = template[
        template.index("createServerCard(server)") : template.index("async openToolsModal")
    ]
    assert "const displayStatus = transport === 'stdio' ? processStatus : status;" in card_renderer
    assert (
        "const totalTools = (server.tools_count || 0) + (server.virtual_tools_count || 0);"
        in card_renderer
    )
    assert (
        "const statusLabel = displayStatus.charAt(0).toUpperCase() + displayStatus.slice(1);"
        in card_renderer
    )
    assert "${statusLabel}" in card_renderer
    assert "${status.charAt(0).toUpperCase() + status.slice(1)}" not in card_renderer


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
async def test_management_profile_binding_stops_server_and_requires_reapproval(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    class FakeRuntime:
        def __init__(self):
            self.stopped = []

        async def block_and_stop_server(self, server_id):
            self.stopped.append(server_id)

    runtime = FakeRuntime()
    request = _request_with_runtime(
        "POST",
        "/admin/api/mcp-servers/1/management/profile",
        {"server_id": "1"},
        runtime=runtime,
        body=b'{"profile":"gitnexus"}',
    )
    events = []
    monkeypatch.setattr(mcp_servers_api, "get_config", lambda _req: DummyConfig())
    monkeypatch.setattr("authmcp_gateway.mcp.store.get_mcp_server", lambda _db, _sid: {"id": 1})
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.prepare_management_config",
        lambda db_path, server_id, config: events.append("prepare")
        or {**config, "manifest_hash": "reviewed"},
    )
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.persist_management_config",
        lambda db_path, server_id, config: events.append(("persist", db_path, server_id, config))
        or True,
    )

    original_stop = runtime.block_and_stop_server

    async def record_stop(server_id):
        events.append("fence")
        await original_stop(server_id)

    runtime.block_and_stop_server = record_stop

    response = await mcp_servers_api.api_update_management_profile(request)

    assert response.status_code == 200
    assert json.loads(response.body) == {
        "message": "Management profile saved; whitelist approval is required",
        "profile": "gitnexus",
        "approval_state": "pending",
    }
    assert events == [
        "prepare",
        "fence",
        (
            "persist",
            "/tmp/unused.db",
            1,
            {"mode": "adapter", "adapter": "gitnexus", "manifest_hash": "reviewed"},
        ),
    ]
    assert runtime.stopped == [1]


@pytest.mark.asyncio
async def test_management_profile_binding_rejects_unreviewed_profiles():
    request = _request_with_runtime(
        "POST",
        "/admin/api/mcp-servers/1/management/profile",
        {"server_id": "1"},
        runtime=SimpleNamespace(),
        body=b'{"profile":"arbitrary-command"}',
    )

    response = await mcp_servers_api.api_update_management_profile(request)

    assert response.status_code == 400
    assert json.loads(response.body) == {"error": "Choose a reviewed management profile"}


@pytest.mark.asyncio
async def test_server_edit_applies_reviewed_management_profile_atomically(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    class FakeRuntime:
        def __init__(self):
            self.events = []

        async def block_and_stop_server(self, server_id):
            self.events.append(("fence", server_id))

        async def reconcile_server(self, _server):
            pytest.fail("A profile change must remain fenced pending approval")

    current = {
        "id": 1,
        "name": "server",
        "url": "",
        "transport_type": "stdio",
        "command": "gpt-repo",
        "command_args": [],
        "env_vars": {},
        "enabled": True,
        "approval_state": "approved",
    }
    updated = {**current, "name": "renamed", "approval_state": "pending"}
    runtime = FakeRuntime()
    request = _request_with_runtime(
        "PATCH",
        "/admin/api/mcp-servers/1",
        {"server_id": "1"},
        runtime=runtime,
        body=b'{"name":"renamed","management_profile":"gpt-repo"}',
    )
    calls = []
    monkeypatch.setattr(mcp_servers_api, "get_config", lambda _req: DummyConfig())
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.get_mcp_server",
        lambda *_args: updated if calls else current,
    )
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.prepare_management_config",
        lambda *_args, **kwargs: {
            "mode": "adapter",
            "adapter": "gpt-repo",
            "manifest_hash": "reviewed",
        },
    )
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.update_mcp_server",
        lambda **fields: calls.append(fields) or True,
    )

    response = await mcp_servers_api.api_update_mcp_server(request)

    assert response.status_code == 200
    assert runtime.events == [("fence", 1)]
    assert calls == [
        {
            "db_path": "/tmp/unused.db",
            "server_id": 1,
            "name": "renamed",
            "management_config": {
                "mode": "adapter",
                "adapter": "gpt-repo",
                "manifest_hash": "reviewed",
            },
        }
    ]


@pytest.mark.asyncio
async def test_server_edit_refreshes_an_unchanged_profile_when_its_manifest_changes(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    class FakeRuntime:
        def __init__(self):
            self.events = []

        async def block_and_stop_server(self, server_id):
            self.events.append(("fence", server_id))

        async def reconcile_server(self, _server):
            pytest.fail("A refreshed profile must remain fenced pending approval")

    current = {
        "id": 1,
        "name": "server",
        "url": "",
        "transport_type": "stdio",
        "command": "gpt-repo",
        "command_args": [],
        "env_vars": {},
        "enabled": True,
        "approval_state": "approved",
        "management": {"mode": "adapter", "adapter": "gpt-repo", "manifest_hash": "old"},
    }
    updated = {**current, "approval_state": "pending"}
    runtime = FakeRuntime()
    request = _request_with_runtime(
        "PATCH",
        "/admin/api/mcp-servers/1",
        {"server_id": "1"},
        runtime=runtime,
        body=b'{"management_profile":"gpt-repo"}',
    )
    calls = []
    monkeypatch.setattr(mcp_servers_api, "get_config", lambda _req: DummyConfig())
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.get_mcp_server",
        lambda *_args: updated if calls else current,
    )
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.prepare_management_config",
        lambda *_args, **_kwargs: {
            "mode": "adapter",
            "adapter": "gpt-repo",
            "manifest_hash": "new",
        },
    )
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.update_mcp_server",
        lambda **fields: calls.append(fields) or True,
    )

    response = await mcp_servers_api.api_update_mcp_server(request)

    assert response.status_code == 200
    assert runtime.events == [("fence", 1)]
    assert calls == [
        {
            "db_path": "/tmp/unused.db",
            "server_id": 1,
            "management_config": {"mode": "adapter", "adapter": "gpt-repo", "manifest_hash": "new"},
        }
    ]


@pytest.mark.asyncio
async def test_server_edit_rejects_adapter_profile_for_http_before_fencing(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    current = {
        "id": 1,
        "name": "server",
        "url": "",
        "transport_type": "stdio",
        "command": "gpt-repo",
        "command_args": [],
        "env_vars": {},
        "enabled": True,
    }
    request = _request_with_runtime(
        "PATCH",
        "/admin/api/mcp-servers/1",
        {"server_id": "1"},
        runtime=SimpleNamespace(),
        body=b'{"transport_type":"http","url":"https://example.test/mcp","management_profile":"gitnexus"}',
    )
    monkeypatch.setattr(mcp_servers_api, "get_config", lambda _req: DummyConfig())
    monkeypatch.setattr("authmcp_gateway.mcp.store.get_mcp_server", lambda *_args: current)

    response = await mcp_servers_api.api_update_mcp_server(request)

    assert response.status_code == 400
    assert json.loads(response.body) == {
        "error": "control-plane management supports STDIO servers only"
    }


@pytest.mark.asyncio
async def test_server_edit_cannot_keep_an_existing_adapter_when_switching_to_http(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    current = {
        "id": 1,
        "name": "server",
        "url": "",
        "transport_type": "stdio",
        "command": "gpt-repo",
        "command_args": [],
        "env_vars": {},
        "enabled": True,
        "management": {"mode": "adapter", "adapter": "gpt-repo"},
    }
    request = _request_with_runtime(
        "PATCH",
        "/admin/api/mcp-servers/1",
        {"server_id": "1"},
        runtime=SimpleNamespace(),
        body=b'{"transport_type":"http","url":"https://example.test/mcp"}',
    )
    monkeypatch.setattr(mcp_servers_api, "get_config", lambda _req: DummyConfig())
    monkeypatch.setattr("authmcp_gateway.mcp.store.get_mcp_server", lambda *_args: current)

    response = await mcp_servers_api.api_update_mcp_server(request)

    assert response.status_code == 400
    assert json.loads(response.body) == {
        "error": "Clear the management profile before changing away from STDIO"
    }


@pytest.mark.asyncio
async def test_server_edit_noop_does_not_recompute_the_approval_fingerprint(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    current = {
        "id": 1,
        "name": "server",
        "description": "",
        "url": "",
        "transport_type": "stdio",
        "command": "gpt-repo",
        "command_args": [],
        "env_vars": {},
        "working_dir": "",
        "enabled": True,
    }
    request = _request_with_runtime(
        "PATCH",
        "/admin/api/mcp-servers/1",
        {"server_id": "1"},
        runtime=SimpleNamespace(),
        body=b'{"description":"","working_dir":null,"command_args":[],"env_vars":{}}',
    )
    monkeypatch.setattr(mcp_servers_api, "get_config", lambda _req: DummyConfig())
    monkeypatch.setattr("authmcp_gateway.mcp.store.get_mcp_server", lambda *_args: current)
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.update_mcp_server",
        lambda **_fields: pytest.fail("No-op edit must not update the server"),
    )

    response = await mcp_servers_api.api_update_mcp_server(request)

    assert response.status_code == 200
    assert json.loads(response.body) == {"message": "No server changes detected"}


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
    assert updates == [
        (("/tmp/unused.db", 1), {"status": "error", "error": "backend startup failed"})
    ]


@pytest.mark.asyncio
async def test_process_start_probes_and_records_current_health(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    class FakeManager:
        def __init__(self):
            self.running = False

        def is_blocked(self, _server_id):
            return False

        async def start_server(self, _server_id, _server):
            self.running = True

        async def probe_tools(self, server_id, *, timeout):
            assert (server_id, timeout) == (1, 60)
            return 32

        def get_status(self, _server_id):
            return "running" if self.running else "stopped"

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
async def test_process_start_marks_management_revision_active_after_success(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    class FakeManager:
        def is_blocked(self, _server_id):
            return False

        async def restart_server(self, _server_id):
            return None

        async def probe_tools(self, _server_id, *, timeout):
            assert timeout == 60
            return 32

        def get_status(self, _server_id):
            return "running"

    class FakeControlPlane:
        def __init__(self):
            self.server_ids = []

        async def invalidate(self, _server_id):
            return None

        async def capture_runtime_revision(self, _server_id):
            return "revision-before-start"

        async def record_runtime_applied(self, server_id, revision):
            self.server_ids.append((server_id, revision))
            return True

    control_plane = FakeControlPlane()
    request = _request_with_runtime(
        "POST",
        "/admin/api/mcp-servers/1/process/restart",
        {"server_id": "1", "action": "restart"},
        runtime=SimpleNamespace(
            proxy=None, process_manager=FakeManager(), control_plane=control_plane
        ),
    )
    server = {
        "id": 1,
        "transport_type": "stdio",
        "approval_state": "approved",
        "enabled": True,
        "timeout": 60,
    }
    monkeypatch.setattr(mcp_servers_api, "get_config", lambda _req: DummyConfig())
    monkeypatch.setattr("authmcp_gateway.mcp.store.get_mcp_server", lambda _db, _sid: server)
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.update_server_health", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.mark_server_online_if_active", lambda *_args: True
    )

    response = await mcp_servers_api.api_mcp_server_process_action(request)

    assert response.status_code == 200
    assert control_plane.server_ids == [(1, "revision-before-start")]
    assert "management_warning" not in json.loads(response.body)


@pytest.mark.asyncio
async def test_process_start_surfaces_management_state_persistence_failure(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    class FakeManager:
        def is_blocked(self, _server_id):
            return False

        async def restart_server(self, _server_id):
            return None

        async def probe_tools(self, _server_id, *, timeout):
            return 32

        def get_status(self, _server_id):
            return "running"

    class FakeControlPlane:
        async def invalidate(self, _server_id):
            return None

        async def capture_runtime_revision(self, _server_id):
            return "revision-before-start"

        async def record_runtime_applied(self, _server_id, _revision):
            raise OSError("disk is read-only")

    request = _request_with_runtime(
        "POST",
        "/admin/api/mcp-servers/1/process/restart",
        {"server_id": "1", "action": "restart"},
        runtime=SimpleNamespace(
            proxy=None, process_manager=FakeManager(), control_plane=FakeControlPlane()
        ),
    )
    server = {"id": 1, "transport_type": "stdio", "approval_state": "approved", "enabled": True}
    monkeypatch.setattr(mcp_servers_api, "get_config", lambda _req: DummyConfig())
    monkeypatch.setattr("authmcp_gateway.mcp.store.get_mcp_server", lambda _db, _sid: server)
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.mark_server_online_if_active", lambda *_args: True
    )

    response = await mcp_servers_api.api_mcp_server_process_action(request)

    assert response.status_code == 200
    assert json.loads(response.body)["management_warning"] == (
        "Server started, but management state could not be saved."
    )


@pytest.mark.asyncio
async def test_process_start_keeps_pending_management_changes_when_already_running(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    class FakeManager:
        def is_blocked(self, _server_id):
            return False

        def get_status(self, _server_id):
            return "running"

        async def start_server(self, _server_id, _server):
            raise AssertionError("must not restart")

    class FakeControlPlane:
        async def capture_runtime_revision(self, _server_id):
            raise AssertionError("must not snapshot")

    request = _request_with_runtime(
        "POST",
        "/admin/api/mcp-servers/1/process/start",
        {"server_id": "1", "action": "start"},
        runtime=SimpleNamespace(
            proxy=None, process_manager=FakeManager(), control_plane=FakeControlPlane()
        ),
    )
    server = {"id": 1, "transport_type": "stdio", "approval_state": "approved", "enabled": True}
    monkeypatch.setattr(mcp_servers_api, "get_config", lambda _req: DummyConfig())
    monkeypatch.setattr("authmcp_gateway.mcp.store.get_mcp_server", lambda _db, _sid: server)

    response = await mcp_servers_api.api_mcp_server_process_action(request)

    assert response.status_code == 200
    assert json.loads(response.body)["management_warning"] == (
        "Restart this server to apply pending management changes."
    )


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
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.mark_server_online_if_active", lambda *_args: False
    )
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
async def test_api_mcp_server_runtime_prefers_applied_fingerprint_when_restart_pending(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    class FakeProcessManager:
        def get_status_detail(self, _server_id):
            return {
                "aggregate": "running",
                "generation": 3,
                "pool_size": 2,
                "active": 1,
                "idle": 1,
                "queue_depth": 0,
                "min_workers": 1,
                "max_workers": 3,
                "max_queue": 8,
                "restart_count": 4,
                "workers": [
                    {"worker_id": "worker-1", "state": "ready", "pid": 4242, "uptime_secs": 91}
                ],
            }

    request = _request_with_runtime(
        "GET",
        "/admin/api/mcp-servers/1/runtime",
        {"server_id": "1"},
        runtime=SimpleNamespace(process_manager=FakeProcessManager(), proxy=None),
    )
    monkeypatch.setattr(mcp_servers_api, "get_config", lambda _req: DummyConfig())
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.get_mcp_server",
        lambda *_args, **_kwargs: {
            "id": 1,
            "transport_type": "stdio",
            "config_fingerprint": "configured-fingerprint-123456",
            "status": "online",
            "last_health_check": "2026-07-18T10:00:00+00:00",
            "tools_count": 33,
            "last_error": None,
            "management": {"mode": "adapter", "adapter": "gpt-repo"},
        },
    )
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.get_management_runtime_state",
        lambda *_args, **_kwargs: {
            "config_fingerprint": "applied-fingerprint-abcdef",
            "active_revision": "rev-live",
            "applied_at": "2026-07-18T10:05:00+00:00",
        },
    )
    monkeypatch.setattr(
        "authmcp_gateway.security.logger.get_server_request_metrics",
        lambda *_args, **_kwargs: {
            "available": True,
            "window_hours": 1,
            "requests": 20,
            "errors": 2,
            "p50_ms": 18,
            "p95_ms": 61,
            "last_timeout_at": "2026-07-18T10:06:00+00:00",
        },
    )

    response = await mcp_servers_api.api_mcp_server_runtime(request)

    assert response.status_code == 200
    payload = json.loads(response.body.decode("utf-8"))
    assert payload["process"]["restart_count"] == 4
    assert payload["configuration"]["state"] == "restart_required"
    assert payload["configuration"]["fingerprint"] == "applied-fing"
    assert payload["configuration"]["applied_fingerprint"] == "applied-fing"
    assert payload["configuration"]["configured_fingerprint"] == "configured-f"


@pytest.mark.asyncio
async def test_api_mcp_server_runtime_returns_not_managed_for_stdio_without_profile(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    class FakeProcessManager:
        def status_detail(self, _server_id):
            return {"state": "stopped", "generation": 0, "workers": {}}

    request = _request_with_runtime(
        "GET",
        "/admin/api/mcp-servers/2/runtime",
        {"server_id": "2"},
        runtime=SimpleNamespace(process_manager=FakeProcessManager(), proxy=None),
    )
    monkeypatch.setattr(mcp_servers_api, "get_config", lambda _req: DummyConfig())
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.get_mcp_server",
        lambda *_args, **_kwargs: {
            "id": 2,
            "transport_type": "stdio",
            "config_fingerprint": "local-fingerprint-123456",
            "status": "offline",
            "management": {"mode": "none"},
        },
    )
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.get_management_runtime_state",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "authmcp_gateway.security.logger.get_server_request_metrics",
        lambda *_args, **_kwargs: {"available": False, "window_hours": 1},
    )

    response = await mcp_servers_api.api_mcp_server_runtime(request)

    assert response.status_code == 200
    payload = json.loads(response.body.decode("utf-8"))
    assert payload["configuration"]["state"] == "not_managed"
    assert payload["configuration"]["fingerprint"] == "local-finger"


@pytest.mark.asyncio
async def test_runtime_snapshot_contains_only_gateway_operations_data(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    class FakeProcessManager:
        def get_status_detail(self, _server_id):
            return {
                "aggregate": "running",
                "generation": 3,
                "pool_size": 2,
                "active": 1,
                "idle": 1,
                "queue_depth": 0,
                "min_workers": 1,
                "max_workers": 3,
                "max_queue": 8,
                "restart_count": 2,
                "workers": [
                    {"worker_id": "worker-1", "state": "busy", "pid": 1234, "uptime_secs": 60}
                ],
            }

    request = _request_with_runtime(
        "GET",
        "/admin/api/mcp-servers/2/runtime",
        {"server_id": "2"},
        runtime=SimpleNamespace(process_manager=FakeProcessManager(), proxy=None),
    )
    monkeypatch.setattr(mcp_servers_api, "get_config", lambda _req: DummyConfig())
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.get_mcp_server",
        lambda *_args: {
            "id": 2,
            "transport_type": "stdio",
            "status": "online",
            "last_health_check": "2026-07-19T01:00:00+00:00",
            "tools_count": 12,
            "last_error": None,
            "config_fingerprint": "fingerprint-123456",
            "management": {"mode": "adapter"},
        },
    )
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.get_management_runtime_state",
        lambda *_args: {
            "config_fingerprint": "fingerprint-123456",
            "active_revision": "revision-7",
            "applied_at": "2026-07-19T01:00:00+00:00",
        },
    )
    monkeypatch.setattr(
        "authmcp_gateway.security.logger.get_server_request_metrics",
        lambda *_args, **_kwargs: {
            "available": True,
            "requests": 4,
            "errors": 1,
            "p50_ms": 12,
            "p95_ms": 80,
        },
    )

    response = await mcp_servers_api.api_mcp_server_runtime(request)

    assert response.status_code == 200
    payload = json.loads(response.body)
    assert payload["process"]["workers"][0]["pid"] == 1234
    assert payload["traffic"]["p95_ms"] == 80
    assert payload["configuration"]["state"] == "applied"
    assert payload["configuration"]["applied_fingerprint"] == "fingerprint-"
    assert payload["configuration"]["configured_fingerprint"] == "fingerprint-"
    assert "command" not in json.dumps(payload)


@pytest.mark.asyncio
async def test_runtime_snapshot_redacts_health_error_and_marks_prior_boot_state(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    class FakeProcessManager:
        def get_status_detail(self, _server_id):
            return {"aggregate": "running", "generation": 1, "workers": []}

    class FakeControlPlane:
        def is_runtime_revision_verified(self, _server_id):
            return False

    request = _request_with_runtime(
        "GET",
        "/admin/api/mcp-servers/2/runtime",
        {"server_id": "2"},
        runtime=SimpleNamespace(
            process_manager=FakeProcessManager(), proxy=None, control_plane=FakeControlPlane()
        ),
    )
    monkeypatch.setattr(mcp_servers_api, "get_config", lambda _req: DummyConfig())
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.get_mcp_server",
        lambda *_args: {
            "id": 2,
            "transport_type": "stdio",
            "config_fingerprint": "same-fingerprint",
            "status": "error",
            "last_error": "request failed authorization=secret E:\\private\\token.txt",
            "management": {"mode": "adapter"},
        },
    )
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.get_management_runtime_state",
        lambda *_args: {
            "config_fingerprint": "same-fingerprint",
            "active_revision": "revision-1",
            "applied_at": "2026-07-19T01:00:00+00:00",
        },
    )
    monkeypatch.setattr(
        "authmcp_gateway.security.logger.get_server_request_metrics",
        lambda *_args, **_kwargs: {"available": False, "window_hours": 1},
    )

    response = await mcp_servers_api.api_mcp_server_runtime(request)

    payload = json.loads(response.body)
    assert payload["configuration"]["state"] == "restored"
    assert "secret" not in payload["health"]["last_error"]
    assert "private" not in payload["health"]["last_error"]


def test_runtime_modal_uses_a_dedicated_operations_endpoint():
    template = Path("src/authmcp_gateway/templates/admin/mcp_servers.html").read_text(
        encoding="utf-8"
    )

    assert "Gateway-owned Runtime Modal" in template
    assert "/runtime`" in template
    assert "Process &amp; health" in template
    assert "Load &amp; traffic" in template
    assert "Applied configuration" in template
    assert "startRuntimePolling" in template


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
