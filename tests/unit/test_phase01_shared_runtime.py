import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient
from starlette.requests import Request

from authmcp_gateway.admin import mcp_servers_api
from authmcp_gateway.mcp.proxy import McpProxy


def _request(
    method: str,
    path: str,
    path_params: dict,
    runtime,
    body: bytes = b"",
    headers: list[tuple[bytes, bytes]] | None = None,
):
    async def _receive():
        return {"type": "http.request", "body": body, "more_body": False}

    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers or ([(b"content-type", b"application/json")] if body else []),
        "query_string": b"",
        "path_params": path_params,
        "app": SimpleNamespace(state=SimpleNamespace(mcp_runtime=runtime)),
    }
    return Request(scope, _receive)


def test_invalidate_cache_is_cache_only(monkeypatch):
    proxy = McpProxy("/tmp/unused.db")
    proxy._tools_cache[7] = [{"name": "tool"}]
    proxy._resources_cache[7] = [{"uri": "resource://one"}]
    proxy._prompts_cache[7] = [{"name": "prompt"}]
    proxy._capabilities_cache[7] = {"capabilities": True}
    proxy._cache_timestamp[7] = datetime.now(timezone.utc)
    proxy._session_ids[7] = "session-7"
    proxy._transports[7] = object()

    create_task_calls = []
    monkeypatch.setattr(
        "authmcp_gateway.mcp.proxy.asyncio.create_task",
        lambda *_args, **_kwargs: create_task_calls.append(True),
    )

    proxy.invalidate_cache(7)

    assert create_task_calls == []
    assert 7 not in proxy._tools_cache
    assert 7 not in proxy._resources_cache
    assert 7 not in proxy._prompts_cache
    assert 7 not in proxy._capabilities_cache
    assert 7 not in proxy._session_ids
    assert 7 not in proxy._transports


@pytest.mark.asyncio
async def test_api_delete_mcp_server_uses_shared_runtime(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    calls = []

    class FakeRuntime:
        async def remove_server(self, server_id):
            calls.append(("remove", server_id))

        async def block_and_stop_server(self, server_id):
            calls.append(("block", server_id))

    request = _request("POST", "/admin/api/mcp-servers/3", {"server_id": "3"}, FakeRuntime())
    monkeypatch.setattr(mcp_servers_api, "get_config", lambda _req: DummyConfig())
    monkeypatch.setattr("authmcp_gateway.mcp.store.delete_mcp_server", lambda *_args, **_kwargs: True)

    response = await mcp_servers_api.api_delete_mcp_server(request)

    assert response.status_code == 200
    assert calls == [("remove", 3)]


@pytest.mark.asyncio
async def test_runtime_reconciles_only_an_active_authorized_stdio_pool(monkeypatch):
    from authmcp_gateway.admin import routes

    # This module is imported before ``app`` in this test file. Reattach its
    # completed endpoint exports so the app module can build its route table.
    for name, value in vars(mcp_servers_api).items():
        if callable(value) and (name.startswith("admin_") or name.startswith("api_")):
            monkeypatch.setattr(routes, name, value, raising=False)
    from authmcp_gateway.app import McpRuntime

    class FakeProcessManager:
        def __init__(self):
            self.status = "stopped"
            self.calls = []

        async def unblock_server(self, server_id):
            self.calls.append(("unblock", server_id))

        async def block_server(self, server_id):
            self.calls.append(("block", server_id))

        async def stop_and_remove(self, server_id, *, blocked):
            self.calls.append(("remove", server_id, blocked))

        def get_status(self, _server_id):
            return self.status

    class FakeProxy:
        def __init__(self):
            self.invalidated = []

        def invalidate_cache(self, server_id):
            self.invalidated.append(server_id)

    manager = FakeProcessManager()
    proxy = FakeProxy()
    runtime = McpRuntime(proxy, manager)
    server = {
        "id": 9,
        "transport_type": "stdio",
        "enabled": True,
        "approval_state": "approved",
        "command": "python",
    }

    await runtime.reconcile_server(server)

    assert manager.calls == [("unblock", 9)]
    assert proxy.invalidated == [9]

    manager.status = "running"
    await runtime.reconcile_server(server)

    assert manager.calls == [
        ("unblock", 9),
        ("block", 9),
        ("remove", 9, True),
        ("unblock", 9),
    ]
    assert proxy.invalidated == [9, 9]


@pytest.mark.asyncio
async def test_runtime_forced_reconcile_starts_or_generation_swaps(monkeypatch):
    from authmcp_gateway.admin import routes
    for name, value in vars(mcp_servers_api).items():
        if callable(value) and (name.startswith("admin_") or name.startswith("api_")):
            monkeypatch.setattr(routes, name, value, raising=False)
    from authmcp_gateway.app import McpRuntime

    class Manager:
        def __init__(self): self.running, self.calls = False, []
        async def unblock_server(self, server_id): self.calls.append(("unblock", server_id))
        def requires_reapproval(self, _server_id): return False
        def get_status(self, _server_id): return "running" if self.running else "stopped"
        async def start_server(self, server_id, _server): self.running = True; self.calls.append(("start", server_id))
        async def reconcile(self, server_id, _server, *, force_generation_swap=False): self.calls.append(("swap", server_id, force_generation_swap))

    class Proxy:
        def invalidate_cache(self, _server_id): pass

    runtime = McpRuntime(Proxy(), Manager())
    server = {"id": 10, "transport_type": "stdio", "enabled": True, "approval_state": "approved"}
    await runtime.reconcile_server(server, force_restart=True)
    await runtime.reconcile_server(server, force_restart=True)

    assert runtime.process_manager.calls == [("unblock", 10), ("start", 10), ("unblock", 10), ("swap", 10, True)]


def test_gateway_boot_does_not_rewrite_management_runtime_state(monkeypatch, tmp_path):
    from authmcp_gateway.mcp import store

    class DummySettings:
        def get(self, *_args, default=None):
            return default

    class FakeHealthChecker:
        def start(self): return None
        async def stop(self): return None

    class FakeTokenRefresher:
        def start(self): return None
        async def stop(self): return None

    class FakeProcessManager:
        instances = []

        def __init__(self):
            self.started = []
            self.probed = []
            FakeProcessManager.instances.append(self)

        async def start_server(self, server_id, server):
            self.started.append((server_id, server["id"]))

        async def probe_tools(self, server_id, *, timeout):
            self.probed.append((server_id, timeout))
            return 3

        async def stop_all(self):
            return None

    class FakeProxy:
        instances = []

        def __init__(self, *_args, **_kwargs):
            self._session_ids = {}
            self._session_recovery_locks = {}
            FakeProxy.instances.append(self)

        def invalidate_cache(self, _server_id):
            return None

        async def close(self):
            return None

    class FakeNativeClient:
        instances = []

        def __init__(self, *_args, **_kwargs):
            FakeNativeClient.instances.append(self)

        async def close(self):
            return None

    class FakeControlPlane:
        instances = []

        def __init__(self, *_args, **_kwargs):
            self.capture_calls = []
            self.record_calls = []
            self.reconcile_callbacks = []
            FakeControlPlane.instances.append(self)

        def set_reconcile_callback(self, callback):
            self.reconcile_callbacks.append(callback)

        async def invalidate(self, _server_id):
            return None

        async def close(self):
            return None

        async def capture_runtime_revision(self, server_id):
            self.capture_calls.append(server_id)
            return "rev-before-boot"

        async def record_runtime_applied(self, server_id, revision):
            self.record_calls.append((server_id, revision))
            return True

    sqlite_path = tmp_path / "auth.db"
    store.init_mcp_database(str(sqlite_path))
    server_id = store.create_mcp_server(
        str(sqlite_path),
        name="booted-stdio",
        url="http://unused",
        transport_type="stdio",
        command="python",
    )
    store.update_server_approval(str(sqlite_path), server_id, "approved", actor="test")

    class DummyConfig:
        auth = SimpleNamespace(
            sqlite_path=str(sqlite_path),
            allowed_scopes=set(),
            password_min_length=8,
            password_require_uppercase=False,
            password_require_lowercase=False,
            password_require_digit=False,
            password_require_special=False,
            allow_registration=False,
            allow_dcr=False,
        )
        jwt = SimpleNamespace(
            secret_key="secret",
            algorithm="HS256",
            access_token_expire_minutes=30,
            refresh_token_expire_days=30,
            enforce_single_session=False,
        )
        request_timeout_seconds = 1
        static_bearer_tokens = []
        trusted_ips = []
        allowed_origins = []
        auth_required = False
        mcp_public_url = "http://example.test"
        whitelist_token = "token"
        rate_limit = SimpleNamespace(enabled=False)

    from authmcp_gateway.admin import routes

    for name, value in vars(mcp_servers_api).items():
        if callable(value) and (name.startswith("admin_") or name.startswith("api_")):
            monkeypatch.setattr(routes, name, value, raising=False)

    monkeypatch.setattr("authmcp_gateway.app.initialize_settings", lambda *_args, **_kwargs: DummySettings())
    monkeypatch.setattr("authmcp_gateway.app.initialize_health_checker", lambda **_kwargs: FakeHealthChecker())
    monkeypatch.setattr("authmcp_gateway.app.initialize_token_refresher", lambda **_kwargs: FakeTokenRefresher())
    monkeypatch.setattr("authmcp_gateway.app.initialize_token_manager", lambda **_kwargs: None)
    monkeypatch.setattr("authmcp_gateway.app.StdioProcessManager", FakeProcessManager)
    monkeypatch.setattr("authmcp_gateway.app.McpProxy", FakeProxy)
    monkeypatch.setattr("authmcp_gateway.app.NativeManagementClient", FakeNativeClient)
    monkeypatch.setattr("authmcp_gateway.app.ControlPlaneService", FakeControlPlane)
    monkeypatch.setattr("authmcp_gateway.app.ensure_whitelist_token", lambda token: (token, False))
    monkeypatch.setattr("authmcp_gateway.app.initialize_crypto", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("authmcp_gateway.app.set_middleware_config", lambda **_kwargs: None)

    from authmcp_gateway.app import create_app

    with TestClient(create_app(DummyConfig())):
        pass

    process_manager = FakeProcessManager.instances[-1]
    control_plane = FakeControlPlane.instances[-1]
    assert process_manager.started == [(server_id, server_id)]
    assert process_manager.probed and process_manager.probed[0][0] == server_id
    assert control_plane.capture_calls == []
    assert control_plane.record_calls == []


@pytest.mark.asyncio
async def test_api_update_mcp_server_blocks_disabled_server(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    calls = []

    class FakeRuntime:
        async def block_and_stop_server(self, server_id):
            calls.append(("block", server_id))

        def allow_server(self, server_id):
            calls.append(("allow", server_id))

    request = _request(
        "POST",
        "/admin/api/mcp-servers/4",
        {"server_id": "4"},
        FakeRuntime(),
        body=json.dumps({"enabled": False}).encode("utf-8"),
    )
    monkeypatch.setattr(mcp_servers_api, "get_config", lambda _req: DummyConfig())
    server_states = iter(
        [
            {
                "id": 4,
                "name": "srv",
                "approval_state": "approved",
                "enabled": True,
                "transport_type": "stdio",
                "command": "python",
                "command_args": [],
                "env_vars": {},
            },
            {
                "id": 4,
                "name": "srv",
                "approval_state": "approved",
                "enabled": False,
                "transport_type": "stdio",
            },
        ]
    )

    def fake_get_mcp_server(*_args, **_kwargs):
        return next(server_states)

    monkeypatch.setattr("authmcp_gateway.mcp.store.get_mcp_server", fake_get_mcp_server)
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.update_mcp_server",
        lambda *_args, **_kwargs: True,
    )

    response = await mcp_servers_api.api_update_mcp_server(request)

    assert response.status_code == 200
    assert calls == [("block", 4)]


@pytest.mark.asyncio
async def test_api_whitelist_reject_uses_shared_runtime(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    calls = []

    class FakeRuntime:
        async def block_and_stop_server(self, server_id):
            calls.append(("block", server_id))

        def allow_server(self, server_id):
            calls.append(("allow", server_id))

    request = _request(
        "POST",
        "/admin/api/mcp-servers/5/whitelist",
        {"server_id": "5"},
        FakeRuntime(),
        body=json.dumps({"action": "reject", "reason": "denied"}).encode("utf-8"),
        headers=[
            (b"content-type", b"application/json"),
            (b"x-whitelist-token", b"token-5"),
        ],
    )
    monkeypatch.setenv("MCP_WHITELIST_TOKEN", "token-5")
    monkeypatch.setattr(
        mcp_servers_api,
        "get_config",
        lambda _req: DummyConfig(),
    )
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.update_server_approval",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.get_mcp_server",
        lambda *_args, **_kwargs: {"id": 5, "approval_state": "rejected"},
    )

    response = await mcp_servers_api.api_whitelist_servers_action(request)

    assert response.status_code == 200
    assert calls == [("block", 5)]
