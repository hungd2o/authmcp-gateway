from types import SimpleNamespace

import pytest

from authmcp_gateway.mcp import store
from authmcp_gateway.mcp.control_plane_contract import CONTROL_PLANE_EXTENSION
from authmcp_gateway.mcp.control_plane_native_client import ManagementUnavailableError
from authmcp_gateway.mcp.control_plane_service import ControlPlaneService


class _ProcessManager:
    def status_detail(self, _server_id):
        return {"generation": 3}


class _NativeClient:
    def __init__(self):
        self.calls = []

    async def request(self, server, generation, method, params, **_kwargs):
        self.calls.append((server, generation, method, params))
        return {"result": {"extension": CONTROL_PLANE_EXTENSION, "revision": "r1"}}

    async def invalidate(self, _server_id):
        return None


@pytest.mark.asyncio
async def test_native_management_uses_fixed_method_and_separate_generation(monkeypatch):
    native = _NativeClient()
    server = {
        "id": 4,
        "enabled": 1,
        "approval_state": "approved",
        "transport_type": "stdio",
        "management": {"mode": "native"},
    }
    monkeypatch.setattr("authmcp_gateway.mcp.control_plane_service.get_mcp_server", lambda *_: server)
    monkeypatch.setattr("authmcp_gateway.mcp.control_plane_service.log_management_audit", lambda *_args, **_kwargs: None)
    service = ControlPlaneService(":memory:", _ProcessManager(), native)

    response = await service.call(4, "descriptor", {})

    assert response["result"]["revision"] == "r1"
    lifecycle = native.calls[0][1]
    assert lifecycle.endswith(":3")
    assert native.calls[0][2:] == (f"{CONTROL_PLANE_EXTENSION}/descriptor", {})


@pytest.mark.asyncio
async def test_management_rejects_disabled_or_non_native_bindings(monkeypatch):
    native = _NativeClient()
    service = ControlPlaneService(":memory:", _ProcessManager(), native)
    monkeypatch.setattr(
        "authmcp_gateway.mcp.control_plane_service.get_mcp_server",
        lambda *_: {"id": 4, "enabled": 1, "approval_state": "approved", "management": {"mode": "none"}},
    )

    with pytest.raises(ManagementUnavailableError):
        await service.call(4, "status_get", {})
    assert native.calls == []


@pytest.mark.asyncio
async def test_legacy_adapter_binding_without_profile_hash_is_unavailable(monkeypatch):
    class _Adapter:
        manifest_hash = "current-profile-hash"

        def probe(self, _server):
            raise AssertionError("legacy binding must fail before probing")

    server = {
        "id": 4, "enabled": 1, "approval_state": "approved", "transport_type": "stdio",
        "management": {"mode": "adapter", "adapter": "gpt-repo"},
    }
    monkeypatch.setattr("authmcp_gateway.mcp.control_plane_service.get_mcp_server", lambda *_: server)
    monkeypatch.setattr("authmcp_gateway.mcp.control_plane_service.adapter_for", lambda *_: _Adapter())
    monkeypatch.setattr("authmcp_gateway.mcp.control_plane_service.save_management_probe", lambda *_args, **_kwargs: None)

    availability = await ControlPlaneService(":memory:", _ProcessManager(), _NativeClient()).availability(4)

    assert availability == {
        "available": False, "mode": "adapter",
        "reason": "management profile requires whitelist re-approval",
    }


@pytest.mark.asyncio
async def test_record_runtime_applied_projects_adapter_revision_as_active(monkeypatch, tmp_path):
    class _Adapter:
        manifest_hash = "current-profile-hash"
        name = "gpt-repo"
        version = "0.1.0"

        def probe(self, _server):
            return SimpleNamespace(compatible=True, package="gpt-repo-mcp", version="0.1.0", reason=None)

        def descriptor(self):
            return {"entities": [], "status_fields": [{"field": "state"}]}

        def call(self, _server, operation, _params):
            if operation == "status_get":
                return {"result": {"state": "pending_restart"}, "revision": "rev-live"}
            raise AssertionError(f"unexpected operation: {operation}")

    db_path = str(tmp_path / "mcp.db")
    store.init_mcp_database(db_path)
    server_id = store.create_mcp_server(db_path, "adapter", "http://unused")
    server = {
        "id": server_id,
        "enabled": 1,
        "approval_state": "approved",
        "transport_type": "stdio",
        "management": {
            "mode": "adapter",
            "adapter": "gpt-repo",
            "manifest_hash": "current-profile-hash",
        },
    }
    monkeypatch.setattr("authmcp_gateway.mcp.control_plane_service.get_mcp_server", lambda *_: server)
    monkeypatch.setattr("authmcp_gateway.mcp.control_plane_service.adapter_for", lambda *_: _Adapter())
    monkeypatch.setattr("authmcp_gateway.mcp.control_plane_service.save_management_probe", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("authmcp_gateway.mcp.control_plane_service.log_management_audit", lambda *_args, **_kwargs: None)

    service = ControlPlaneService(db_path, _ProcessManager(), _NativeClient())

    pending = await service.call(server_id, "status_get", {})
    assert not await service.record_runtime_applied(server_id, "revision-changed-during-start")
    assert (await service.call(server_id, "status_get", {}))["result"]["state"] == "pending_restart"
    assert await service.record_runtime_applied(server_id, "rev-live")
    assert await service.capture_runtime_revision(server_id) == "rev-live"
    assert (await service.call(server_id, "status_get", {}))["result"]["state"] == "pending_restart"
    assert await service.record_runtime_applied(server_id, "rev-live")
    active = await ControlPlaneService(db_path, _ProcessManager(), _NativeClient()).call(
        server_id, "status_get", {}
    )

    assert pending["result"]["state"] == "pending_restart"
    assert active["result"]["state"] == "active"
