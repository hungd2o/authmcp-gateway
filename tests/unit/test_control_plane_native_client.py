"""Isolation and lifecycle tests for the dedicated native management session."""

import pytest

from authmcp_gateway.mcp.control_plane_contract import (
    CONTROL_PLANE_EXTENSION,
    CONTROL_PLANE_PROTOCOL_VERSION,
)
from authmcp_gateway.mcp.control_plane_native_client import (
    ManagementUnavailableError,
    NativeManagementClient,
)


class _Transport:
    def __init__(self, *_args, **_kwargs): pass


class _Worker:
    instances = []

    def __init__(self, _transport):
        self.state = None
        self.payloads, self.notifications, self.closed = [], [], False
        type(self).instances.append(self)

    async def start(self): pass

    async def send_payload(self, payload, _timeout):
        self.payloads.append(payload)
        if payload["method"] == "initialize":
            return {"result": {"protocolVersion": CONTROL_PLANE_PROTOCOL_VERSION,
                    "capabilities": {"extensions": {CONTROL_PLANE_EXTENSION: {}}}}}
        return {"result": {"ok": True}}

    async def send_notification(self, method, params): self.notifications.append((method, params))

    async def close(self): self.closed = True


@pytest.mark.asyncio
async def test_native_client_uses_one_isolated_worker_and_initialized_notification(monkeypatch):
    monkeypatch.setattr("authmcp_gateway.mcp.control_plane_native_client.StdioTransport", _Transport)
    monkeypatch.setattr("authmcp_gateway.mcp.control_plane_native_client.ManagedStdioWorker", _Worker)
    _Worker.instances = []
    client = NativeManagementClient(boot_id="boot-a")
    server = {"id": 8, "transport_type": "stdio", "command": "ignored", "command_args": []}

    await client.request(server, "fingerprint:2", f"{CONTROL_PLANE_EXTENSION}/status/get", {})
    await client.request(server, "fingerprint:2", f"{CONTROL_PLANE_EXTENSION}/status/get", {})

    assert len(_Worker.instances) == 1
    worker = _Worker.instances[0]
    assert worker.payloads[0]["method"] == "initialize"
    assert worker.payloads[0]["params"]["capabilities"] == {"extensions": {CONTROL_PLANE_EXTENSION: {}}}
    assert worker.notifications == [("notifications/initialized", {})]
    metadata = client.session_metadata(8, "fingerprint:2")
    assert metadata["boot_id"] == "boot-a" and metadata["session_epoch"]

    await client.invalidate(8)
    assert worker.closed and client.session_metadata(8, "fingerprint:2") is None


@pytest.mark.asyncio
async def test_native_client_checks_eligibility_inside_its_server_lock(monkeypatch):
    monkeypatch.setattr("authmcp_gateway.mcp.control_plane_native_client.StdioTransport", _Transport)
    monkeypatch.setattr("authmcp_gateway.mcp.control_plane_native_client.ManagedStdioWorker", _Worker)
    client = NativeManagementClient()
    server = {"id": 9, "transport_type": "stdio", "command": "ignored", "command_args": []}

    def reject():
        raise ManagementUnavailableError("revoked")

    with pytest.raises(ManagementUnavailableError, match="revoked"):
        await client.request(server, "fingerprint:3", "status", {}, eligible=reject)
    assert client.session_metadata(9, "fingerprint:3") is None
