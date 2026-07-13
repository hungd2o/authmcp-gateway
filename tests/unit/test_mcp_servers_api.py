"""Tests for MCP server API payload normalization."""

import json
from pathlib import Path

import pytest
from starlette.requests import Request
from starlette.testclient import TestClient

from authmcp_gateway.app import create_app
from authmcp_gateway.admin import mcp_servers_api
from authmcp_gateway.admin.mcp_servers_api import _normalize_transport_payload
from authmcp_gateway.auth.password import hash_password
from authmcp_gateway.auth.user_store import create_user
from authmcp_gateway.config import AppConfig, AuthConfig, JWTConfig, RateLimitConfig
from authmcp_gateway.mcp import store


def _create_test_client(db_path: str) -> TestClient:
    settings_path = Path(db_path).parent / "auth_settings.json"
    settings_path.write_text(
        json.dumps({"system": {"allow_registration": False, "allow_dcr": False, "auth_required": True}})
    )

    config = AppConfig(
        jwt=JWTConfig(
            algorithm="HS256",
            secret_key="test-secret-key-at-least-32-characters-long-for-hmac",
            enforce_single_session=True,
        ),
        auth=AuthConfig(sqlite_path=db_path, allow_registration=False, allow_dcr=False),
        rate_limit=RateLimitConfig(enabled=False),
        mcp_public_url="http://localhost:8000",
        auth_required=True,
        whitelist_token="whitelist-secret",
    )
    return TestClient(create_app(config))


def _login_admin(client: TestClient, db_path: str) -> None:
    create_user(
        db_path=db_path,
        username="admin",
        email="admin@example.com",
        password_hash=hash_password("Password123!"),
        is_superuser=True,
    )
    login = client.post("/admin/api/login", json={"username": "admin", "password": "Password123!"})
    assert login.status_code == 200


def _admin_csrf_headers(client: TestClient) -> dict:
    response = client.get("/admin/whitelist")
    assert response.status_code == 200
    csrf = client.cookies.get("csrf_token")
    assert csrf
    return {"X-CSRF-Token": csrf}


def _base_payload(command_args=None, **overrides):
    payload = {
        "name": "demo",
        "transport_type": "stdio",
        "command": "npx",
        "command_args": command_args,
    }
    payload.update(overrides)
    return payload


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

    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/admin/api/mcp-servers/1/test",
        "headers": [],
        "query_string": b"",
        "path_params": {"server_id": "1"},
    }
    request = Request(scope, _receive)
    monkeypatch.setattr(mcp_servers_api, "get_config", lambda _req: DummyConfig())
    monkeypatch.setattr(
        "authmcp_gateway.mcp.store.get_mcp_server",
        lambda _db, _sid: {"id": 1, "approval_state": "pending", "blocked_reason": "pending"},
    )
    response = await mcp_servers_api.api_test_mcp_server(request)
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_tools_api_returns_metadata_payload(monkeypatch):
    class DummyAuth:
        sqlite_path = "/tmp/unused.db"

    class DummyConfig:
        auth = DummyAuth()

    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/admin/api/mcp-servers/2/tools",
        "headers": [],
        "query_string": b"",
        "path_params": {"server_id": "2"},
    }
    request = Request(scope, _receive)
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

    class FakeProxy:
        def __init__(self, *_args, **_kwargs):
            pass

        async def _fetch_tools_from_server(self, _server):
            return [{"name": "native", "description": "n", "inputSchema": {"type": "object"}}]

    monkeypatch.setattr("authmcp_gateway.mcp.proxy.McpProxy", FakeProxy)
    response = await mcp_servers_api.api_get_mcp_server_tools(request)
    assert response.status_code == 200
    payload = json.loads(response.body.decode("utf-8"))
    assert len(payload["tools"]) == 2
    assert {tool["tool_type"] for tool in payload["tools"]} == {"native", "virtual"}


def test_admin_whitelist_page_uses_admin_route_without_embedding_token(db_path):
    with _create_test_client(db_path) as client:
        _login_admin(client, db_path)

        response = client.get("/admin/whitelist")
        assert response.status_code == 200
        assert "Whitelist token" in response.text
        assert "whitelist-secret" not in response.text
        assert "/admin/api/whitelist/pending" in response.text

        legacy = client.get("/whitelist-secret/whitelist")
        assert legacy.status_code == 404


def test_whitelist_api_requires_header_token_and_approves_pending_server(db_path):
    store.init_mcp_database(db_path)
    server_id = store.create_mcp_server(
        db_path=db_path,
        name="pending-server",
        url="",
        transport_type="stdio",
        command="python",
    )

    with _create_test_client(db_path) as client:
        _login_admin(client, db_path)

        missing = client.get("/admin/api/whitelist/pending")
        assert missing.status_code == 401

        pending = client.get(
            "/admin/api/whitelist/pending", headers={"X-Whitelist-Token": "whitelist-secret"}
        )
        assert pending.status_code == 200
        assert pending.json()["servers"][0]["id"] == server_id

        approved = client.post(
            f"/admin/api/whitelist/servers/{server_id}",
            json={"action": "approve"},
            headers={
                "X-Whitelist-Token": "whitelist-secret",
                **_admin_csrf_headers(client),
            },
        )
        assert approved.status_code == 200

    server = store.get_mcp_server(db_path, server_id)
    assert server["approval_state"] == "approved"
