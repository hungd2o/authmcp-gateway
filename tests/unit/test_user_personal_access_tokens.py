"""Tests for user-managed personal access tokens in account portal."""

import json
from pathlib import Path

from starlette.testclient import TestClient

from authmcp_gateway.app import create_app
from authmcp_gateway.auth.password import hash_password
from authmcp_gateway.auth.user_store import create_user
from authmcp_gateway.config import AppConfig, AuthConfig, JWTConfig, RateLimitConfig


def _create_test_client(db_path: str) -> TestClient:
    settings_path = Path(db_path).parent / "auth_settings.json"
    settings_path.write_text(
        json.dumps(
            {"system": {"allow_registration": False, "allow_dcr": False, "auth_required": True}}
        )
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
    )
    return TestClient(create_app(config))


def _mcp_initialize(token: str) -> dict:
    return {
        "headers": {"Authorization": "Bearer " + token},
        "json": {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    }


def _csrf_headers(client: TestClient) -> dict:
    client.get("/account")
    csrf = client.cookies.get("csrf_token")
    assert csrf
    return {"X-CSRF-Token": csrf}


def test_create_lifetime_personal_access_token_and_use_it(db_path):
    with _create_test_client(db_path) as client:
        create_user(
            db_path=db_path,
            username="alice",
            email="alice@example.com",
            password_hash=hash_password("Password123!"),
            is_superuser=False,
        )

        login = client.post("/api/login", json={"username": "alice", "password": "Password123!"})
        assert login.status_code == 200

        created = client.post(
            "/account/pats",
            json={"name": "CI Service", "lifetime": "lifetime"},
            headers=_csrf_headers(client),
        )
        assert created.status_code == 201
        body = created.json()
        assert body["name"] == "CI Service"
        assert body["lifetime_minutes"] == 60 * 24 * 365 * 10
        assert body["access_token"]

        mcp = client.post("/mcp", **_mcp_initialize(body["access_token"]))
        assert mcp.status_code == 200

        listed = client.get("/account/pats")
        assert listed.status_code == 200
        tokens = listed.json()["tokens"]
        assert len(tokens) == 1
        assert tokens[0]["name"] == "CI Service"
        assert tokens[0]["is_active"] is True


def test_rotate_and_revoke_personal_access_token_invalidates_old_tokens(db_path):
    with _create_test_client(db_path) as client:
        create_user(
            db_path=db_path,
            username="bob",
            email="bob@example.com",
            password_hash=hash_password("Password123!"),
            is_superuser=False,
        )
        login = client.post("/api/login", json={"username": "bob", "password": "Password123!"})
        assert login.status_code == 200

        created = client.post(
            "/account/pats",
            json={"name": "Deploy Bot", "lifetime": "very_long"},
            headers=_csrf_headers(client),
        )
        assert created.status_code == 201
        old_token = created.json()["access_token"]
        old_id = created.json()["id"]

        rotated = client.post(f"/account/pats/{old_id}/rotate", headers=_csrf_headers(client))
        assert rotated.status_code == 200
        new_token = rotated.json()["access_token"]
        new_id = rotated.json()["id"]
        assert new_token != old_token

        assert client.post("/mcp", **_mcp_initialize(old_token)).status_code == 401
        assert client.post("/mcp", **_mcp_initialize(new_token)).status_code == 200

        revoked = client.post(f"/account/pats/{new_id}/revoke", headers=_csrf_headers(client))
        assert revoked.status_code == 200
        assert client.post("/mcp", **_mcp_initialize(new_token)).status_code == 401
