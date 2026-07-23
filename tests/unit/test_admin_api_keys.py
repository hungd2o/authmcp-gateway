"""Tests for admin-managed API key creation and lifecycle."""

import json
from datetime import date, timedelta
from pathlib import Path

from starlette.testclient import TestClient

from authmcp_gateway.app import create_app
from authmcp_gateway.auth.password import hash_password
from authmcp_gateway.auth.user_store import create_user
from authmcp_gateway.config import (
    AppConfig,
    AuthConfig,
    JWTConfig,
    RateLimitConfig,
    WhitelistAuthConfig,
)


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
        whitelist_auth=WhitelistAuthConfig(
            credential_encryption_key="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
        ),
    )
    return TestClient(create_app(config))


def _mcp_initialize(token: str) -> dict:
    return {
        "headers": {"Authorization": "Bearer " + token},
        "json": {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    }


def _admin_csrf_headers(client: TestClient) -> dict:
    response = client.get("/admin/api-keys")
    assert response.status_code == 200
    csrf = client.cookies.get("csrf_token")
    assert csrf
    return {"X-CSRF-Token": csrf}


def _date_window(days: int = 30) -> dict:
    start = date.today()
    end = start + timedelta(days=days)
    return {"date_from": start.isoformat(), "date_to": end.isoformat(), "no_expire": False}


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


def test_admin_can_create_api_key_and_use_it(db_path):
    with _create_test_client(db_path) as client:
        _login_admin(client, db_path)

        created = client.post(
            "/admin/api/api-keys",
            json={"name": "CI Deploy", **_date_window(30)},
            headers=_admin_csrf_headers(client),
        )
        assert created.status_code == 201
        body = created.json()
        assert body["name"] == "CI Deploy"
        assert body["lifetime_minutes"] == 60 * 24 * 30
        assert body["access_token"]

        listed = client.get("/admin/api/api-keys")
        assert listed.status_code == 200
        data = listed.json()
        assert data["current_user_id"] > 0
        assert len(data["tokens"]) == 1
        token = data["tokens"][0]
        assert token["token_name"] == "CI Deploy"
        assert token["name"] == "CI Deploy"
        assert token["username"] == "admin"
        assert token["revoked_at"] is None
        assert token["can_view_token"] is True
        assert "access_token" not in token

        secret = client.get(f"/admin/api/api-keys/{body['id']}/secret")
        assert secret.status_code == 200
        assert secret.json()["access_token"] == body["access_token"]

        mcp = client.post("/mcp", **_mcp_initialize(body["access_token"]))
        assert mcp.status_code == 200


def test_admin_api_key_create_validates_name_and_dates(db_path):
    with _create_test_client(db_path) as client:
        _login_admin(client, db_path)
        headers = _admin_csrf_headers(client)

        short_name = client.post(
            "/admin/api/api-keys",
            json={"name": "ab", **_date_window(30)},
            headers=headers,
        )
        assert short_name.status_code == 400
        assert short_name.json()["detail"] == "Token name must be between 3 and 64 characters"

        invalid_dates = client.post(
            "/admin/api/api-keys",
            json={
                "name": "Deploy Bot",
                "date_from": date.today().isoformat(),
                "date_to": date.today().isoformat(),
                "no_expire": False,
            },
            headers=headers,
        )
        assert invalid_dates.status_code == 400
        assert invalid_dates.json()["detail"] == "Date to must be at least 1 day after date from"


def test_admin_can_revoke_created_api_key(db_path):
    with _create_test_client(db_path) as client:
        _login_admin(client, db_path)
        headers = _admin_csrf_headers(client)

        created = client.post(
            "/admin/api/api-keys",
            json={"name": "Release Bot", "no_expire": True},
            headers=headers,
        )
        assert created.status_code == 201
        created_body = created.json()
        assert created_body["no_expire"] is True

        assert (
            client.post("/mcp", **_mcp_initialize(created_body["access_token"])).status_code == 200
        )

        revoked = client.post(
            f"/admin/api/api-keys/{created_body['id']}/revoke",
            headers=headers,
        )
        assert revoked.status_code == 200

        listed = client.get("/admin/api/api-keys")
        assert listed.status_code == 200
        tokens = listed.json()["tokens"]
        assert len(tokens) == 1
        assert tokens[0]["revoked_at"] is not None

        assert (
            client.post("/mcp", **_mcp_initialize(created_body["access_token"])).status_code == 401
        )
