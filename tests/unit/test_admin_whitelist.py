"""Tests for admin whitelist unlock flow."""

import json
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
from authmcp_gateway.mcp import store


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
        whitelist_token="whitelist-secret",
        whitelist_auth=WhitelistAuthConfig(
            webauthn_rp_ids=["localhost"],
            webauthn_allowed_origins=["http://localhost:8000"],
            credential_encryption_key="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=",
        ),
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


def test_admin_whitelist_page_uses_admin_route_without_embedding_token(db_path):
    with _create_test_client(db_path) as client:
        _login_admin(client, db_path)

        response = client.get("/admin/whitelist")
        assert response.status_code == 200
        assert "legacy whitelist token" in response.text.lower()
        assert "Verify with passkey" in response.text
        assert "Review approval" in response.text
        assert "Verify with passkey and approve" in response.text
        assert "Configuration fingerprint" in response.text
        assert "whitelist-secret" not in response.text
        assert "/admin/api/whitelist/items" in response.text

        legacy = client.get("/whitelist-secret/whitelist")
        assert legacy.status_code == 404


def test_whitelist_api_requires_verified_session_and_approves_http_server(db_path):
    store.init_mcp_database(db_path)
    server_id = store.create_mcp_server(
        db_path=db_path,
        name="pending-server",
        transport_type="http",
        url="https://example.invalid/mcp",
    )

    with _create_test_client(db_path) as client:
        _login_admin(client, db_path)

        missing = client.get("/admin/api/whitelist/items")
        assert missing.status_code == 401

        unlocked = client.post(
            "/admin/api/whitelist/unlock/legacy",
            json={"token": "whitelist-secret"},
            headers=_admin_csrf_headers(client),
        )
        assert unlocked.status_code == 200

        pending = client.get("/admin/api/whitelist/items")
        assert pending.status_code == 200
        server = pending.json()["servers"][0]
        assert server["id"] == server_id

        approved = client.post(
            f"/admin/api/whitelist/servers/{server_id}",
            json={"action": "approve", "config_fingerprint": server["config_fingerprint"]},
            headers=_admin_csrf_headers(client),
        )
        assert approved.status_code == 200

    server = store.get_mcp_server(db_path, server_id)
    assert server["approval_state"] == "approved"
