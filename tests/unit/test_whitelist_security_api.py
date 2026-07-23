"""Focused API tests for Whitelist passkey and TOTP security endpoints."""

import json
from pathlib import Path

from cryptography.fernet import Fernet
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


def _client(db_path: str, *, client_address: tuple[str, int] = ("127.0.0.1", 50000)) -> TestClient:
    Path(db_path).parent.joinpath("auth_settings.json").write_text(
        json.dumps({"system": {"auth_required": True}})
    )
    config = AppConfig(
        jwt=JWTConfig(
            algorithm="HS256", secret_key="test-secret-key-at-least-32-characters-long-for-hmac"
        ),
        auth=AuthConfig(sqlite_path=db_path),
        rate_limit=RateLimitConfig(enabled=False),
        mcp_public_url="http://localhost",
        whitelist_token="legacy-token",
        whitelist_auth=WhitelistAuthConfig(
            webauthn_rp_ids=["localhost"],
            webauthn_allowed_origins=["http://localhost"],
            credential_encryption_key=Fernet.generate_key().decode("ascii"),
        ),
    )
    return TestClient(create_app(config), base_url="http://localhost", client=client_address)


def _login(client: TestClient, db_path: str) -> dict[str, str]:
    create_user(
        db_path=db_path,
        username="admin",
        email="admin@example.test",
        password_hash=hash_password("Password123!"),
        is_superuser=True,
    )
    assert (
        client.post(
            "/admin/api/login", json={"username": "admin", "password": "Password123!"}
        ).status_code
        == 200
    )
    assert client.get("/admin/whitelist").status_code == 200
    return {"X-CSRF-Token": str(client.cookies.get("csrf_token")), "Origin": "http://localhost"}


def test_legacy_session_cannot_register_a_passkey(db_path):
    with _client(db_path) as client:
        headers = _login(client, db_path)
        assert (
            client.post(
                "/admin/api/whitelist/passkeys/register/options", headers=headers
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/admin/api/whitelist/unlock/legacy",
                json={"token": "legacy-token"},
                headers=headers,
            ).status_code
            == 200
        )
        response = client.post("/admin/api/whitelist/passkeys/register/options", headers=headers)
        assert response.status_code == 403
        assert "fresh assertion" in response.json()["error"]
        bad_origin = client.post(
            "/admin/api/whitelist/passkeys/register/options",
            headers={**headers, "Origin": "http://attacker.test"},
        )
        assert bad_origin.status_code == 403


def test_passkey_read_endpoints_do_not_require_origin_on_same_origin_get(db_path):
    with _client(db_path) as client:
        headers = _login(client, db_path)
        assert (
            client.post(
                "/admin/api/whitelist/unlock/legacy",
                json={"token": "legacy-token"},
                headers=headers,
            ).status_code
            == 200
        )

        # Same-origin browser GET requests commonly omit Origin. They only read
        # the current RP's metadata and must not weaken POST WebAuthn validation.
        read_headers = {"X-CSRF-Token": headers["X-CSRF-Token"]}
        status = client.get("/admin/api/whitelist/security-methods/status", headers=read_headers)
        passkeys = client.get("/admin/api/whitelist/passkeys", headers=read_headers)

        assert status.status_code == 200
        assert status.json()["passkey_supported"] is True
        assert status.json()["current_rp_id"] == "localhost"
        assert passkeys.status_code == 200
        assert passkeys.json()["current_rp_id"] == "localhost"


def test_totp_setup_confirmation_and_removal_guard(db_path):
    with _client(db_path) as client:
        headers = _login(client, db_path)
        assert (
            client.post(
                "/admin/api/whitelist/unlock/legacy",
                json={"token": "legacy-token"},
                headers=headers,
            ).status_code
            == 200
        )
        setup = client.post("/admin/api/whitelist/totp/setup", headers=headers)
        assert setup.status_code == 200 and setup.json()["secret"]
        from authmcp_gateway.auth.totp import totp_at
        import time

        code = totp_at(setup.json()["secret"], int(time.time() // 30))
        assert (
            client.post(
                "/admin/api/whitelist/totp/confirm", json={"code": code}, headers=headers
            ).status_code
            == 200
        )
        assert client.get("/admin/api/whitelist/totp", headers=headers).status_code == 401
        assert (
            client.post(
                "/admin/api/whitelist/unlock/legacy",
                json={"token": "legacy-token"},
                headers=headers,
            ).status_code
            == 403
        )


def test_recovery_grant_is_restricted_to_security_recovery_routes(db_path):
    from authmcp_gateway.auth.whitelist_recovery import create_recovery_code

    with _client(db_path) as client:
        create_user(
            db_path=db_path,
            username="recovery-admin",
            email="recovery-admin@example.test",
            password_hash=hash_password("Password123!"),
            is_superuser=True,
        )
        with __import__("sqlite3").connect(db_path) as connection:
            user_id = connection.execute(
                "SELECT id FROM users WHERE username = ?", ("recovery-admin",)
            ).fetchone()[0]
        code = create_recovery_code(db_path, user_id)

        assert client.get("/whitelist/recover").status_code == 200
        csrf = client.cookies.get("csrf_token")
        claimed = client.post(
            "/whitelist/recovery/claim", json={"code": code}, headers={"X-CSRF-Token": csrf}
        )
        assert claimed.status_code == 200
        assert (
            client.post(
                "/whitelist/recovery/passkeys/register/options",
                headers={"X-CSRF-Token": csrf, "Origin": "http://localhost"},
            ).status_code
            == 200
        )
        assert (
            client.post(
                "/whitelist/recovery/totp/reset", headers={"X-CSRF-Token": csrf}
            ).status_code
            == 200
        )
        assert client.get("/admin/api/whitelist/items").status_code == 401
        assert (
            client.post(
                "/admin/api/mcp-servers/1/process/start", headers={"X-CSRF-Token": csrf}
            ).status_code
            == 401
        )


def test_recovery_page_rejects_non_loopback_clients(db_path):
    with _client(db_path, client_address=("203.0.113.9", 50000)) as client:
        response = client.get("/whitelist/recover")

    assert response.status_code == 403
    assert "Recovery is local-only" in response.text
    assert response.headers["cache-control"].startswith("no-store")
