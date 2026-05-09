"""Regression tests for single-session behavior in /auth endpoints."""

import json
from pathlib import Path

from starlette.testclient import TestClient

from authmcp_gateway.app import create_app
from authmcp_gateway.auth import endpoints as auth_endpoints
from authmcp_gateway.auth.jwt_handler import decode_token_unsafe
from authmcp_gateway.auth.oauth_code_flow import generate_authorization_code
from authmcp_gateway.auth.password import hash_password
from authmcp_gateway.auth.user_store import create_user, get_current_user_token_jti
from authmcp_gateway.config import AppConfig, AuthConfig, JWTConfig, RateLimitConfig


def _create_test_client(db_path: str, *, allow_dcr: bool = False) -> TestClient:
    settings_path = Path(db_path).parent / "auth_settings.json"
    settings_path.write_text(
        json.dumps(
            {
                "system": {
                    "allow_registration": False,
                    "allow_dcr": allow_dcr,
                    "auth_required": True,
                }
            }
        )
    )

    config = AppConfig(
        jwt=JWTConfig(
            algorithm="HS256",
            secret_key="test-secret-key-at-least-32-characters-long-for-hmac",
            enforce_single_session=True,
        ),
        auth=AuthConfig(
            sqlite_path=db_path,
            allow_registration=False,
            allow_dcr=allow_dcr,
        ),
        rate_limit=RateLimitConfig(enabled=False),
        mcp_public_url="http://localhost:8000",
        auth_required=True,
    )
    app = create_app(config)
    return TestClient(app)


def _mcp_initialize(token: str) -> dict:
    return {
        "headers": {"Authorization": f"Bearer {token}"},
        "json": {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    }


def test_auth_login_updates_current_jti_and_invalidates_previous_token(db_path):
    """Second /auth/login should rotate current JTI used by MCP middleware."""
    with _create_test_client(db_path) as client:
        create_user(
            db_path=db_path,
            username="alice",
            email="alice@example.com",
            password_hash=hash_password("Password123!"),
            is_superuser=False,
        )

        first = client.post(
            "/auth/login",
            json={"username": "alice", "password": "Password123!"},
        )
        second = client.post(
            "/auth/login",
            json={"username": "alice", "password": "Password123!"},
        )

        assert first.status_code == 200
        assert second.status_code == 200

        token1 = first.json()["access_token"]
        token2 = second.json()["access_token"]
        jti2 = decode_token_unsafe(token2)["jti"]

        assert get_current_user_token_jti(db_path, 1) == jti2
        assert client.post("/mcp", **_mcp_initialize(token1)).status_code == 401
        assert client.post("/mcp", **_mcp_initialize(token2)).status_code == 200


def test_auth_refresh_updates_current_jti_and_invalidates_previous_token(db_path):
    """Refreshing should set a new current JTI and reject previous access token for MCP."""
    with _create_test_client(db_path) as client:
        create_user(
            db_path=db_path,
            username="bob",
            email="bob@example.com",
            password_hash=hash_password("Password123!"),
            is_superuser=False,
        )

        login = client.post(
            "/auth/login",
            json={"username": "bob", "password": "Password123!"},
        )
        assert login.status_code == 200

        old_access_token = login.json()["access_token"]
        refresh_token = login.json()["refresh_token"]

        refreshed = client.post("/auth/refresh", json={"refresh_token": refresh_token})
        assert refreshed.status_code == 200

        new_access_token = refreshed.json()["access_token"]
        jti2 = decode_token_unsafe(new_access_token)["jti"]

        assert get_current_user_token_jti(db_path, 1) == jti2
        assert client.post("/mcp", **_mcp_initialize(old_access_token)).status_code == 401
        assert client.post("/mcp", **_mcp_initialize(new_access_token)).status_code == 200


def test_auth_me_returns_oidc_compatible_userinfo_claims(db_path):
    with _create_test_client(db_path) as client:
        create_user(
            db_path=db_path,
            username="carol",
            email="carol@example.com",
            password_hash=hash_password("Password123!"),
            is_superuser=False,
        )

        login = client.post(
            "/auth/login",
            json={"username": "carol", "password": "Password123!"},
        )
        assert login.status_code == 200

        me = client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {login.json()['access_token']}"},
        )
        assert me.status_code == 200

        body = me.json()
        assert body["sub"] == "1"
        assert body["preferred_username"] == "carol"
        assert body["email"] == "carol@example.com"
        assert body["email_verified"] is True
        assert body["name"] == "carol"


def test_auth_login_expires_in_matches_effective_settings_ttl(db_path, monkeypatch):
    class _FakeSettings:
        def get(self, *keys, default=None):
            if keys == ("jwt", "access_token_expire_minutes"):
                return 2
            if keys == ("jwt", "refresh_token_expire_days"):
                return 7
            return default

    monkeypatch.setattr(auth_endpoints, "get_settings_manager", lambda: _FakeSettings())

    with _create_test_client(db_path) as client:
        create_user(
            db_path=db_path,
            username="carol",
            email="carol@example.com",
            password_hash=hash_password("Password123!"),
            is_superuser=False,
        )

        login = client.post(
            "/auth/login",
            json={"username": "carol", "password": "Password123!"},
        )
        assert login.status_code == 200

        payload = decode_token_unsafe(login.json()["access_token"])
        actual_ttl = int(payload["exp"]) - int(payload["iat"])

        assert login.json()["expires_in"] == 120
        assert 119 <= actual_ttl <= 121


def test_openid_configuration_advertises_supported_auth_code_metadata(db_path):
    with _create_test_client(db_path) as client:
        response = client.get("/.well-known/openid-configuration")

        assert response.status_code == 200
        body = response.json()

        assert body["issuer"] == "http://localhost:8000"
        assert body["authorization_endpoint"] == "http://localhost:8000/authorize"
        assert body["token_endpoint"] == "http://localhost:8000/oauth/token"
        assert body["response_types_supported"] == ["code"]
        assert body["grant_types_supported"] == ["authorization_code", "refresh_token"]
        assert body["token_endpoint_auth_methods_supported"] == ["none"]
        # 'plain' was removed in 1.2.32 (RFC 7636 §4.2 / OAuth 2.1 — S256 only).
        assert body["code_challenge_methods_supported"] == ["S256"]
        assert "offline_access" in body["scopes_supported"]


def test_dcr_register_omits_null_optional_fields_for_public_client(db_path):
    with _create_test_client(db_path, allow_dcr=True) as client:
        response = client.post(
            "/oauth/register",
            json={
                "redirect_uris": ["http://localhost:3000/callback"],
                "token_endpoint_auth_method": "none",
                "client_name": "Test Public Client",
            },
        )

        assert response.status_code == 201
        body = response.json()

        assert body["client_id"]
        assert body["token_endpoint_auth_method"] == "none"
        assert body["redirect_uris"] == ["http://localhost:3000/callback"]
        assert "client_secret" not in body
        assert "scope" not in body


def test_dcr_register_rejects_unknown_scope(db_path):
    """DCR client metadata with non-allowlisted scope must be rejected (S6)."""
    with _create_test_client(db_path, allow_dcr=True) as client:
        response = client.post(
            "/oauth/register",
            json={
                "redirect_uris": ["http://localhost:3000/callback"],
                "token_endpoint_auth_method": "none",
                "client_name": "Bad Scope Client",
                "scope": "openid admin:everything",
            },
        )
        assert response.status_code == 400
        body = response.json()
        assert "scope" in str(body).lower()


def test_oauth_token_auth_code_returns_scope_and_id_token_for_openid(db_path):
    import base64
    import hashlib

    with _create_test_client(db_path) as client:
        create_user(
            db_path=db_path,
            username="dave",
            email="dave@example.com",
            password_hash=hash_password("Password123!"),
            is_superuser=False,
        )
        client_id = "https://chatgpt.com"
        redirect_uri = "https://chatgpt.com/callback"
        scope = "openid profile email offline_access"
        code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        code_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )
        code = generate_authorization_code(
            db_path=db_path,
            user_id=1,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method="S256",
            scope=scope,
        )

        response = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["scope"] == scope
        assert "id_token" in body

        claims = decode_token_unsafe(body["id_token"])
        assert claims["iss"] == "http://localhost:8000"
        assert claims["aud"] == client_id
        assert claims["sub"] == "1"
        assert claims["preferred_username"] == "dave"
        assert claims["email"] == "dave@example.com"
        assert claims["email_verified"] is True


def test_oauth_authorization_server_advertises_offline_access_scope(db_path):
    with _create_test_client(db_path) as client:
        response = client.get("/.well-known/oauth-authorization-server")

        assert response.status_code == 200
        body = response.json()

        assert body["authorization_endpoint"] == "http://localhost:8000/authorize"
        assert body["token_endpoint"] == "http://localhost:8000/oauth/token"
        assert body["response_types_supported"] == ["code"]
        assert "offline_access" in body["scopes_supported"]
