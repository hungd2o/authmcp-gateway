"""Integration tests for auth/endpoints.py public surface.

Covers register / login / refresh / logout / me / oauth_token. Each test
builds a real Starlette `Request` (so `request.headers`, `request.scope`,
`request.app.state.config` and friends behave like in production) but
patches `request.json` / `request.form` to return fixture data — no live
ASGI server, no router, no middleware.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from urllib.parse import urlencode

import jwt as pyjwt
import pytest
from starlette.requests import Request

from authmcp_gateway.auth import endpoints as ep
from authmcp_gateway.config import AppConfig, AuthConfig, JWTConfig, RateLimitConfig

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def reset_settings():
    """Each test starts without a global SettingsManager — endpoints fall
    through to AppConfig values."""
    import authmcp_gateway.settings_manager as sm

    sm._settings_manager = None
    yield
    sm._settings_manager = None


@pytest.fixture
def config(initialized_db) -> AppConfig:
    return AppConfig(
        jwt=JWTConfig(
            algorithm="HS256",
            secret_key="test-secret-key-at-least-32-characters-long-for-hmac",
            access_token_expire_minutes=30,
            refresh_token_expire_days=7,
        ),
        auth=AuthConfig(
            sqlite_path=initialized_db,
            allow_registration=True,  # Enable for the register tests
            password_min_length=8,
            password_require_special=True,
        ),
        rate_limit=RateLimitConfig(enabled=False),
        mcp_public_url="http://localhost:8000",
    )


def _make_request(
    *,
    config: AppConfig,
    body=None,
    form=None,
    headers: dict | None = None,
    method: str = "POST",
    ip: str = "127.0.0.1",
) -> Request:
    """Build a Starlette Request with the right scope and a stubbed json/form."""
    raw_headers = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    scope = {
        "type": "http",
        "method": method,
        "headers": raw_headers,
        "client": (ip, 12345),
        "app": SimpleNamespace(state=SimpleNamespace(config=config)),
    }
    request = Request(scope)
    if body is not None:

        async def fake_json():
            return body

        request.json = fake_json  # type: ignore[assignment]
    if form is not None:

        async def fake_form():
            return form

        request.form = fake_form  # type: ignore[assignment]
    return request


# Strong default password that satisfies the default policy (uppercase,
# lowercase, digit, special, >=8 chars).
PASSWORD = "StrongP@ssw0rd!"


def _create_user_via_register(config, *, username="alice", email=None, password=PASSWORD):
    """Helper: register a user end-to-end. Returns the JSONResponse."""
    import asyncio

    body = {
        "username": username,
        "email": email or f"{username}@example.com",
        "password": password,
        "full_name": username.title(),
    }
    request = _make_request(config=config, body=body)
    return asyncio.get_event_loop().run_until_complete(ep.register(request))


# ---------------------------------------------------------------------------
# /auth/register
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_blocked_when_disabled(reset_settings, config):
    """allow_registration=False → 403."""
    config.auth.allow_registration = False
    request = _make_request(
        config=config,
        body={"username": "alice", "email": "a@x.com", "password": PASSWORD},
    )
    response = await ep.register(request)
    assert response.status_code == 403
    assert b"REGISTRATION_DISABLED" in response.body


@pytest.mark.asyncio
async def test_register_400_on_weak_password(reset_settings, config):
    request = _make_request(
        config=config,
        body={"username": "alice", "email": "a@x.com", "password": "short"},
    )
    response = await ep.register(request)
    assert response.status_code == 400
    body = json.loads(response.body)
    assert body["error_code"] in {"WEAK_PASSWORD", "VALIDATION_ERROR"}


@pytest.mark.asyncio
async def test_register_happy_path_creates_non_superuser(reset_settings, config):
    request = _make_request(
        config=config,
        body={
            "username": "alice",
            "email": "alice@example.com",
            "password": PASSWORD,
            "full_name": "Alice",
        },
    )
    response = await ep.register(request)
    assert response.status_code == 201, response.body

    body = json.loads(response.body)
    assert body["username"] == "alice"
    assert body["is_superuser"] is False  # Public registration never grants superuser
    assert body["is_active"] is True

    # Persisted as a non-superuser in DB.
    from authmcp_gateway.auth.user_store import get_user_by_username

    user = get_user_by_username(config.auth.sqlite_path, "alice")
    assert user is not None
    assert user["is_superuser"] == 0


@pytest.mark.asyncio
async def test_register_409_on_duplicate_username(reset_settings, config):
    body1 = {
        "username": "alice",
        "email": "alice@example.com",
        "password": PASSWORD,
        "full_name": "Alice",
    }
    first = await ep.register(_make_request(config=config, body=body1))
    assert first.status_code == 201

    response = await ep.register(_make_request(config=config, body=body1))
    assert response.status_code == 409
    assert b"USERNAME_EXISTS" in response.body


# ---------------------------------------------------------------------------
# /auth/login
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_invalid_credentials(reset_settings, config):
    """No such user → 401 INVALID_CREDENTIALS."""
    request = _make_request(
        config=config, body={"username": "nope", "password": "wrong-password-1!"}
    )
    response = await ep.login(request)
    assert response.status_code == 401
    assert b"INVALID_CREDENTIALS" in response.body


@pytest.mark.asyncio
async def test_login_success_returns_token_pair(reset_settings, config):
    """Registered user can log in; response carries a usable access token."""
    await ep.register(
        _make_request(
            config=config,
            body={
                "username": "alice",
                "email": "alice@example.com",
                "password": PASSWORD,
                "full_name": "Alice",
            },
        )
    )

    response = await ep.login(
        _make_request(config=config, body={"username": "alice", "password": PASSWORD})
    )
    assert response.status_code == 200, response.body
    body = json.loads(response.body)
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["refresh_token"]

    # Access token decodes against the configured JWT secret.
    payload = pyjwt.decode(body["access_token"], config.jwt.secret_key, algorithms=["HS256"])
    assert payload["username"] == "alice"
    assert payload["type"] == "access"


@pytest.mark.asyncio
async def test_login_403_when_account_disabled(reset_settings, config):
    """Disabled user → 403 ACCOUNT_DISABLED."""
    await ep.register(
        _make_request(
            config=config,
            body={
                "username": "alice",
                "email": "alice@example.com",
                "password": PASSWORD,
                "full_name": "Alice",
            },
        )
    )
    from authmcp_gateway.auth.user_store import get_user_by_username, update_user_status

    user = get_user_by_username(config.auth.sqlite_path, "alice")
    update_user_status(config.auth.sqlite_path, user["id"], False)

    response = await ep.login(
        _make_request(config=config, body={"username": "alice", "password": PASSWORD})
    )
    assert response.status_code == 403
    assert b"ACCOUNT_DISABLED" in response.body


# ---------------------------------------------------------------------------
# /auth/refresh
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_invalid_token_returns_401(reset_settings, config):
    """Token not in DB → 401 INVALID_REFRESH_TOKEN."""
    response = await ep.refresh(
        _make_request(config=config, body={"refresh_token": "not.a.real.token"})
    )
    assert response.status_code == 401
    assert b"INVALID_REFRESH_TOKEN" in response.body


@pytest.mark.asyncio
async def test_refresh_happy_path_issues_new_access_token(reset_settings, config):
    """Login → take refresh_token → exchange for a new access_token."""
    await ep.register(
        _make_request(
            config=config,
            body={
                "username": "alice",
                "email": "alice@example.com",
                "password": PASSWORD,
                "full_name": "Alice",
            },
        )
    )
    login_response = await ep.login(
        _make_request(config=config, body={"username": "alice", "password": PASSWORD})
    )
    refresh_token = json.loads(login_response.body)["refresh_token"]

    response = await ep.refresh(_make_request(config=config, body={"refresh_token": refresh_token}))
    assert response.status_code == 200, response.body
    body = json.loads(response.body)
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    # /auth/refresh deliberately omits a new refresh_token from the response.
    assert "refresh_token" not in body or body.get("refresh_token") is None


# ---------------------------------------------------------------------------
# /auth/logout
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_logout_blacklists_access_token_jti(reset_settings, config):
    """Logout → access token's JTI is in the blacklist for any future check."""
    await ep.register(
        _make_request(
            config=config,
            body={
                "username": "alice",
                "email": "alice@example.com",
                "password": PASSWORD,
                "full_name": "Alice",
            },
        )
    )
    login_response = await ep.login(
        _make_request(config=config, body={"username": "alice", "password": PASSWORD})
    )
    tokens = json.loads(login_response.body)
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    response = await ep.logout(
        _make_request(
            config=config,
            body={"access_token": access_token, "refresh_token": refresh_token},
        )
    )
    assert response.status_code == 200, response.body

    # Verify JTI was blacklisted.
    from authmcp_gateway.auth.jwt_handler import get_token_jti
    from authmcp_gateway.auth.user_store import is_token_blacklisted

    jti = get_token_jti(access_token)
    assert is_token_blacklisted(config.auth.sqlite_path, jti) is True


@pytest.mark.asyncio
async def test_logout_401_on_invalid_access_token(reset_settings, config):
    response = await ep.logout(
        _make_request(config=config, body={"access_token": "garbage", "refresh_token": "x"})
    )
    assert response.status_code == 401
    assert b"INVALID_TOKEN" in response.body or b"VERIFICATION_ERROR" in response.body


# ---------------------------------------------------------------------------
# /auth/me
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_me_401_without_token(reset_settings, config):
    response = await ep.me(_make_request(config=config, method="GET"))
    assert response.status_code == 401
    assert b"NO_TOKEN" in response.body


@pytest.mark.asyncio
async def test_me_returns_oidc_userinfo(reset_settings, config):
    """Valid access token → OIDC-shaped payload with `sub`, `preferred_username`, `email`."""
    await ep.register(
        _make_request(
            config=config,
            body={
                "username": "alice",
                "email": "alice@example.com",
                "password": PASSWORD,
                "full_name": "Alice",
            },
        )
    )
    login_response = await ep.login(
        _make_request(config=config, body={"username": "alice", "password": PASSWORD})
    )
    access_token = json.loads(login_response.body)["access_token"]

    request = _make_request(
        config=config,
        method="GET",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    response = await ep.me(request)
    assert response.status_code == 200, response.body

    body = json.loads(response.body)
    assert body["username"] == "alice"
    assert body["email"] == "alice@example.com"
    # OIDC claims layered on top of the legacy fields.
    assert body["sub"] == str(body["id"])
    assert body["preferred_username"] == "alice"
    assert body["name"] == "Alice"
    assert body["email_verified"] is True


@pytest.mark.asyncio
async def test_me_401_on_blacklisted_token(reset_settings, config):
    """After logout, /me with the same access token returns 401 TOKEN_REVOKED."""
    await ep.register(
        _make_request(
            config=config,
            body={
                "username": "alice",
                "email": "alice@example.com",
                "password": PASSWORD,
                "full_name": "Alice",
            },
        )
    )
    login_response = await ep.login(
        _make_request(config=config, body={"username": "alice", "password": PASSWORD})
    )
    tokens = json.loads(login_response.body)

    await ep.logout(
        _make_request(
            config=config,
            body={
                "access_token": tokens["access_token"],
                "refresh_token": tokens["refresh_token"],
            },
        )
    )

    response = await ep.me(
        _make_request(
            config=config,
            method="GET",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
    )
    assert response.status_code == 401
    assert b"TOKEN_REVOKED" in response.body


# ---------------------------------------------------------------------------
# /oauth/token
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_oauth_token_400_on_missing_grant_type(reset_settings, config):
    response = await ep.oauth_token(_make_request(config=config, form={}))
    assert response.status_code == 400
    assert b"invalid_request" in response.body


@pytest.mark.asyncio
async def test_oauth_token_password_grant_form_data(reset_settings, config):
    """OAuth2 password grant via x-www-form-urlencoded body."""
    await ep.register(
        _make_request(
            config=config,
            body={
                "username": "alice",
                "email": "alice@example.com",
                "password": PASSWORD,
                "full_name": "Alice",
            },
        )
    )

    form = {"grant_type": "password", "username": "alice", "password": PASSWORD}
    request = _make_request(
        config=config,
        form=form,
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    response = await ep.oauth_token(request)
    assert response.status_code == 200, response.body
    body = json.loads(response.body)
    assert body["token_type"] == "bearer" or body["token_type"] == "Bearer"
    assert body["access_token"]
    assert body["refresh_token"]


@pytest.mark.asyncio
async def test_oauth_token_password_grant_invalid_creds_returns_401(reset_settings, config):
    request = _make_request(
        config=config,
        form={"grant_type": "password", "username": "nobody", "password": "wrong-pw-1!"},
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    response = await ep.oauth_token(request)
    assert response.status_code == 401
    assert b"invalid_grant" in response.body


@pytest.mark.asyncio
async def test_oauth_token_refresh_grant_returns_new_access_token(reset_settings, config):
    """OAuth2 refresh_token grant produces a new access_token."""
    await ep.register(
        _make_request(
            config=config,
            body={
                "username": "alice",
                "email": "alice@example.com",
                "password": PASSWORD,
                "full_name": "Alice",
            },
        )
    )
    login_response = await ep.login(
        _make_request(config=config, body={"username": "alice", "password": PASSWORD})
    )
    refresh_token = json.loads(login_response.body)["refresh_token"]

    request = _make_request(
        config=config,
        form={"grant_type": "refresh_token", "refresh_token": refresh_token},
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    response = await ep.oauth_token(request)
    assert response.status_code == 200, response.body
    body = json.loads(response.body)
    assert body["access_token"]


# Suppress unused-import warning on urlencode (kept for future expansion).
_ = urlencode
