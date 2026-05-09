"""Tests for the first-run setup wizard.

Covers `is_setup_required`, `setup_page`, and the initial-admin creation
endpoint. Request objects are hand-rolled SimpleNamespaces — Starlette's
TestClient would also work but adds a lot of fixture surface for routes
that aren't really being exercised here.
"""

import json
from dataclasses import dataclass, field
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from authmcp_gateway import setup_wizard
from authmcp_gateway.config import AuthConfig

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@dataclass
class _FakeAppConfig:
    auth: AuthConfig = field(default_factory=AuthConfig)


def _make_request(config, body=None):
    """Build a minimal fake Starlette Request.

    `config` becomes `request.app.state.config`. If `body` is given,
    `await request.json()` returns it.
    """
    app = SimpleNamespace(state=SimpleNamespace(config=config))
    request = SimpleNamespace(app=app)
    if body is not None:
        request.json = AsyncMock(return_value=body)
    return request


@pytest.fixture
def setup_config(initialized_db):
    """An AppConfig-like object pointing at a fresh, empty users DB."""
    cfg = _FakeAppConfig()
    cfg.auth.sqlite_path = initialized_db
    return cfg


# ---------------------------------------------------------------------------
# is_setup_required
# ---------------------------------------------------------------------------


def test_is_setup_required_true_when_no_users(setup_config):
    """Fresh DB with no users -> setup required."""
    request = _make_request(setup_config)
    assert setup_wizard.is_setup_required(request) is True


def test_is_setup_required_false_when_users_exist(setup_config):
    """Any user -> setup not required."""
    from authmcp_gateway.auth.user_store import create_user

    create_user(setup_config.auth.sqlite_path, "alice", "alice@x.com", "hash")
    request = _make_request(setup_config)
    assert setup_wizard.is_setup_required(request) is False


def test_is_setup_required_false_when_config_is_none():
    """No config bound to app state -> setup is not required (no-op)."""
    request = _make_request(None)
    assert setup_wizard.is_setup_required(request) is False


def test_is_setup_required_returns_false_on_db_error(setup_config, monkeypatch):
    """sqlite3 / OS errors are logged and surface as 'no setup needed' so
    the gateway doesn't open the wizard on a transient DB failure."""
    import sqlite3 as sqlite_mod

    def boom(_path):
        raise sqlite_mod.OperationalError("disk gone")

    monkeypatch.setattr("authmcp_gateway.setup_wizard.get_all_users", boom)

    request = _make_request(setup_config)
    assert setup_wizard.is_setup_required(request) is False


# ---------------------------------------------------------------------------
# setup_page
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_setup_page_redirects_when_setup_done(setup_config):
    """If users already exist, /setup redirects to /admin (302)."""
    from authmcp_gateway.auth.user_store import create_user

    create_user(setup_config.auth.sqlite_path, "alice", "alice@x.com", "hash")

    response = await setup_wizard.setup_page(_make_request(setup_config))
    assert response.status_code == 302
    assert response.headers["location"] == "/admin"


@pytest.mark.asyncio
async def test_setup_page_serves_html_when_setup_required(setup_config):
    """Empty DB -> setup wizard HTML form is served."""
    response = await setup_wizard.setup_page(_make_request(setup_config))
    assert response.status_code == 200
    assert response.media_type == "text/html"
    body = response.body.decode("utf-8")
    assert "Initial Setup" in body
    assert 'id="setupForm"' in body


# ---------------------------------------------------------------------------
# create_admin_user
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_admin_blocks_when_already_set_up(setup_config):
    """If users already exist, the endpoint refuses with 403."""
    from authmcp_gateway.auth.user_store import create_user

    create_user(setup_config.auth.sqlite_path, "alice", "alice@x.com", "hash")
    request = _make_request(setup_config, body={"username": "x"})

    response = await setup_wizard.create_admin_user(request)
    assert response.status_code == 403
    assert b"already completed" in response.body


@pytest.mark.asyncio
async def test_create_admin_400_on_missing_fields(setup_config):
    """Missing username/email/password -> 400."""
    request = _make_request(setup_config, body={"username": "alice", "password": ""})
    response = await setup_wizard.create_admin_user(request)
    assert response.status_code == 400
    assert b"required" in response.body


@pytest.mark.asyncio
async def test_create_admin_400_on_weak_password(setup_config):
    """Password fails policy check -> 400 with the policy's error message."""
    request = _make_request(
        setup_config,
        body={
            "username": "alice",
            "email": "alice@x.com",
            "password": "short",  # Too short for default policy
            "full_name": "Alice",
        },
    )
    response = await setup_wizard.create_admin_user(request)
    assert response.status_code == 400
    # Exact wording comes from validate_password_strength; just verify the
    # endpoint passed it through rather than masking with a generic message.
    body = response.body.decode("utf-8")
    assert "Password" in body or "password" in body


@pytest.mark.asyncio
async def test_create_admin_happy_path(setup_config):
    """Strong password + empty DB -> 201 with user_id; user is superuser."""
    request = _make_request(
        setup_config,
        body={
            "username": "alice",
            "email": "alice@x.com",
            "password": "StrongP@ssw0rd!",
            "full_name": "Alice Admin",
        },
    )
    response = await setup_wizard.create_admin_user(request)
    assert response.status_code == 201

    payload = json.loads(response.body)
    assert payload["success"] is True
    assert payload["username"] == "alice"
    assert isinstance(payload["user_id"], int)

    # Verify the user is actually a superuser in the DB.
    from authmcp_gateway.auth.user_store import get_user_by_username

    user = get_user_by_username(setup_config.auth.sqlite_path, "alice")
    assert user is not None
    assert user["is_superuser"] == 1
    assert user["full_name"] == "Alice Admin"


@pytest.mark.asyncio
async def test_create_admin_500_on_db_error(setup_config, monkeypatch):
    """sqlite3.Error during create_user surfaces as 500 with the error in body."""
    import sqlite3 as sqlite_mod

    def boom(**_kwargs):
        raise sqlite_mod.OperationalError("disk full")

    monkeypatch.setattr("authmcp_gateway.setup_wizard.create_user", boom)

    request = _make_request(
        setup_config,
        body={
            "username": "alice",
            "email": "alice@x.com",
            "password": "StrongP@ssw0rd!",
            "full_name": None,
        },
    )
    response = await setup_wizard.create_admin_user(request)
    assert response.status_code == 500
    assert b"disk full" in response.body


@pytest.mark.asyncio
async def test_create_admin_overlays_password_policy_from_settings(setup_config, monkeypatch):
    """The endpoint pulls min_length / require_* overrides from
    SettingsManager — tighter policy than env-config should reject a
    password that env-config would accept."""

    class _StubSettings:
        def get(self, *keys, default=None):
            # Force min_length to 100 so even StrongP@ssw0rd! fails.
            if keys == ("password_policy",):
                return {
                    "min_length": 100,
                    "require_uppercase": True,
                    "require_lowercase": True,
                    "require_digit": True,
                    "require_special": True,
                }
            return default

    monkeypatch.setattr(
        "authmcp_gateway.setup_wizard.get_settings_manager", lambda: _StubSettings()
    )

    request = _make_request(
        setup_config,
        body={
            "username": "alice",
            "email": "alice@x.com",
            "password": "StrongP@ssw0rd!",
            "full_name": None,
        },
    )
    response = await setup_wizard.create_admin_user(request)
    assert response.status_code == 400
    body = response.body.decode("utf-8")
    assert "100" in body or "length" in body


@pytest.mark.asyncio
async def test_create_admin_falls_back_to_env_policy_on_settings_error(setup_config, monkeypatch):
    """If SettingsManager isn't initialised, fall through to AuthConfig
    defaults rather than 500."""

    def boom():
        raise RuntimeError("settings not initialized")

    monkeypatch.setattr("authmcp_gateway.setup_wizard.get_settings_manager", boom)

    request = _make_request(
        setup_config,
        body={
            "username": "alice",
            "email": "alice@x.com",
            "password": "StrongP@ssw0rd!",
            "full_name": None,
        },
    )
    # Default AuthConfig already requires upper/lower/digit/special >= 8.
    # StrongP@ssw0rd! satisfies that, so the request should succeed.
    response = await setup_wizard.create_admin_user(request)
    assert response.status_code == 201, response.body


# Inline: make sure starlette redirect import path didn't break.
def test_module_imports_clean():
    assert callable(setup_wizard.is_setup_required)
    assert callable(setup_wizard.setup_page)
    assert callable(setup_wizard.create_admin_user)
