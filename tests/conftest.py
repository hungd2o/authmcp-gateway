"""Shared test fixtures for AuthMCP Gateway."""

import pytest

from authmcp_gateway.config import JWTConfig


@pytest.fixture(autouse=True)
def _isolate_global_config(monkeypatch, tmp_path):
    """Prevent tests from polluting the live `data/auth.db`.

    `rate_limiter`, `security/logger`, and a few admin paths reach the
    AppConfig via the global singleton in `authmcp_gateway.config.get_config()`.
    Without this fixture, the singleton lazy-loads from `.env` in cwd —
    when pytest runs from the project root that resolves to the same
    `data/auth.db` mounted into the running container, so tests that
    trigger rate limiting (or any code path calling `get_config()`) write
    into the prod DB.

    This autouse fixture wipes the cached singleton and points the
    sqlite path at a per-test tmp file. `monkeypatch` reverts both at
    teardown. Tests that intentionally exercise config still build their
    own `AppConfig` directly and pass it as a parameter — those code paths
    never go through `get_config()`.
    """
    from authmcp_gateway import config as config_mod

    monkeypatch.setattr(config_mod, "_config_instance", None)
    monkeypatch.setenv("AUTH_SQLITE_PATH", str(tmp_path / "isolated_auth.db"))
    yield


@pytest.fixture
def db_path(tmp_path):
    """Provide a temporary SQLite database path."""
    return str(tmp_path / "test.db")


@pytest.fixture
def jwt_config():
    """Provide a JWTConfig with HS256 test key."""
    return JWTConfig(
        algorithm="HS256",
        secret_key="test-secret-key-at-least-32-characters-long-for-hmac",
    )


@pytest.fixture
def initialized_db(db_path):
    """DB with all user_store tables created."""
    from authmcp_gateway.auth.user_store import init_database

    init_database(db_path)
    return db_path
