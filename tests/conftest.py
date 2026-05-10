"""Shared test fixtures for AuthMCP Gateway."""

import pytest

from authmcp_gateway.config import JWTConfig


@pytest.fixture(autouse=True)
def _isolate_global_state(monkeypatch, tmp_path):
    """Prevent tests from polluting the live `data/auth.db` and
    `data/logs/auth.log`.

    Two leak vectors exist:

    1. **AppConfig singleton** — `rate_limiter`, `security/logger`, and
       a few admin paths reach the AppConfig via
       `authmcp_gateway.config.get_config()`. Without this fixture the
       singleton lazy-loads from `.env` in cwd; when pytest runs from
       the project root that resolves to the same `data/auth.db` mounted
       into the live container.

    2. **Auth-events file logger** — `auth.user_store.get_auth_logger()`
       hardcodes `Path("data/logs/auth.log")`. Tests that exercise
       login / register / OAuth flows would emit JSONL lines into the
       prod log file (visible in admin "MCP Auth Events" widget).

    The fixture wipes the cached singletons and redirects both to a
    per-test tmp file. `monkeypatch` reverts at teardown.
    """
    from authmcp_gateway import config as config_mod
    from authmcp_gateway.auth import user_store as user_store_mod

    monkeypatch.setattr(config_mod, "_config_instance", None)
    monkeypatch.setenv("AUTH_SQLITE_PATH", str(tmp_path / "isolated_auth.db"))

    # Reset the file-logger singleton; setup_file_logger will rebuild it
    # next time it's needed, against an isolated path. Also patch
    # get_auth_logger to point at a tmp log file so writes don't reach
    # data/logs/auth.log.
    monkeypatch.setattr(user_store_mod, "_auth_logger", None)
    isolated_log = tmp_path / "isolated_auth.log"

    def _isolated_auth_logger():
        from authmcp_gateway.logging_config import setup_file_logger

        if user_store_mod._auth_logger is None:
            user_store_mod._auth_logger = setup_file_logger("auth_events", isolated_log)
        return user_store_mod._auth_logger

    monkeypatch.setattr(user_store_mod, "get_auth_logger", _isolated_auth_logger)
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
