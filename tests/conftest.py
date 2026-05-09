"""Shared test fixtures for AuthMCP Gateway."""

import pytest

from authmcp_gateway.config import JWTConfig


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
