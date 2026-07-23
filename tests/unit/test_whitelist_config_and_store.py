"""Unit tests for Whitelist security configuration and one-time records."""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.fernet import Fernet

from authmcp_gateway.auth.whitelist_store import (
    consume_action_authorization,
    consume_challenge,
    init_whitelist_database,
)
from authmcp_gateway.config import (
    AppConfig,
    AuthConfig,
    JWTConfig,
    RateLimitConfig,
    WhitelistAuthConfig,
    initialize_whitelist_credential_key,
)


def _app_config(mcp_public_url: str, whitelist_auth: WhitelistAuthConfig | None = None) -> AppConfig:
    return AppConfig(
        jwt=JWTConfig(algorithm="HS256", secret_key="x" * 32),
        auth=AuthConfig(sqlite_path="data/test-auth.db"),
        rate_limit=RateLimitConfig(enabled=False),
        mcp_public_url=mcp_public_url,
        whitelist_auth=whitelist_auth or WhitelistAuthConfig(),
    )


def test_webauthn_defaults_to_mcp_public_url_for_a_single_domain():
    config = _app_config("https://gateway.example.com")

    assert config.whitelist_auth.webauthn_rp_ids == ["gateway.example.com"]
    assert config.whitelist_auth.webauthn_allowed_origins == ["https://gateway.example.com"]


def test_explicit_webauthn_domains_override_mcp_public_url_defaults():
    config = _app_config(
        "https://mcp.example.com",
        WhitelistAuthConfig(
            webauthn_rp_ids=["mcp.example.com", "admin.example.com", "localhost"],
            webauthn_allowed_origins=[
                "https://mcp.example.com",
                "https://admin.example.com",
                "http://localhost:9105",
            ],
        ),
    )

    assert config.whitelist_auth.webauthn_rp_ids == [
        "mcp.example.com",
        "admin.example.com",
        "localhost",
    ]
    assert config.whitelist_auth.webauthn_allowed_origins == [
        "https://mcp.example.com",
        "https://admin.example.com",
        "http://localhost:9105",
    ]


def test_credential_key_requires_explicit_initialization(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    env_path = tmp_path / ".env"
    env_path.write_text("JWT_SECRET_KEY=existing\n", encoding="utf-8")

    config = WhitelistAuthConfig()
    assert config.credential_encryption_key is None
    assert "WHITELIST_CREDENTIAL_ENCRYPTION_KEY" not in env_path.read_text(encoding="utf-8")

    key = initialize_whitelist_credential_key()
    Fernet(key.encode("ascii"))
    assert f"WHITELIST_CREDENTIAL_ENCRYPTION_KEY={key}" in (env_path.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "origin",
    [
        "example.com",
        "https://example.com/path",
        "ftp://example.com",
        "https://:443",
        "https://example.com:bad",
        "https://example.com:99999",
    ],
)
def test_whitelist_allowed_origins_must_be_complete_origins(origin):
    with pytest.raises(ValueError, match="ORIGINS|invalid port"):
        WhitelistAuthConfig(
            credential_encryption_key=Fernet.generate_key().decode("ascii"),
            webauthn_allowed_origins=[origin],
        )


def test_one_time_whitelist_records_are_consumed_atomically(tmp_path):
    db_path = str(tmp_path / "auth.db")
    init_whitelist_database(db_path)
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(minutes=1)).isoformat()

    with sqlite3.connect(db_path) as conn:
        challenge_id = conn.execute(
            """
            INSERT INTO whitelist_challenges (
                challenge_digest, user_id, admin_session_jti, rp_id, purpose, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            ("challenge", 1, "admin-jti", "localhost", "authenticate", now.isoformat(), expires_at),
        ).lastrowid
        authorization_id = conn.execute(
            """
            INSERT INTO whitelist_action_authorizations (
                user_id, admin_session_jti, action, resource_type, resource_id,
                config_fingerprint, authorized_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (1, "admin-jti", "approve", "server", 1, "fingerprint", now.isoformat(), expires_at),
        ).lastrowid

    consumed_challenge = consume_challenge(db_path, int(challenge_id))

    assert consumed_challenge and consumed_challenge["id"] == challenge_id
    assert consume_challenge(db_path, int(challenge_id)) is None
    assert consume_action_authorization(db_path, int(authorization_id)) is True
    assert consume_action_authorization(db_path, int(authorization_id)) is False
