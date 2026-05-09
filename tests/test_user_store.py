"""Tests for user store (CRUD, tokens, blacklist, audit)."""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from authmcp_gateway.auth.user_store import (
    blacklist_token,
    create_user,
    delete_user,
    get_all_users,
    get_user_by_id,
    get_user_by_username,
    hash_token,
    init_database,
    is_token_blacklisted,
    log_auth_event,
    make_user_superuser,
    revoke_refresh_token,
    save_refresh_token,
    update_user_status,
    upsert_user_access_token,
    verify_refresh_token,
)


def test_init_database(db_path):
    """All tables created successfully."""
    init_database(db_path)
    from authmcp_gateway.db import get_db

    with get_db(db_path, row_factory=None) as conn:
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        table_names = {t[0] for t in tables}
        assert "users" in table_names
        assert "refresh_tokens" in table_names
        assert "token_blacklist" in table_names
        assert "auth_audit_log" in table_names
        assert "user_access_tokens" in table_names


def test_create_user(initialized_db):
    """User created, returns ID."""
    uid = create_user(initialized_db, "alice", "alice@test.com", "hash123")
    assert isinstance(uid, int)
    assert uid > 0


def test_create_duplicate_username(initialized_db):
    """IntegrityError on duplicate username."""
    create_user(initialized_db, "alice", "alice@test.com", "hash123")
    with pytest.raises(sqlite3.IntegrityError):
        create_user(initialized_db, "alice", "alice2@test.com", "hash456")


def test_get_user_by_username(initialized_db):
    """Found and returns dict with expected keys."""
    create_user(initialized_db, "alice", "alice@test.com", "hash123")
    user = get_user_by_username(initialized_db, "alice")
    assert user is not None
    assert user["username"] == "alice"
    assert user["email"] == "alice@test.com"
    assert user["is_active"] == 1

    # Nonexistent
    assert get_user_by_username(initialized_db, "nobody") is None


def test_get_user_by_id(initialized_db):
    """Found and returns dict."""
    uid = create_user(initialized_db, "alice", "alice@test.com", "hash123")
    user = get_user_by_id(initialized_db, uid)
    assert user is not None
    assert user["id"] == uid
    assert user["username"] == "alice"

    assert get_user_by_id(initialized_db, 999) is None


def test_get_all_users(initialized_db):
    """Returns list of all users."""
    create_user(initialized_db, "alice", "alice@test.com", "hash1")
    create_user(initialized_db, "bob", "bob@test.com", "hash2")
    users = get_all_users(initialized_db)
    assert len(users) == 2
    names = {u["username"] for u in users}
    assert names == {"alice", "bob"}


def test_update_user_status(initialized_db):
    """Activate/deactivate user."""
    uid = create_user(initialized_db, "alice", "alice@test.com", "hash1")
    update_user_status(initialized_db, uid, False)
    user = get_user_by_id(initialized_db, uid)
    assert user["is_active"] == 0

    update_user_status(initialized_db, uid, True)
    user = get_user_by_id(initialized_db, uid)
    assert user["is_active"] == 1


def test_make_user_superuser(initialized_db):
    """Superuser flag set."""
    uid = create_user(initialized_db, "alice", "alice@test.com", "hash1")
    user = get_user_by_id(initialized_db, uid)
    assert user["is_superuser"] == 0

    make_user_superuser(initialized_db, uid)
    user = get_user_by_id(initialized_db, uid)
    assert user["is_superuser"] == 1


def test_delete_user(initialized_db):
    """User removed from DB."""
    uid = create_user(initialized_db, "alice", "alice@test.com", "hash1")
    assert delete_user(initialized_db, uid) is True
    assert get_user_by_id(initialized_db, uid) is None
    # Delete nonexistent returns False
    assert delete_user(initialized_db, 999) is False


def test_save_and_verify_refresh_token(initialized_db):
    """Refresh token hash stored and verified."""
    uid = create_user(initialized_db, "alice", "alice@test.com", "hash1")
    token_hash = hash_token("my-refresh-token")
    expires = datetime.now(timezone.utc) + timedelta(days=7)
    save_refresh_token(initialized_db, uid, token_hash, expires)

    result = verify_refresh_token(initialized_db, token_hash)
    assert result == uid


def test_revoke_refresh_token(initialized_db):
    """Revoked token no longer verifies."""
    uid = create_user(initialized_db, "alice", "alice@test.com", "hash1")
    token_hash = hash_token("my-refresh-token")
    expires = datetime.now(timezone.utc) + timedelta(days=7)
    save_refresh_token(initialized_db, uid, token_hash, expires)

    revoke_refresh_token(initialized_db, token_hash)
    assert verify_refresh_token(initialized_db, token_hash) is None


def test_blacklist_token(initialized_db):
    """JTI blacklisted and checked correctly."""
    jti = "test-jti-12345"
    expires = datetime.now(timezone.utc) + timedelta(hours=1)

    assert is_token_blacklisted(initialized_db, jti) is False
    blacklist_token(initialized_db, jti, expires)
    assert is_token_blacklisted(initialized_db, jti) is True


def test_log_auth_event(initialized_db, monkeypatch):
    """Event inserted in audit log."""
    # Monkeypatch file logger to avoid side effects
    monkeypatch.setattr("authmcp_gateway.auth.user_store.log_auth_event_to_file", lambda **kw: None)
    log_auth_event(
        db_path=initialized_db,
        event_type="login",
        user_id=1,
        username="alice",
        ip_address="127.0.0.1",
        success=True,
    )
    from authmcp_gateway.db import get_db

    with get_db(initialized_db) as conn:
        row = conn.execute("SELECT * FROM auth_audit_log LIMIT 1").fetchone()
        assert row is not None
        assert row["event_type"] == "login"
        assert row["username"] == "alice"


def test_hash_token():
    """Deterministic SHA256 hash."""
    h1 = hash_token("test-token")
    h2 = hash_token("test-token")
    assert h1 == h2
    assert len(h1) == 64  # SHA256 hex digest
    assert hash_token("other") != h1


def test_upsert_user_access_token(initialized_db):
    """Insert then update access token."""
    uid = create_user(initialized_db, "alice", "alice@test.com", "hash1")
    expires = datetime.now(timezone.utc) + timedelta(hours=1)

    # Insert
    upsert_user_access_token(initialized_db, uid, "", "jti-1", expires)

    from authmcp_gateway.auth.user_store import get_user_access_token

    tok = get_user_access_token(initialized_db, uid)
    assert tok is not None
    assert tok["token_jti"] == "jti-1"

    # Update
    upsert_user_access_token(initialized_db, uid, "", "jti-2", expires)
    tok = get_user_access_token(initialized_db, uid)
    assert tok["token_jti"] == "jti-2"
