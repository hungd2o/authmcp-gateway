"""Characterization + behaviour tests for auth/token_service.py.

Written before refactoring the broad ``except Exception: pass`` blocks.
The intent is to lock in the public behaviour (token issuance, single-session
rotation, blacklisting on rotate) so that narrowing the catch sites cannot
silently regress it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from authmcp_gateway.auth.jwt_handler import (
    create_access_token,
    decode_token_unsafe,
    verify_token,
)
from authmcp_gateway.auth.token_service import (
    _parse_expires_at,
    format_expires_in,
    get_or_create_admin_token,
    get_or_create_user_token,
    rotate_admin_token,
    rotate_user_token,
)
from authmcp_gateway.auth.user_store import (
    blacklist_token,
    get_admin_access_token,
    get_user_access_token,
    init_database,
    is_token_blacklisted,
)
from authmcp_gateway.config import JWTConfig

# ---------- fixtures ----------


@pytest.fixture
def jwt_cfg() -> JWTConfig:
    return JWTConfig(
        algorithm="HS256",
        secret_key="test-secret-key-at-least-32-characters-long-for-hmac",
        enforce_single_session=True,
    )


@pytest.fixture
def jwt_cfg_no_single_session() -> JWTConfig:
    return JWTConfig(
        algorithm="HS256",
        secret_key="test-secret-key-at-least-32-characters-long-for-hmac",
        enforce_single_session=False,
    )


@pytest.fixture
def ready_db(db_path):
    init_database(db_path)
    return db_path


# ---------- _parse_expires_at ----------


def test_parse_expires_at_returns_none_for_falsy():
    assert _parse_expires_at(None) is None
    assert _parse_expires_at("") is None
    assert _parse_expires_at(0) is None


def test_parse_expires_at_passes_aware_datetime_through():
    dt = datetime(2026, 5, 9, 10, 0, 0, tzinfo=timezone.utc)
    assert _parse_expires_at(dt) == dt


def test_parse_expires_at_promotes_naive_datetime_to_utc():
    naive = datetime(2026, 5, 9, 10, 0, 0)
    parsed = _parse_expires_at(naive)
    assert parsed is not None
    assert parsed.tzinfo is timezone.utc


def test_parse_expires_at_handles_iso_string_with_z():
    parsed = _parse_expires_at("2026-05-09T10:00:00Z")
    assert parsed is not None
    assert parsed.tzinfo is not None


def test_parse_expires_at_returns_none_for_garbage_string():
    assert _parse_expires_at("not-a-date") is None


def test_parse_expires_at_returns_none_for_unsupported_type():
    # Lists, dicts, etc. are not parseable.
    assert _parse_expires_at(["2026-05-09"]) is None


# ---------- format_expires_in ----------


def test_format_expires_in_minutes():
    future = datetime.now(timezone.utc) + timedelta(minutes=5)
    assert "minute" in format_expires_in(future)


def test_format_expires_in_hours():
    future = datetime.now(timezone.utc) + timedelta(hours=3)
    assert "hour" in format_expires_in(future)


def test_format_expires_in_days():
    future = datetime.now(timezone.utc) + timedelta(days=2)
    assert "day" in format_expires_in(future)


def test_format_expires_in_empty_for_none():
    assert format_expires_in(None) == ""


# ---------- get_or_create_user_token ----------


def test_get_or_create_user_token_creates_new_when_no_stored(ready_db, jwt_cfg):
    token, exp = get_or_create_user_token(
        ready_db,
        user_id=1,
        username="alice",
        is_superuser=False,
        config=jwt_cfg,
        expire_minutes=30,
    )
    assert token
    assert exp > datetime.now(timezone.utc)
    payload = verify_token(token, "access", jwt_cfg)
    assert payload["sub"] == "1"
    assert payload["username"] == "alice"

    stored = get_user_access_token(ready_db, 1)
    assert stored is not None
    assert stored["token_jti"] == payload["jti"]


def test_get_or_create_user_token_returns_same_when_current_matches_stored(ready_db, jwt_cfg):
    first, _ = get_or_create_user_token(
        ready_db,
        user_id=1,
        username="alice",
        is_superuser=False,
        config=jwt_cfg,
        expire_minutes=30,
    )
    second, _ = get_or_create_user_token(
        ready_db,
        user_id=1,
        username="alice",
        is_superuser=False,
        config=jwt_cfg,
        expire_minutes=30,
        current_token=first,
    )
    assert second == first


def test_get_or_create_user_token_rotates_when_current_token_jti_differs(ready_db, jwt_cfg):
    """Stale or attacker-supplied token (different JTI) must trigger rotation."""
    issued, _ = get_or_create_user_token(
        ready_db,
        user_id=1,
        username="alice",
        is_superuser=False,
        config=jwt_cfg,
        expire_minutes=30,
    )

    foreign_token = create_access_token(
        user_id=1, username="alice", is_superuser=False, config=jwt_cfg, expire_minutes=30
    )
    new_token, _ = get_or_create_user_token(
        ready_db,
        user_id=1,
        username="alice",
        is_superuser=False,
        config=jwt_cfg,
        expire_minutes=30,
        current_token=foreign_token,
    )
    assert new_token != issued
    issued_jti = decode_token_unsafe(issued)["jti"]
    # The previously stored token's jti is now blacklisted.
    assert is_token_blacklisted(ready_db, issued_jti)


def test_get_or_create_user_token_rotates_when_current_token_is_garbage(ready_db, jwt_cfg):
    issued, _ = get_or_create_user_token(
        ready_db,
        user_id=1,
        username="alice",
        is_superuser=False,
        config=jwt_cfg,
        expire_minutes=30,
    )
    new_token, _ = get_or_create_user_token(
        ready_db,
        user_id=1,
        username="alice",
        is_superuser=False,
        config=jwt_cfg,
        expire_minutes=30,
        current_token="not-a-jwt",
    )
    assert new_token != issued
    issued_jti = decode_token_unsafe(issued)["jti"]
    assert is_token_blacklisted(ready_db, issued_jti)


def test_get_or_create_user_token_rotates_when_current_already_blacklisted(ready_db, jwt_cfg):
    issued, exp = get_or_create_user_token(
        ready_db,
        user_id=1,
        username="alice",
        is_superuser=False,
        config=jwt_cfg,
        expire_minutes=30,
    )
    issued_jti = decode_token_unsafe(issued)["jti"]
    blacklist_token(ready_db, issued_jti, exp)

    new_token, _ = get_or_create_user_token(
        ready_db,
        user_id=1,
        username="alice",
        is_superuser=False,
        config=jwt_cfg,
        expire_minutes=30,
        current_token=issued,
    )
    assert new_token != issued


def test_get_or_create_user_token_does_not_blacklist_when_single_session_disabled(
    ready_db, jwt_cfg_no_single_session
):
    issued, _ = get_or_create_user_token(
        ready_db,
        user_id=1,
        username="alice",
        is_superuser=False,
        config=jwt_cfg_no_single_session,
        expire_minutes=30,
    )
    issued_jti = decode_token_unsafe(issued)["jti"]
    foreign = create_access_token(
        user_id=1,
        username="alice",
        is_superuser=False,
        config=jwt_cfg_no_single_session,
        expire_minutes=30,
    )
    get_or_create_user_token(
        ready_db,
        user_id=1,
        username="alice",
        is_superuser=False,
        config=jwt_cfg_no_single_session,
        expire_minutes=30,
        current_token=foreign,
    )
    assert is_token_blacklisted(ready_db, issued_jti) is False


# ---------- get_or_create_admin_token: parity with user variant on a separate store ----------


def test_get_or_create_admin_token_uses_separate_store(ready_db, jwt_cfg):
    user_token, _ = get_or_create_user_token(
        ready_db,
        user_id=1,
        username="alice",
        is_superuser=True,
        config=jwt_cfg,
        expire_minutes=30,
    )
    admin_token, _ = get_or_create_admin_token(
        ready_db,
        user_id=1,
        username="alice",
        is_superuser=True,
        config=jwt_cfg,
        expire_minutes=30,
    )
    # Admin and user tables are independent: each has its own jti.
    assert (
        get_user_access_token(ready_db, 1)["token_jti"]
        != get_admin_access_token(ready_db, 1)["token_jti"]
    )
    assert admin_token != user_token


def test_get_or_create_admin_token_rotates_on_jti_mismatch(ready_db, jwt_cfg):
    issued, _ = get_or_create_admin_token(
        ready_db,
        user_id=1,
        username="alice",
        is_superuser=True,
        config=jwt_cfg,
        expire_minutes=30,
    )
    foreign = create_access_token(
        user_id=1, username="alice", is_superuser=True, config=jwt_cfg, expire_minutes=30
    )
    new_token, _ = get_or_create_admin_token(
        ready_db,
        user_id=1,
        username="alice",
        is_superuser=True,
        config=jwt_cfg,
        expire_minutes=30,
        current_token=foreign,
    )
    assert new_token != issued
    issued_jti = decode_token_unsafe(issued)["jti"]
    assert is_token_blacklisted(ready_db, issued_jti)


# ---------- rotate_user_token / rotate_admin_token ----------


def test_rotate_user_token_without_current_just_creates_new(ready_db, jwt_cfg):
    token, exp = rotate_user_token(
        ready_db,
        user_id=1,
        username="alice",
        is_superuser=False,
        config=jwt_cfg,
        expire_minutes=30,
        current_token=None,
    )
    assert token
    assert exp > datetime.now(timezone.utc)
    payload = verify_token(token, "access", jwt_cfg)
    assert payload["username"] == "alice"


def test_rotate_user_token_blacklists_provided_current_token(ready_db, jwt_cfg):
    issued = create_access_token(
        user_id=1, username="alice", is_superuser=False, config=jwt_cfg, expire_minutes=30
    )
    new_token, _ = rotate_user_token(
        ready_db,
        user_id=1,
        username="alice",
        is_superuser=False,
        config=jwt_cfg,
        expire_minutes=30,
        current_token=issued,
    )
    assert new_token != issued
    issued_jti = decode_token_unsafe(issued)["jti"]
    assert is_token_blacklisted(ready_db, issued_jti)


def test_rotate_user_token_handles_garbage_current_token(ready_db, jwt_cfg):
    """A non-decodable current_token must not raise — rotation still issues a new one."""
    new_token, _ = rotate_user_token(
        ready_db,
        user_id=1,
        username="alice",
        is_superuser=False,
        config=jwt_cfg,
        expire_minutes=30,
        current_token="garbage",
    )
    assert new_token


def test_rotate_admin_token_blacklists_provided_current_token(ready_db, jwt_cfg):
    issued = create_access_token(
        user_id=1, username="alice", is_superuser=True, config=jwt_cfg, expire_minutes=30
    )
    new_token, _ = rotate_admin_token(
        ready_db,
        user_id=1,
        username="alice",
        is_superuser=True,
        config=jwt_cfg,
        expire_minutes=30,
        current_token=issued,
    )
    assert new_token != issued
    issued_jti = decode_token_unsafe(issued)["jti"]
    assert is_token_blacklisted(ready_db, issued_jti)
