"""Unit coverage for server-owned WebAuthn persistence and challenge binding."""

import sqlite3
from datetime import datetime, timedelta, timezone

from types import SimpleNamespace

import pytest
from starlette.requests import Request

from authmcp_gateway.auth.password import hash_password
from authmcp_gateway.auth.user_store import create_user, init_database
from authmcp_gateway.auth.webauthn_store import (
    create_challenge,
    create_passkey,
    get_and_consume_challenge,
    get_passkey_by_credential_id,
    list_passkeys,
    revoke_passkey,
    resolve_origin,
    resolve_rp_id,
    update_sign_count,
)
from authmcp_gateway.auth.whitelist_store import init_whitelist_database


def _request(
    host: str = "admin.example.test", origin: str = "https://admin.example.test"
) -> Request:
    return Request(
        {
            "type": "http",
            "scheme": "https",
            "path": "/",
            "server": (host, 443),
            "headers": [(b"host", host.encode()), (b"origin", origin.encode())],
        }
    )


def _user(db_path: str) -> int:
    init_database(db_path)
    init_whitelist_database(db_path)
    return create_user(db_path, "admin", "admin@example.test", hash_password("Password123!"), True)


def test_resolvers_use_exact_server_side_allowlists():
    config = SimpleNamespace(
        webauthn_rp_ids=["admin.example.test"],
        webauthn_allowed_origins=["https://admin.example.test"],
    )
    assert resolve_rp_id(_request(), config) == "admin.example.test"
    assert resolve_origin(_request(), config) == "https://admin.example.test"
    with pytest.raises(ValueError):
        resolve_rp_id(_request(host="attacker.example.test"), config)
    with pytest.raises(ValueError):
        resolve_origin(_request(origin="https://attacker.example.test"), config)


def test_challenge_is_hashed_bound_and_consumed_once(db_path):
    user_id = _user(db_path)
    _, challenge = create_challenge(
        db_path,
        user_id=user_id,
        admin_session_jti="jti",
        rp_id="admin.example.test",
        purpose="authenticate",
    )
    assert (
        get_and_consume_challenge(
            db_path,
            challenge=challenge,
            user_id=user_id,
            admin_session_jti="wrong",
            rp_id="admin.example.test",
            purpose="authenticate",
        )
        is None
    )
    assert (
        get_and_consume_challenge(
            db_path,
            challenge=challenge,
            user_id=user_id,
            admin_session_jti="jti",
            rp_id="admin.example.test",
            purpose="authenticate",
        )
        is not None
    )
    assert (
        get_and_consume_challenge(
            db_path,
            challenge=challenge,
            user_id=user_id,
            admin_session_jti="jti",
            rp_id="admin.example.test",
            purpose="authenticate",
        )
        is None
    )


def test_passkey_public_data_can_be_updated_without_private_key(db_path):
    user_id = _user(db_path)
    create_passkey(
        db_path,
        user_id=user_id,
        credential_id=b"credential",
        public_key=b"public-key",
        sign_count=0,
        rp_id="admin.example.test",
        label="Laptop",
    )
    credential_id = list_passkeys(db_path, user_id)[0]["credential_id"]
    stored = get_passkey_by_credential_id(db_path, credential_id)
    assert stored and stored["public_key_bytes"] == b"public-key"
    assert update_sign_count(db_path, credential_id=credential_id, sign_count=1)
    assert not update_sign_count(db_path, credential_id=credential_id, sign_count=0)


def test_final_passkey_revocation_requires_recovery_in_one_transaction(db_path):
    user_id = _user(db_path)
    create_passkey(
        db_path,
        user_id=user_id,
        credential_id=b"credential",
        public_key=b"public-key",
        sign_count=0,
        rp_id="admin.example.test",
    )
    credential_id = list_passkeys(db_path, user_id)[0]["credential_id"]
    assert (
        revoke_passkey(db_path, user_id=user_id, credential_id=credential_id) == "recovery_required"
    )
    assert len(list_passkeys(db_path, user_id)) == 1

    now = datetime.now(timezone.utc)
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """INSERT INTO whitelist_recovery_credentials
               (user_id, code_digest, created_at, expires_at) VALUES (?, ?, ?, ?)""",
            (user_id, "active-recovery", now.isoformat(), (now + timedelta(minutes=5)).isoformat()),
        )
    assert revoke_passkey(db_path, user_id=user_id, credential_id=credential_id) == "revoked"
    assert list_passkeys(db_path, user_id) == []
