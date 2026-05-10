"""Tests for OAuth 2.0 Authorization Code Flow with PKCE."""

import base64
import hashlib

import pytest

from authmcp_gateway.auth.oauth_code_flow import (
    cleanup_expired_codes,
    create_authorization_code_table,
    generate_authorization_code,
    verify_authorization_code,
)
from authmcp_gateway.db import get_db


def _pkce_pair(verifier: str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"):
    """Return (verifier, S256 challenge) pair for PKCE."""
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
    return verifier, challenge


@pytest.fixture
def code_db(db_path):
    """DB with authorization_codes table and a users table."""
    create_authorization_code_table(db_path)
    # Create a minimal users table for FK
    with get_db(db_path, row_factory=None) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users " "(id INTEGER PRIMARY KEY, username TEXT)")
        conn.execute("INSERT INTO users VALUES (1, 'alice')")
    return db_path


def test_create_table(db_path):
    """Table creation is idempotent."""
    create_authorization_code_table(db_path)
    create_authorization_code_table(db_path)  # No error on second call


def test_generate_code(code_db):
    """Code generated and stored in DB."""
    code = generate_authorization_code(
        db_path=code_db,
        user_id=1,
        client_id="client1",
        redirect_uri="http://localhost/callback",
        code_challenge=None,
        code_challenge_method=None,
        scope="read",
    )
    assert isinstance(code, str)
    assert len(code) > 20


def test_verify_valid_code(code_db):
    """Valid code returns user_id and scope (PKCE S256 required per OAuth 2.1)."""
    verifier, challenge = _pkce_pair()
    code = generate_authorization_code(
        db_path=code_db,
        user_id=1,
        client_id="client1",
        redirect_uri="http://localhost/callback",
        code_challenge=challenge,
        code_challenge_method="S256",
        scope="read write",
    )
    result = verify_authorization_code(
        db_path=code_db,
        code=code,
        client_id="client1",
        redirect_uri="http://localhost/callback",
        code_verifier=verifier,
    )
    assert result is not None
    assert result["user_id"] == 1
    assert result["scope"] == "read write"


def test_verify_marks_used(code_db):
    """Code can only be used once."""
    verifier, challenge = _pkce_pair()
    code = generate_authorization_code(
        db_path=code_db,
        user_id=1,
        client_id="client1",
        redirect_uri="http://localhost/callback",
        code_challenge=challenge,
        code_challenge_method="S256",
        scope=None,
    )
    # First use succeeds
    result = verify_authorization_code(
        code_db, code, "client1", "http://localhost/callback", verifier
    )
    assert result is not None

    # Second use fails
    result2 = verify_authorization_code(
        code_db, code, "client1", "http://localhost/callback", verifier
    )
    assert result2 is None


def test_verify_expired_code(code_db):
    """Expired code returns None."""
    code = generate_authorization_code(
        db_path=code_db,
        user_id=1,
        client_id="client1",
        redirect_uri="http://localhost/callback",
        code_challenge=None,
        code_challenge_method=None,
        scope=None,
        expires_in_seconds=-1,  # Already expired
    )
    result = verify_authorization_code(code_db, code, "client1", "http://localhost/callback", None)
    assert result is None


def test_verify_wrong_client(code_db):
    """Wrong client_id returns None."""
    code = generate_authorization_code(
        db_path=code_db,
        user_id=1,
        client_id="client1",
        redirect_uri="http://localhost/callback",
        code_challenge=None,
        code_challenge_method=None,
        scope=None,
    )
    result = verify_authorization_code(
        code_db, code, "wrong_client", "http://localhost/callback", None
    )
    assert result is None


def test_verify_wrong_redirect(code_db):
    """Wrong redirect_uri returns None."""
    code = generate_authorization_code(
        db_path=code_db,
        user_id=1,
        client_id="client1",
        redirect_uri="http://localhost/callback",
        code_challenge=None,
        code_challenge_method=None,
        scope=None,
    )
    result = verify_authorization_code(code_db, code, "client1", "http://evil.com/steal", None)
    assert result is None


def test_pkce_s256_success(code_db):
    """S256 PKCE challenge verifies with correct verifier."""
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )

    code = generate_authorization_code(
        db_path=code_db,
        user_id=1,
        client_id="client1",
        redirect_uri="http://localhost/callback",
        code_challenge=challenge,
        code_challenge_method="S256",
        scope=None,
    )
    result = verify_authorization_code(
        code_db, code, "client1", "http://localhost/callback", verifier
    )
    assert result is not None
    assert result["user_id"] == 1


def test_pkce_s256_failure(code_db):
    """Wrong verifier is rejected."""
    verifier = "correct-verifier"
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )

    code = generate_authorization_code(
        db_path=code_db,
        user_id=1,
        client_id="client1",
        redirect_uri="http://localhost/callback",
        code_challenge=challenge,
        code_challenge_method="S256",
        scope=None,
    )
    result = verify_authorization_code(
        code_db, code, "client1", "http://localhost/callback", "wrong-verifier"
    )
    assert result is None


def test_verify_rejects_code_without_challenge(code_db):
    """OAuth 2.1: code stored without PKCE challenge must be rejected on exchange."""
    code = generate_authorization_code(
        db_path=code_db,
        user_id=1,
        client_id="client1",
        redirect_uri="http://localhost/callback",
        code_challenge=None,
        code_challenge_method=None,
        scope=None,
    )
    # Even if a verifier is supplied, no challenge bound → reject (defense in depth).
    result = verify_authorization_code(
        code_db, code, "client1", "http://localhost/callback", "any-verifier"
    )
    assert result is None


def test_verify_rejects_plain_method(code_db):
    """RFC 7636 §4.2: 'plain' challenge method must not be accepted."""
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    code = generate_authorization_code(
        db_path=code_db,
        user_id=1,
        client_id="client1",
        redirect_uri="http://localhost/callback",
        code_challenge=verifier,  # plain method uses verifier directly
        code_challenge_method="plain",
        scope=None,
    )
    result = verify_authorization_code(
        code_db, code, "client1", "http://localhost/callback", verifier
    )
    assert result is None


def test_cleanup_expired(code_db):
    """Expired and used codes are deleted."""
    # Create an expired code
    generate_authorization_code(
        db_path=code_db,
        user_id=1,
        client_id="client1",
        redirect_uri="http://localhost/callback",
        code_challenge=None,
        code_challenge_method=None,
        scope=None,
        expires_in_seconds=-1,
    )
    # Create a used code
    code2 = generate_authorization_code(
        db_path=code_db,
        user_id=1,
        client_id="client1",
        redirect_uri="http://localhost/callback",
        code_challenge=None,
        code_challenge_method=None,
        scope=None,
    )
    verify_authorization_code(code_db, code2, "client1", "http://localhost/callback", None)

    cleanup_expired_codes(code_db)

    with get_db(code_db, row_factory=None) as conn:
        count = conn.execute("SELECT COUNT(*) FROM authorization_codes").fetchone()[0]
        assert count == 0
