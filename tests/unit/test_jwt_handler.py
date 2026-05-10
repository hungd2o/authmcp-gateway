"""Tests for JWT token creation and verification."""

import jwt as pyjwt
import pytest

from authmcp_gateway.auth.jwt_handler import (
    create_access_token,
    create_refresh_token,
    decode_token_unsafe,
    get_token_jti,
    verify_token,
)
from authmcp_gateway.config import JWTConfig


def test_create_access_token(jwt_config):
    """Access token has correct claims."""
    token = create_access_token(1, "alice", False, jwt_config)
    payload = decode_token_unsafe(token)
    assert payload["sub"] == "1"
    assert payload["username"] == "alice"
    assert payload["is_superuser"] is False
    assert payload["type"] == "access"
    assert "exp" in payload
    assert "iat" in payload
    assert "jti" in payload


def test_create_access_token_custom_ttl(jwt_config):
    """expire_minutes override works."""
    token = create_access_token(1, "alice", False, jwt_config, expire_minutes=5)
    payload = decode_token_unsafe(token)
    # exp - iat should be ~300 seconds
    diff = payload["exp"] - payload["iat"]
    assert 290 <= diff <= 310


def test_create_refresh_token(jwt_config):
    """Refresh token has type=refresh and correct expiration."""
    token = create_refresh_token(1, jwt_config)
    payload = decode_token_unsafe(token)
    assert payload["sub"] == "1"
    assert payload["type"] == "refresh"
    # Default 7 days = 604800 seconds
    diff = payload["exp"] - payload["iat"]
    assert diff >= 600000  # at least ~6.9 days


def test_verify_access_token(jwt_config):
    """Valid access token verifies correctly."""
    token = create_access_token(1, "alice", True, jwt_config)
    payload = verify_token(token, "access", jwt_config)
    assert payload["sub"] == "1"
    assert payload["username"] == "alice"
    assert payload["is_superuser"] is True


def test_verify_wrong_type_rejected(jwt_config):
    """Access token rejected when expecting refresh."""
    token = create_access_token(1, "alice", False, jwt_config)
    with pytest.raises(ValueError, match="Invalid token type"):
        verify_token(token, "refresh", jwt_config)


def test_verify_expired_token(jwt_config):
    """Expired token raises ExpiredSignatureError."""
    token = create_access_token(1, "alice", False, jwt_config, expire_minutes=-1)
    with pytest.raises(pyjwt.ExpiredSignatureError):
        verify_token(token, "access", jwt_config)


def test_verify_invalid_signature():
    """Tampered token raises InvalidTokenError."""
    config1 = JWTConfig(algorithm="HS256", secret_key="secret-key-one-at-least-32-characters")
    config2 = JWTConfig(algorithm="HS256", secret_key="secret-key-two-at-least-32-characters")
    token = create_access_token(1, "alice", False, config1)
    with pytest.raises(pyjwt.InvalidSignatureError):
        verify_token(token, "access", config2)


def test_decode_token_unsafe(jwt_config):
    """Decodes token without signature verification."""
    token = create_access_token(1, "alice", False, jwt_config)
    payload = decode_token_unsafe(token)
    assert payload["sub"] == "1"
    assert payload["type"] == "access"


def test_get_token_jti(jwt_config):
    """Extracts JTI from token."""
    token = create_access_token(1, "alice", False, jwt_config)
    jti = get_token_jti(token)
    assert isinstance(jti, str)
    assert len(jti) > 0


def test_unsupported_algorithm():
    """ValueError for unknown algorithm."""
    with pytest.raises(ValueError, match="Unsupported JWT algorithm"):
        JWTConfig(algorithm="UNKNOWN", secret_key="test-key")


def test_access_token_has_jti(jwt_config):
    """Every access token gets a JTI."""
    token = create_access_token(1, "alice", False, jwt_config)
    payload = decode_token_unsafe(token)
    assert "jti" in payload
    assert len(payload["jti"]) > 0


def test_different_tokens_have_different_jti(jwt_config):
    """JTIs are unique across tokens."""
    t1 = create_access_token(1, "alice", False, jwt_config)
    t2 = create_access_token(1, "alice", False, jwt_config)
    assert get_token_jti(t1) != get_token_jti(t2)
