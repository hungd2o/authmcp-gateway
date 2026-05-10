"""Tests for private helpers in auth/endpoints.py.

Pre-refactor characterization tests for `_get_token_ttl`,
`_get_password_policy`, and `_parse_basic_auth`. The point is to lock the
fallback semantics in place before narrowing the broad ``except Exception``
catches in those helpers.
"""

from __future__ import annotations

import base64
import json

import pytest
from starlette.requests import Request

from authmcp_gateway.auth import endpoints as ep
from authmcp_gateway.config import AppConfig, AuthConfig, JWTConfig, RateLimitConfig
from authmcp_gateway.settings_manager import initialize_settings

# ---------- shared fixtures ----------


@pytest.fixture
def app_config() -> AppConfig:
    return AppConfig(
        jwt=JWTConfig(
            algorithm="HS256",
            secret_key="test-secret-key-at-least-32-characters-long-for-hmac",
            access_token_expire_minutes=42,
            refresh_token_expire_days=11,
        ),
        auth=AuthConfig(
            sqlite_path=":memory:",
            password_min_length=9,
            password_require_special=False,
        ),
        rate_limit=RateLimitConfig(enabled=False),
        mcp_public_url="http://localhost:8000",
    )


@pytest.fixture
def reset_settings():
    """Ensure each test starts with no global SettingsManager."""
    import authmcp_gateway.settings_manager as sm

    sm._settings_manager = None
    yield
    sm._settings_manager = None


def _make_request(headers: dict) -> Request:
    """Build a minimal Starlette Request carrying *headers*."""
    raw_headers = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    scope = {"type": "http", "method": "GET", "headers": raw_headers}
    return Request(scope)


# ---------- _get_token_ttl ----------


def test_get_token_ttl_uses_settings_when_initialized(tmp_path, reset_settings, app_config):
    settings_path = tmp_path / "auth_settings.json"
    settings_path.write_text(
        json.dumps({"jwt": {"access_token_expire_minutes": 99, "refresh_token_expire_days": 55}})
    )
    initialize_settings(str(settings_path))

    access_ttl, refresh_ttl = ep._get_token_ttl(app_config)
    assert access_ttl == 99
    assert refresh_ttl == 55


def test_get_token_ttl_falls_back_to_config_when_settings_not_initialized(
    reset_settings, app_config
):
    """RuntimeError from get_settings_manager() must fall through to AppConfig."""
    access_ttl, refresh_ttl = ep._get_token_ttl(app_config)
    assert access_ttl == 42
    assert refresh_ttl == 11


# ---------- _get_password_policy ----------


def test_get_password_policy_uses_settings_when_initialized(tmp_path, reset_settings, app_config):
    settings_path = tmp_path / "auth_settings.json"
    settings_path.write_text(
        json.dumps({"password_policy": {"min_length": 16, "require_uppercase": False}})
    )
    initialize_settings(str(settings_path))

    policy = ep._get_password_policy(app_config)
    assert policy.password_min_length == 16
    assert policy.password_require_uppercase is False
    # untouched fields should keep AppConfig defaults
    assert policy.password_require_special is False


def test_get_password_policy_falls_back_to_config_when_settings_not_initialized(
    reset_settings, app_config
):
    policy = ep._get_password_policy(app_config)
    # When falling back we expect the AuthConfig instance from app_config.auth
    assert policy is app_config.auth


# ---------- _parse_basic_auth ----------


def _basic(value: str) -> str:
    return "Basic " + base64.b64encode(value.encode("utf-8")).decode("ascii")


def test_parse_basic_auth_returns_credentials_for_valid_header():
    req = _make_request({"authorization": _basic("alice:s3cret")})
    assert ep._parse_basic_auth(req) == ("alice", "s3cret")


def test_parse_basic_auth_returns_credentials_when_password_contains_colons():
    req = _make_request({"authorization": _basic("alice:s3cr:et:with:colons")})
    assert ep._parse_basic_auth(req) == ("alice", "s3cr:et:with:colons")


def test_parse_basic_auth_returns_none_when_header_missing():
    req = _make_request({})
    assert ep._parse_basic_auth(req) == (None, None)


def test_parse_basic_auth_returns_none_for_non_basic_scheme():
    req = _make_request({"authorization": "Bearer xxx"})
    assert ep._parse_basic_auth(req) == (None, None)


def test_parse_basic_auth_returns_none_for_malformed_base64():
    req = _make_request({"authorization": "Basic !!!not-base64!!!"})
    assert ep._parse_basic_auth(req) == (None, None)


def test_parse_basic_auth_returns_none_when_no_colon_separator():
    req = _make_request({"authorization": _basic("nocolonhere")})
    assert ep._parse_basic_auth(req) == (None, None)


def test_parse_basic_auth_returns_none_for_invalid_utf8():
    """A base64 payload that decodes to non-UTF-8 bytes must not raise."""
    raw = base64.b64encode(b"\xff\xfe\xfd").decode("ascii")
    req = _make_request({"authorization": "Basic " + raw})
    assert ep._parse_basic_auth(req) == (None, None)
