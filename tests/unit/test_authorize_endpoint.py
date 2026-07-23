"""Tests for /authorize endpoint PKCE enforcement (OAuth 2.1 + RFC 7636)."""

import json
from pathlib import Path

from starlette.testclient import TestClient

from authmcp_gateway.app import create_app
from authmcp_gateway.config import (
    AppConfig,
    AuthConfig,
    JWTConfig,
    RateLimitConfig,
    WhitelistAuthConfig,
)


def _create_test_client(db_path: str) -> TestClient:
    settings_path = Path(db_path).parent / "auth_settings.json"
    settings_path.write_text(
        json.dumps(
            {
                "system": {
                    "allow_registration": False,
                    "allow_dcr": False,
                    "auth_required": True,
                }
            }
        )
    )
    config = AppConfig(
        jwt=JWTConfig(
            algorithm="HS256",
            secret_key="test-secret-key-at-least-32-characters-long-for-hmac",
        ),
        auth=AuthConfig(sqlite_path=db_path, allow_registration=False, allow_dcr=False),
        rate_limit=RateLimitConfig(enabled=False),
        mcp_public_url="http://localhost:8000",
        auth_required=True,
        whitelist_auth=WhitelistAuthConfig(
            credential_encryption_key="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
        ),
    )
    app = create_app(config)
    return TestClient(app)


def _base_params() -> dict:
    return {
        "response_type": "code",
        "client_id": "https://example.com/app",
        "redirect_uri": "https://example.com/cb",
        "state": "xyz",
        "scope": "openid",
    }


def _patch_cimd_pass(monkeypatch):
    """Stub CIMD fetch so happy-path tests don't hit the network.

    The stub returns metadata that lists the request's redirect_uri.
    """
    from authmcp_gateway.auth import authorize_endpoint as ae

    def _stub(url):
        return {
            "client_id": url,
            "client_name": "Test",
            "redirect_uris": ["https://example.com/cb"],
        }

    monkeypatch.setattr(ae, "fetch_client_metadata", _stub)


def test_authorize_rejects_missing_code_challenge(db_path):
    """OAuth 2.1: /authorize must reject requests without code_challenge."""
    with _create_test_client(db_path) as client:
        params = _base_params()
        # No code_challenge in params
        response = client.get("/authorize", params=params)
        assert response.status_code == 400
        assert "code_challenge" in response.text.lower() or "pkce" in response.text.lower()


def test_authorize_rejects_plain_method(db_path):
    """RFC 7636 §4.2: /authorize must reject code_challenge_method=plain."""
    with _create_test_client(db_path) as client:
        params = _base_params()
        params["code_challenge"] = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        params["code_challenge_method"] = "plain"
        response = client.get("/authorize", params=params)
        assert response.status_code == 400
        assert "s256" in response.text.lower() or "plain" in response.text.lower()


def test_authorize_accepts_s256_challenge(db_path, monkeypatch):
    """Happy path: /authorize with valid S256 challenge proceeds to login form."""
    _patch_cimd_pass(monkeypatch)
    with _create_test_client(db_path) as client:
        params = _base_params()
        params["code_challenge"] = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        params["code_challenge_method"] = "S256"
        response = client.get("/authorize", params=params)
        # Either renders login form (200) or redirects to login (302)
        assert response.status_code in (200, 302)


# --- Scope allowlist (S6 / OAuth 2.1 §3.3) ---


def _params_with_pkce() -> dict:
    p = _base_params()
    p["code_challenge"] = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    p["code_challenge_method"] = "S256"
    return p


def test_authorize_rejects_unknown_scope(db_path):
    """OAuth 2.1: /authorize must reject scopes not in the server allowlist."""
    with _create_test_client(db_path) as client:
        params = _params_with_pkce()
        params["scope"] = "admin:everything"
        response = client.get("/authorize", params=params)
        assert response.status_code == 400
        assert "scope" in response.text.lower()


def test_authorize_rejects_partially_unknown_scope(db_path):
    """A request mixing valid and unknown scopes must be rejected entirely."""
    with _create_test_client(db_path) as client:
        params = _params_with_pkce()
        params["scope"] = "openid admin:everything"
        response = client.get("/authorize", params=params)
        assert response.status_code == 400
        assert "scope" in response.text.lower()


def test_authorize_accepts_subset_of_default_scopes(db_path, monkeypatch):
    """Single allowlisted scope passes validation."""
    _patch_cimd_pass(monkeypatch)
    with _create_test_client(db_path) as client:
        params = _params_with_pkce()
        params["scope"] = "openid"
        response = client.get("/authorize", params=params)
        assert response.status_code in (200, 302)


def test_authorize_accepts_all_default_scopes(db_path, monkeypatch):
    """All advertised default scopes pass validation."""
    _patch_cimd_pass(monkeypatch)
    with _create_test_client(db_path) as client:
        params = _params_with_pkce()
        params["scope"] = "openid profile email offline_access"
        response = client.get("/authorize", params=params)
        assert response.status_code in (200, 302)


# --- URL-based client_id via CIMD (S7 / MCP authorization spec) ---


def test_authorize_url_client_id_without_path_rejected(db_path):
    """A URL client_id without a path component is not a valid CIMD identifier."""
    with _create_test_client(db_path) as client:
        params = _params_with_pkce()
        params["client_id"] = "https://example.com"
        params["redirect_uri"] = "https://example.com/cb"
        response = client.get("/authorize", params=params)
        assert response.status_code == 400


def test_authorize_url_client_id_with_valid_cimd_accepts(db_path, monkeypatch):
    """When CIMD fetch returns valid metadata listing the redirect_uri, accept."""
    from authmcp_gateway.auth import authorize_endpoint as ae

    valid_metadata = {
        "client_id": "https://example.com/oauth/client.json",
        "client_name": "Test",
        "redirect_uris": ["https://example.com/oauth/cb"],
    }
    monkeypatch.setattr(ae, "fetch_client_metadata", lambda url: valid_metadata)

    with _create_test_client(db_path) as client:
        params = _params_with_pkce()
        params["client_id"] = "https://example.com/oauth/client.json"
        params["redirect_uri"] = "https://example.com/oauth/cb"
        response = client.get("/authorize", params=params)
        assert response.status_code in (200, 302)


def test_authorize_url_client_id_redirect_uri_not_in_metadata_rejected(db_path, monkeypatch):
    """If redirect_uri is not in CIMD metadata.redirect_uris, reject."""
    from authmcp_gateway.auth import authorize_endpoint as ae

    valid_metadata = {
        "client_id": "https://example.com/oauth/client.json",
        "client_name": "Test",
        "redirect_uris": ["https://example.com/oauth/cb"],
    }
    monkeypatch.setattr(ae, "fetch_client_metadata", lambda url: valid_metadata)

    with _create_test_client(db_path) as client:
        params = _params_with_pkce()
        params["client_id"] = "https://example.com/oauth/client.json"
        params["redirect_uri"] = "https://example.com/EVIL"
        response = client.get("/authorize", params=params)
        assert response.status_code == 400


def test_authorize_url_client_id_failed_cimd_fetch_rejected(db_path, monkeypatch):
    """If CIMD fetch fails (CIMDError), authorize must reject — no fallback to looser checks."""
    from authmcp_gateway.auth import authorize_endpoint as ae
    from authmcp_gateway.auth.cimd import CIMDError

    def _raise(_url):
        raise CIMDError("metadata document is not valid JSON")

    monkeypatch.setattr(ae, "fetch_client_metadata", _raise)

    with _create_test_client(db_path) as client:
        params = _params_with_pkce()
        params["client_id"] = "https://example.com/oauth/client.json"
        params["redirect_uri"] = "https://example.com/oauth/cb"
        response = client.get("/authorize", params=params)
        assert response.status_code == 400
