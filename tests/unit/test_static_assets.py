"""Tests for static asset availability across local hostnames."""

from pathlib import Path

from starlette.testclient import TestClient

from authmcp_gateway.app import create_app
from authmcp_gateway.config import AppConfig, AuthConfig, JWTConfig, RateLimitConfig


def _build_client(db_path: str) -> TestClient:
    settings_path = Path(db_path).parent / "auth_settings.json"
    settings_path.write_text('{"system":{"allow_registration":false,"allow_dcr":false}}')
    config = AppConfig(
        jwt=JWTConfig(algorithm="HS256", secret_key="test-secret-key-at-least-32-characters-long"),
        auth=AuthConfig(sqlite_path=db_path, allow_registration=False, allow_dcr=False),
        rate_limit=RateLimitConfig(enabled=False),
        mcp_public_url="http://localhost:8000",
    )
    return TestClient(create_app(config))


def test_tailwind_stylesheet_served(db_path):
    with _build_client(db_path) as client:
        response = client.get("/static/tailwind.css")
    assert response.status_code == 200
    assert "text/css" in response.headers.get("content-type", "")
    assert len(response.text) > 0


def test_admin_login_and_static_work_for_localhost_and_loopback(db_path):
    with _build_client(db_path) as client:
        for host in ("localhost:8000", "127.0.0.1:8000"):
            login = client.get("/admin/login", headers={"host": host})
            css = client.get("/static/tailwind.css", headers={"host": host})
            assert login.status_code == 200
            assert css.status_code == 200
