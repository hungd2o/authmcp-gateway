"""Tests for admin auth middleware behavior."""

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from authmcp_gateway.admin_auth import AdminAuthMiddleware
from authmcp_gateway.config import AppConfig, AuthConfig, JWTConfig, RateLimitConfig


def _build_app(db_path: str) -> Starlette:
    config = AppConfig(
        jwt=JWTConfig(algorithm="HS256", secret_key="test-secret-key-at-least-32-characters-long"),
        auth=AuthConfig(sqlite_path=db_path),
        rate_limit=RateLimitConfig(enabled=False),
        mcp_public_url="http://localhost:8000",
    )

    async def admin_page(_):
        return PlainTextResponse("admin")

    async def admin_api(_):
        return PlainTextResponse("api")

    async def login_page(_):
        return PlainTextResponse("login")

    app = Starlette(
        routes=[
            Route("/admin", admin_page),
            Route("/admin/api/protected", admin_api),
            Route("/admin/login", login_page),
            Route("/admin/api/login", login_page, methods=["POST"]),
        ]
    )
    app.add_middleware(AdminAuthMiddleware, config=config)
    return app


def test_invalid_admin_cookie_redirect_clears_cookie(db_path, monkeypatch):
    monkeypatch.setattr("authmcp_gateway.admin_auth.is_setup_required", lambda _: False)

    with TestClient(_build_app(db_path)) as client:
        response = client.get("/admin", cookies={"admin_token": "invalid.jwt.token"}, follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["location"] == "/admin/login"
    set_cookie = response.headers.get("set-cookie", "")
    assert "admin_token=" in set_cookie
    assert "Max-Age=0" in set_cookie


def test_invalid_admin_cookie_api_401_clears_cookie(db_path, monkeypatch):
    monkeypatch.setattr("authmcp_gateway.admin_auth.is_setup_required", lambda _: False)

    with TestClient(_build_app(db_path)) as client:
        response = client.get(
            "/admin/api/protected",
            cookies={"admin_token": "invalid.jwt.token"},
            follow_redirects=False,
        )

    assert response.status_code == 401
    set_cookie = response.headers.get("set-cookie", "")
    assert "admin_token=" in set_cookie
    assert "Max-Age=0" in set_cookie
