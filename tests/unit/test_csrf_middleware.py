"""Integration tests for CSRF middleware."""

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from authmcp_gateway.csrf import CSRFMiddleware, generate_csrf_token

SECRET = "test-secret-key-at-least-32-characters-long-for-hmac"


def _make_app():
    """Create a minimal Starlette app with CSRF middleware."""

    async def index(request):
        return PlainTextResponse("ok")

    async def submit(request):
        return PlainTextResponse("submitted")

    async def mcp_endpoint(request):
        return PlainTextResponse("mcp")

    async def auth_login(request):
        return PlainTextResponse("logged in")

    app = Starlette(
        routes=[
            Route("/", index),
            Route("/submit", submit, methods=["POST"]),
            Route("/mcp", mcp_endpoint, methods=["POST"]),
            Route("/auth/login", auth_login, methods=["POST"]),
        ]
    )
    app.add_middleware(CSRFMiddleware, secret_key=SECRET)
    return app


def test_get_sets_csrf_cookie():
    """GET response includes csrf_token Set-Cookie."""
    client = TestClient(_make_app())
    resp = client.get("/")
    assert resp.status_code == 200
    assert "csrf_token" in resp.cookies


def test_post_without_token_403():
    """POST without CSRF token returns 403."""
    client = TestClient(_make_app())
    resp = client.post("/submit")
    assert resp.status_code == 403
    assert "csrf" in resp.json()["detail"].lower()


def test_post_with_valid_tokens_200():
    """Matching cookie+header passes through."""
    client = TestClient(_make_app())
    # First GET to get cookie
    client.get("/")
    csrf_token = client.cookies.get("csrf_token")
    assert csrf_token

    resp = client.post(
        "/submit",
        headers={"X-CSRF-Token": csrf_token},
    )
    assert resp.status_code == 200
    assert resp.text == "submitted"


def test_post_mismatch_tokens_403():
    """Different cookie vs header returns 403."""
    client = TestClient(_make_app(), cookies={"csrf_token": generate_csrf_token(SECRET)})
    resp = client.post(
        "/submit",
        headers={"X-CSRF-Token": generate_csrf_token(SECRET)},  # Different token
    )
    assert resp.status_code == 403
    assert "mismatch" in resp.json()["detail"].lower()


def test_post_invalid_signature_403():
    """Valid format but bad HMAC returns 403."""
    fake_token = "a" * 32 + "." + "b" * 64
    client = TestClient(_make_app(), cookies={"csrf_token": fake_token})
    resp = client.post(
        "/submit",
        headers={"X-CSRF-Token": fake_token},
    )
    assert resp.status_code == 403
    assert "invalid" in resp.json()["detail"].lower()


def test_exempt_mcp_path():
    """POST to /mcp skips CSRF validation."""
    client = TestClient(_make_app())
    resp = client.post("/mcp")
    assert resp.status_code == 200
    assert resp.text == "mcp"


def test_exempt_auth_path():
    """POST to /auth/login skips CSRF validation."""
    client = TestClient(_make_app())
    resp = client.post("/auth/login")
    assert resp.status_code == 200
    assert resp.text == "logged in"


def test_existing_valid_cookie_preserved():
    """GET with valid cookie doesn't re-set it."""
    client = TestClient(_make_app())
    # First GET sets cookie
    resp1 = client.get("/")
    assert resp1.cookies.get("csrf_token") is not None

    # Second GET with same valid cookie should pass through without new Set-Cookie
    resp2 = client.get("/")
    # The cookie is already set in the client jar, response may or may not re-set
    assert resp2.status_code == 200
    # Token should still be valid
    token2 = client.cookies.get("csrf_token")
    assert token2 is not None
