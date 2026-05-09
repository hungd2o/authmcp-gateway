"""Pure ASGI tests for McpAuthMiddleware + ContentTypeFixMiddleware.

These tests don't spin up Starlette or uvicorn — they invoke the
middleware's ``__call__(scope, receive, send)`` directly and inspect
which messages reach the wrapped inner app vs which 401/403 short-circuit
before the inner app is called.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

import jwt as pyjwt
import pytest

from authmcp_gateway import middleware as mw
from authmcp_gateway.config import JWTConfig

# ---------------------------------------------------------------------------
# ASGI test harness
# ---------------------------------------------------------------------------


class _RecordingApp:
    """Inner ASGI app that records whether it was called and lets tests
    drive a stub response back through `send`."""

    def __init__(self, status: int = 200, body: bytes = b'{"ok": true}'):
        self.called = False
        self.status = status
        self.body = body

    async def __call__(self, scope, receive, send):
        self.called = True
        await send(
            {
                "type": "http.response.start",
                "status": self.status,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": self.body, "more_body": False})


def _make_scope(
    *,
    path: str = "/mcp",
    method: str = "POST",
    headers: dict | None = None,
    client_host: str = "127.0.0.1",
) -> dict:
    raw_headers = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    return {
        "type": "http",
        "method": method,
        "path": path,
        "headers": raw_headers,
        "client": (client_host, 12345),
    }


async def _drive(middleware, scope, body: bytes = b"") -> List[Dict[str, Any]]:
    """Run the middleware against a scope+body and return all messages it
    sent back through `send`."""
    sent_messages: List[Dict[str, Any]] = []
    body_consumed = False

    async def receive():
        nonlocal body_consumed
        if body_consumed:
            return {"type": "http.disconnect"}
        body_consumed = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        sent_messages.append(message)

    await middleware(scope, receive, send)
    return sent_messages


def _status_of(messages: List[Dict[str, Any]]) -> int | None:
    for msg in messages:
        if msg.get("type") == "http.response.start":
            return msg.get("status")
    return None


def _body_of(messages: List[Dict[str, Any]]) -> bytes:
    return b"".join(m.get("body", b"") for m in messages if m.get("type") == "http.response.body")


def _header(messages: List[Dict[str, Any]], name: str) -> str | None:
    """Return the value of a response header (case-insensitive), or None."""
    name_lower = name.lower().encode()
    for msg in messages:
        if msg.get("type") == "http.response.start":
            for k, v in msg.get("headers", []):
                if k.lower() == name_lower:
                    return v.decode("utf-8", errors="ignore")
    return None


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def jwt_cfg() -> JWTConfig:
    return JWTConfig(
        algorithm="HS256",
        secret_key="test-secret-key-at-least-32-characters-long-for-hmac",
        access_token_expire_minutes=30,
        enforce_single_session=False,
    )


@pytest.fixture
def auth_middleware(initialized_db, jwt_cfg):
    """Build McpAuthMiddleware around a recording inner app, with the
    middleware globals reset to a known state."""
    inner = _RecordingApp()
    mw.set_middleware_config(
        static_bearer_tokens=set(),
        trusted_ips=set(),
        allowed_origins=set(),
        auth_required=True,
        streamable_path="/mcp",
    )
    middleware = mw.McpAuthMiddleware(
        app=inner,
        jwt_config=jwt_cfg,
        auth_db_path=initialized_db,
        mcp_public_url="https://mcp.example.com",
        oauth_scopes="openid profile email",
    )
    return middleware, inner


def _make_jwt(
    jwt_cfg: JWTConfig,
    *,
    sub: str = "1",
    typ: str = "access",
    jti: str = "test-jti",
    extra: dict | None = None,
) -> str:
    from datetime import datetime, timedelta, timezone

    payload = {
        "sub": sub,
        "username": "alice",
        "type": typ,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        "jti": jti,
    }
    if extra:
        payload.update(extra)
    return pyjwt.encode(payload, jwt_cfg.secret_key, algorithm="HS256")


# ---------------------------------------------------------------------------
# McpAuthMiddleware
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_websocket_scope_passes_through(auth_middleware):
    middleware, inner = auth_middleware
    scope = {"type": "websocket"}

    async def receive():
        return {"type": "websocket.connect"}

    async def send(_msg):
        pass

    await middleware(scope, receive, send)
    assert inner.called is True


@pytest.mark.asyncio
async def test_well_known_path_bypasses_auth(auth_middleware):
    """`/.well-known/...` is the OAuth discovery endpoint — must not require auth."""
    middleware, inner = auth_middleware
    messages = await _drive(
        middleware, _make_scope(path="/.well-known/oauth-authorization-server", method="GET")
    )
    assert inner.called is True
    assert _status_of(messages) == 200


@pytest.mark.asyncio
async def test_health_path_bypasses_auth(auth_middleware):
    middleware, inner = auth_middleware
    messages = await _drive(middleware, _make_scope(path="/health", method="GET"))
    assert inner.called is True
    assert _status_of(messages) == 200


@pytest.mark.asyncio
async def test_admin_path_bypasses_mcp_auth(auth_middleware):
    """Admin paths have their own AdminAuthMiddleware — McpAuthMiddleware must skip them."""
    middleware, inner = auth_middleware
    messages = await _drive(middleware, _make_scope(path="/admin/users", method="GET"))
    assert inner.called is True
    assert _status_of(messages) == 200


@pytest.mark.asyncio
async def test_disallowed_origin_returns_403(auth_middleware):
    middleware, inner = auth_middleware
    mw.set_middleware_config(
        static_bearer_tokens=set(),
        trusted_ips=set(),
        allowed_origins={"https://allowed.example.com"},
        auth_required=True,
        streamable_path="/mcp",
    )
    messages = await _drive(
        middleware,
        _make_scope(headers={"origin": "https://attacker.example.com"}),
    )
    assert _status_of(messages) == 403
    assert inner.called is False


@pytest.mark.asyncio
async def test_auth_required_false_passes_through(auth_middleware):
    """Global toggle: auth_required=False bypasses every other gate."""
    middleware, inner = auth_middleware
    mw.set_middleware_config(
        static_bearer_tokens=set(),
        trusted_ips=set(),
        allowed_origins=set(),
        auth_required=False,
        streamable_path="/mcp",
    )
    messages = await _drive(
        middleware,
        _make_scope(path="/mcp"),
        body=json.dumps({"jsonrpc": "2.0", "method": "tools/call", "id": 1}).encode(),
    )
    assert inner.called is True
    assert _status_of(messages) == 200


@pytest.mark.asyncio
async def test_mcp_endpoint_without_token_returns_401(auth_middleware):
    """`/mcp` (gateway endpoint) requires a bearer token — no token → 401."""
    middleware, inner = auth_middleware
    messages = await _drive(
        middleware,
        _make_scope(path="/mcp"),
        body=json.dumps({"jsonrpc": "2.0", "method": "tools/list", "id": 1}).encode(),
    )
    assert _status_of(messages) == 401
    assert inner.called is False
    assert _header(messages, "WWW-Authenticate") is not None
    assert 'resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"' in (
        _header(messages, "WWW-Authenticate") or ""
    )


@pytest.mark.asyncio
async def test_mcp_endpoint_with_valid_jwt_passes_through(auth_middleware, jwt_cfg):
    """A valid access JWT lets the request through to the inner app."""
    middleware, inner = auth_middleware
    token = _make_jwt(jwt_cfg)
    messages = await _drive(
        middleware,
        _make_scope(
            path="/mcp",
            headers={"authorization": f"Bearer {token}"},
        ),
        body=json.dumps({"jsonrpc": "2.0", "method": "ping", "id": 1}).encode(),
    )
    assert inner.called is True
    assert _status_of(messages) == 200


@pytest.mark.asyncio
async def test_static_bearer_token_accepted(auth_middleware):
    """Configured static bearer tokens bypass JWT verification."""
    middleware, inner = auth_middleware
    mw.set_middleware_config(
        static_bearer_tokens={"static-secret"},
        trusted_ips=set(),
        allowed_origins=set(),
        auth_required=True,
        streamable_path="/mcp",
    )
    messages = await _drive(
        middleware,
        _make_scope(
            path="/mcp",
            headers={"authorization": "Bearer static-secret"},
        ),
        body=json.dumps({"jsonrpc": "2.0", "method": "ping", "id": 1}).encode(),
    )
    assert inner.called is True
    assert _status_of(messages) == 200


@pytest.mark.asyncio
async def test_blacklisted_jwt_returns_401(auth_middleware, jwt_cfg, initialized_db):
    """A JTI that's been blacklisted (e.g. via /auth/logout) returns 401."""
    from datetime import datetime, timedelta, timezone

    from authmcp_gateway.auth.user_store import blacklist_token

    jti = "blacklisted-jti"
    token = _make_jwt(jwt_cfg, jti=jti)
    blacklist_token(initialized_db, jti, datetime.now(timezone.utc) + timedelta(hours=2))

    middleware, inner = auth_middleware
    messages = await _drive(
        middleware,
        _make_scope(
            path="/mcp",
            headers={"authorization": f"Bearer {token}"},
        ),
        body=json.dumps({"jsonrpc": "2.0", "method": "ping", "id": 1}).encode(),
    )
    assert _status_of(messages) == 401
    assert inner.called is False


@pytest.mark.asyncio
async def test_invalid_jwt_at_gateway_returns_401(auth_middleware):
    """Garbage in the Authorization header ⇒ 401 at /mcp gateway."""
    middleware, inner = auth_middleware
    messages = await _drive(
        middleware,
        _make_scope(path="/mcp", headers={"authorization": "Bearer not.a.jwt"}),
        body=json.dumps({"jsonrpc": "2.0", "method": "ping", "id": 1}).encode(),
    )
    assert _status_of(messages) == 401
    assert inner.called is False


@pytest.mark.asyncio
async def test_server_specific_tools_call_without_token_returns_401(auth_middleware):
    """`tools/call` on `/mcp/<server>` requires a token even though `initialize` doesn't."""
    middleware, inner = auth_middleware
    messages = await _drive(
        middleware,
        _make_scope(path="/mcp/github", method="POST"),
        body=json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "do_thing", "arguments": {}},
                "id": 1,
            }
        ).encode(),
    )
    assert _status_of(messages) == 401
    assert inner.called is False


@pytest.mark.asyncio
async def test_server_specific_initialize_without_token_passes_through(auth_middleware):
    """`initialize` is allowed pre-auth on per-server endpoints (handshake)."""
    middleware, inner = auth_middleware
    messages = await _drive(
        middleware,
        _make_scope(path="/mcp/github"),
        body=json.dumps({"jsonrpc": "2.0", "method": "initialize", "id": 1}).encode(),
    )
    assert inner.called is True
    assert _status_of(messages) == 200


@pytest.mark.asyncio
async def test_trusted_ip_bypasses_token_for_tools_call(auth_middleware):
    """An IP in trusted_ips can skip auth on per-server endpoints (e.g. localhost service mesh)."""
    middleware, inner = auth_middleware
    mw.set_middleware_config(
        static_bearer_tokens=set(),
        trusted_ips={"10.0.0.1"},
        allowed_origins=set(),
        auth_required=True,
        streamable_path="/mcp",
    )
    messages = await _drive(
        middleware,
        _make_scope(path="/mcp/github", client_host="10.0.0.1"),
        body=json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "x", "arguments": {}},
                "id": 1,
            }
        ).encode(),
    )
    assert inner.called is True
    assert _status_of(messages) == 200


# ---------------------------------------------------------------------------
# tools/list response interception (securitySchemes injection)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tools_list_response_gets_security_schemes_injected(jwt_cfg, initialized_db):
    """The middleware buffers the tools/list response and adds an oauth2
    securitySchemes entry to every tool. Authenticated request, so the
    middleware lets it through and only the response transformation is
    under test."""
    inner_body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "get_repo"}, {"name": "list_issues"}]},
        }
    ).encode()
    inner = _RecordingApp(body=inner_body)

    mw.set_middleware_config(
        static_bearer_tokens={"static-secret"},
        trusted_ips=set(),
        allowed_origins=set(),
        auth_required=True,
        streamable_path="/mcp",
    )
    middleware = mw.McpAuthMiddleware(
        app=inner,
        jwt_config=jwt_cfg,
        auth_db_path=initialized_db,
        mcp_public_url="https://mcp.example.com",
        oauth_scopes="openid profile email",
    )

    messages = await _drive(
        middleware,
        _make_scope(
            path="/mcp",
            headers={
                "authorization": "Bearer static-secret",
                "content-type": "application/json",
            },
        ),
        body=json.dumps({"jsonrpc": "2.0", "method": "tools/list", "id": 1}).encode(),
    )
    assert inner.called is True
    assert _status_of(messages) == 200

    out = json.loads(_body_of(messages))
    tools = out["result"]["tools"]
    assert all("securitySchemes" in t for t in tools)
    assert tools[0]["securitySchemes"][0]["type"] == "oauth2"
    assert "openid" in tools[0]["securitySchemes"][0]["scopes"]


# ---------------------------------------------------------------------------
# ContentTypeFixMiddleware
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_content_type_fix_rewrites_octet_stream():
    """POST /mcp with application/octet-stream is rewritten to application/json."""
    inner = _RecordingApp()
    middleware = mw.ContentTypeFixMiddleware(inner)
    mw.set_middleware_config(
        static_bearer_tokens=set(),
        trusted_ips=set(),
        allowed_origins=set(),
        auth_required=True,
        streamable_path="/mcp",
    )

    captured_scope: dict = {}

    class _Capture:
        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            captured_scope.update(scope)
            await self.app(scope, receive, send)

    middleware.app = _Capture(inner)

    await _drive(
        middleware,
        _make_scope(
            path="/mcp",
            method="POST",
            headers={"content-type": "application/octet-stream; charset=utf-8"},
        ),
    )
    assert inner.called is True
    rewritten = next(
        (v for k, v in captured_scope["headers"] if k.lower() == b"content-type"), None
    )
    assert rewritten == b"application/json"


@pytest.mark.asyncio
async def test_content_type_fix_passes_through_non_mcp_path():
    inner = _RecordingApp()
    middleware = mw.ContentTypeFixMiddleware(inner)

    await _drive(
        middleware,
        _make_scope(
            path="/auth/login",
            method="POST",
            headers={"content-type": "application/octet-stream"},
        ),
    )
    assert inner.called is True


@pytest.mark.asyncio
async def test_content_type_fix_passes_through_websocket_scope():
    inner = _RecordingApp()
    middleware = mw.ContentTypeFixMiddleware(inner)

    async def receive():
        return {"type": "websocket.connect"}

    async def send(_msg):
        pass

    await middleware({"type": "websocket"}, receive, send)
    assert inner.called is True
