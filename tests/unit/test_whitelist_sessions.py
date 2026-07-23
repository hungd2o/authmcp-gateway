"""Regression tests for short-lived Whitelist verification sessions."""

from authmcp_gateway.mcp import store
from test_admin_whitelist import (
    _admin_csrf_headers,
    _create_test_client,
    _login_admin,
)


def _unlock_legacy(client, headers: dict):
    return client.post(
        "/admin/api/whitelist/unlock/legacy", json={"token": "whitelist-secret"}, headers=headers
    )


def test_bootstrap_is_exchanged_for_browser_session(db_path):
    store.init_mcp_database(db_path)
    with _create_test_client(db_path) as client:
        _login_admin(client, db_path)

        assert client.get("/admin/api/whitelist/items").status_code == 401
        unlocked = _unlock_legacy(client, _admin_csrf_headers(client))
        assert unlocked.status_code == 200
        assert unlocked.json()["whitelist_session"]["verified"] is True
        assert client.cookies.get("authmcp_whitelist_session")

        refreshed = client.get("/admin/api/whitelist/items")
        assert refreshed.status_code == 200
        assert refreshed.json()["whitelist_session"]["verified"] is True


def test_lock_revokes_current_browser_session(db_path):
    store.init_mcp_database(db_path)
    with _create_test_client(db_path) as client:
        _login_admin(client, db_path)
        headers = _admin_csrf_headers(client)
        assert _unlock_legacy(client, headers).status_code == 200

        locked = client.post("/admin/api/whitelist/lock", headers=headers)
        assert locked.status_code == 200
        assert client.get("/admin/api/whitelist/items").status_code == 401


def test_action_actor_comes_from_authenticated_admin(db_path):
    store.init_mcp_database(db_path)
    server_id = store.create_mcp_server(
        db_path=db_path,
        name="review-server",
        url="https://example.invalid/mcp",
        transport_type="http",
    )

    with _create_test_client(db_path) as client:
        _login_admin(client, db_path)
        headers = _admin_csrf_headers(client)
        assert _unlock_legacy(client, headers).status_code == 200
        pending = client.get("/admin/api/whitelist/items")
        assert pending.status_code == 200
        server = next(item for item in pending.json()["servers"] if item["id"] == server_id)

        approved = client.post(
            f"/admin/api/whitelist/servers/{server_id}",
            json={
                "action": "approve",
                "actor": "client-supplied-name",
                "config_fingerprint": server["config_fingerprint"],
            },
            headers=headers,
        )
        assert approved.status_code == 200

    saved = store.get_mcp_server(db_path, server_id)
    assert saved["approval_metadata"]["actor"] == "admin"


def test_session_becomes_invalid_when_admin_jti_rotates(db_path):
    """A second login as the same user rotates the admin JWT jti (single-session
    enforcement); the first browser's Whitelist session — bound to the old jti —
    must become unusable even though its cookie is technically still unexpired."""
    store.init_mcp_database(db_path)
    with _create_test_client(db_path) as client, _create_test_client(db_path) as other_client:
        _login_admin(client, db_path)
        headers = _admin_csrf_headers(client)
        assert _unlock_legacy(client, headers).status_code == 200
        assert client.get("/admin/api/whitelist/items").status_code == 200

        # Second login as the same user rotates the stored jti server-side.
        relogin = other_client.post(
            "/admin/api/login", json={"username": "admin", "password": "Password123!"}
        )
        assert relogin.status_code == 200

        assert client.get("/admin/api/whitelist/items").status_code == 401


def test_whitelist_admin_can_view_env_vars_and_auth_token(db_path):
    store.init_mcp_database(db_path)
    from authmcp_gateway.mcp.crypto import initialize_crypto

    initialize_crypto("test-secret-key-at-least-32-characters-long-for-hmac")
    server_id = store.create_mcp_server(
        db_path=db_path,
        name="secret-server",
        url="",
        transport_type="stdio",
        command="python",
        auth_token="super-secret-token",
        env_vars={"API_KEY": "super-secret-env-value"},
    )
    store.update_server_approval(
        db_path,
        server_id=server_id,
        approval_state="approved",
        actor="admin",
        expected_fingerprint=None,
    )

    with _create_test_client(db_path) as client:
        _login_admin(client, db_path)
        headers = _admin_csrf_headers(client)
        assert _unlock_legacy(client, headers).status_code == 200

        response = client.get("/admin/api/whitelist/items")
        assert response.status_code == 200
        body = response.text
        assert "super-secret-token" in body
        assert "super-secret-env-value" in body
        server = next(item for item in response.json()["servers"] if item["id"] == server_id)
        assert server["env_vars"]["API_KEY"] == "super-secret-env-value"
        assert server["auth_token"] == "super-secret-token"


def test_high_risk_server_approval_fails_closed_until_passkey_authorization(db_path):
    store.init_mcp_database(db_path)
    server_id = store.create_mcp_server(
        db_path=db_path,
        name="high-risk-server",
        url="",
        transport_type="stdio",
        command="python",
    )

    with _create_test_client(db_path) as client:
        _login_admin(client, db_path)
        headers = _admin_csrf_headers(client)
        assert _unlock_legacy(client, headers).status_code == 200
        server = next(
            item
            for item in client.get("/admin/api/whitelist/items").json()["servers"]
            if item["id"] == server_id
        )

        response = client.post(
            f"/admin/api/whitelist/servers/{server_id}",
            json={"action": "approve", "config_fingerprint": server["config_fingerprint"]},
            headers=headers,
        )

    assert response.status_code == 403
    assert response.json()["code"] == "fresh_authorization_required"


def test_virtual_tool_approval_requires_current_fingerprint(db_path):
    store.init_mcp_database(db_path)
    server_id = store.create_mcp_server(
        db_path=db_path,
        name="source-server",
        url="https://example.invalid/mcp",
        transport_type="http",
    )
    tool_id = store.create_virtual_tool(
        db_path, server_id, "safe-call", "", "http_call", {"url": "https://example.invalid"}
    )

    with _create_test_client(db_path) as client:
        _login_admin(client, db_path)
        headers = _admin_csrf_headers(client)
        assert _unlock_legacy(client, headers).status_code == 200
        tool = next(
            item
            for item in client.get("/admin/api/whitelist/items").json()["virtual_tools"]
            if item["id"] == tool_id
        )

        stale = client.post(
            f"/admin/api/whitelist/virtual-tools/{tool_id}",
            json={"action": "approve", "config_fingerprint": "stale"},
            headers=headers,
        )
        approved = client.post(
            f"/admin/api/whitelist/virtual-tools/{tool_id}",
            json={"action": "approve", "config_fingerprint": tool["config_fingerprint"]},
            headers=headers,
        )

    assert stale.status_code == 403
    assert approved.status_code == 403
