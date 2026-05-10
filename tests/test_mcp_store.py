"""Tests for `mcp/store.py` — pure SQLite CRUD with no async/HTTP surface.

Covers MCP server CRUD, tool mappings, user permissions, the token-audit
log, and the proactive-refresh query. The encrypt/decrypt path is hit
implicitly: `mcp/crypto.py` is initialised with a test secret so
`auth_token` round-trips through Fernet on insert + read.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from authmcp_gateway.mcp import store

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mcp_db(initialized_db):
    """auth + mcp tables ready, plus a token-encryption key initialised
    so auth_token round-trips through Fernet (no plaintext-fallback paths)."""
    from authmcp_gateway.mcp.crypto import initialize_crypto

    store.init_mcp_database(initialized_db)
    initialize_crypto("test-fernet-secret-key-32-chars-min!!!")
    return initialized_db


# ---------------------------------------------------------------------------
# init_mcp_database
# ---------------------------------------------------------------------------


def test_init_mcp_database_creates_tables(mcp_db):
    """All four MCP tables exist after init."""
    from authmcp_gateway.db import get_db

    expected = {
        "mcp_servers",
        "tool_mappings",
        "user_mcp_permissions",
        "backend_mcp_token_audit",
    }
    with get_db(mcp_db, row_factory=None) as conn:
        names = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
    assert expected.issubset(names)


# ---------------------------------------------------------------------------
# create_mcp_server / get_mcp_server
# ---------------------------------------------------------------------------


def test_create_mcp_server_returns_int_id(mcp_db):
    server_id = store.create_mcp_server(mcp_db, "github", "https://gh.example.com/mcp")
    assert isinstance(server_id, int)
    assert server_id > 0


def test_create_mcp_server_persists_fields(mcp_db):
    sid = store.create_mcp_server(
        mcp_db,
        name="rag",
        url="https://rag.example.com/mcp",
        description="Knowledge base",
        tool_prefix="rag_",
        enabled=False,
        auth_type="bearer",
        auth_token="secret-bearer-token",
        timeout=45,
    )
    server = store.get_mcp_server(mcp_db, sid)
    assert server is not None
    assert server["name"] == "rag"
    assert server["url"] == "https://rag.example.com/mcp"
    assert server["description"] == "Knowledge base"
    assert server["tool_prefix"] == "rag_"
    assert server["enabled"] == 0
    assert server["auth_type"] == "bearer"
    # auth_token round-trips through Fernet — what we wrote is what we read.
    assert server["auth_token"] == "secret-bearer-token"
    assert server["timeout"] == 45


def test_create_mcp_server_encrypts_auth_token_on_disk(mcp_db):
    """Plaintext token must NOT appear in the raw column value."""
    plaintext = "plaintext-bearer-token-do-not-leak"
    sid = store.create_mcp_server(
        mcp_db,
        name="enc-test",
        url="https://x/mcp",
        auth_type="bearer",
        auth_token=plaintext,
    )
    from authmcp_gateway.db import get_db

    with get_db(mcp_db) as conn:
        raw = conn.execute("SELECT auth_token FROM mcp_servers WHERE id = ?", (sid,)).fetchone()[
            "auth_token"
        ]
    assert plaintext not in raw  # Fernet ciphertext shouldn't echo plaintext.
    assert raw  # something is stored
    assert raw != plaintext


def test_create_mcp_server_duplicate_name_raises_integrity_error(mcp_db):
    import sqlite3

    store.create_mcp_server(mcp_db, "github", "https://gh.example.com/mcp")
    with pytest.raises(sqlite3.IntegrityError):
        store.create_mcp_server(mcp_db, "github", "https://other.example.com/mcp")


def test_get_mcp_server_returns_none_when_missing(mcp_db):
    assert store.get_mcp_server(mcp_db, 99999) is None


def test_get_mcp_server_by_name_round_trip(mcp_db):
    sid = store.create_mcp_server(mcp_db, "by-name", "https://x/mcp")
    by_name = store.get_mcp_server_by_name(mcp_db, "by-name")
    assert by_name is not None
    assert by_name["id"] == sid

    assert store.get_mcp_server_by_name(mcp_db, "no-such-server") is None


# ---------------------------------------------------------------------------
# list_mcp_servers
# ---------------------------------------------------------------------------


def test_list_mcp_servers_returns_all_by_default(mcp_db):
    store.create_mcp_server(mcp_db, "a", "https://a/mcp", enabled=True)
    store.create_mcp_server(mcp_db, "b", "https://b/mcp", enabled=False)
    store.create_mcp_server(mcp_db, "c", "https://c/mcp", enabled=True)

    servers = store.list_mcp_servers(mcp_db)
    names = sorted(s["name"] for s in servers)
    assert names == ["a", "b", "c"]


def test_list_mcp_servers_enabled_only_filters_disabled(mcp_db):
    store.create_mcp_server(mcp_db, "a", "https://a/mcp", enabled=True)
    store.create_mcp_server(mcp_db, "b", "https://b/mcp", enabled=False)

    enabled = store.list_mcp_servers(mcp_db, enabled_only=True)
    assert {s["name"] for s in enabled} == {"a"}


def test_list_mcp_servers_with_user_id_respects_explicit_deny(mcp_db):
    """`user_id` filter excludes servers the user has been explicitly denied."""
    from authmcp_gateway.auth.user_store import create_user

    sid_a = store.create_mcp_server(mcp_db, "a", "https://a/mcp")
    sid_b = store.create_mcp_server(mcp_db, "b", "https://b/mcp")
    uid = create_user(mcp_db, "alice", "alice@x.com", "hash")

    # Deny access to server B explicitly; A has no row → defaults to allowed.
    store.set_user_mcp_permission(mcp_db, uid, sid_b, can_access=False)

    visible = {s["name"] for s in store.list_mcp_servers(mcp_db, user_id=uid)}
    assert "a" in visible
    assert "b" not in visible
    # Sanity: id matches what we created
    assert sid_a in {s["id"] for s in store.list_mcp_servers(mcp_db, user_id=uid)}


# ---------------------------------------------------------------------------
# update_mcp_server / update_server_health / delete_mcp_server
# ---------------------------------------------------------------------------


def test_update_mcp_server_returns_true_on_known_server(mcp_db):
    sid = store.create_mcp_server(mcp_db, "x", "https://x/mcp")
    assert store.update_mcp_server(mcp_db, sid, description="updated") is True
    assert store.get_mcp_server(mcp_db, sid)["description"] == "updated"


def test_update_mcp_server_returns_false_for_missing_id(mcp_db):
    assert store.update_mcp_server(mcp_db, 99999, description="nope") is False


def test_update_mcp_server_rejects_unknown_columns(mcp_db):
    sid = store.create_mcp_server(mcp_db, "x", "https://x/mcp")
    with pytest.raises(ValueError) as exc:
        store.update_mcp_server(mcp_db, sid, evil_column="DROP TABLE users;")
    assert "evil_column" in str(exc.value)


def test_update_mcp_server_re_encrypts_auth_token(mcp_db):
    """Updating auth_token re-runs Fernet encryption — plaintext must not land on disk."""
    sid = store.create_mcp_server(mcp_db, "x", "https://x/mcp")

    new_plain = "new-plaintext-bearer"
    store.update_mcp_server(mcp_db, sid, auth_token=new_plain)

    from authmcp_gateway.db import get_db

    with get_db(mcp_db) as conn:
        raw = conn.execute("SELECT auth_token FROM mcp_servers WHERE id = ?", (sid,)).fetchone()[
            "auth_token"
        ]
    assert new_plain not in raw

    # The decrypted accessor returns the plaintext.
    assert store.get_mcp_server(mcp_db, sid)["auth_token"] == new_plain


def test_update_server_health_writes_status_and_counts(mcp_db):
    sid = store.create_mcp_server(mcp_db, "x", "https://x/mcp")
    store.update_server_health(mcp_db, sid, status="online", tools_count=42)
    server = store.get_mcp_server(mcp_db, sid)
    assert server["status"] == "online"
    assert server["tools_count"] == 42


def test_update_server_health_writes_error(mcp_db):
    sid = store.create_mcp_server(mcp_db, "x", "https://x/mcp")
    store.update_server_health(mcp_db, sid, status="error", error="Connection refused")
    server = store.get_mcp_server(mcp_db, sid)
    assert server["status"] == "error"
    assert server["last_error"] == "Connection refused"


def test_delete_mcp_server_removes_row(mcp_db):
    sid = store.create_mcp_server(mcp_db, "x", "https://x/mcp")
    assert store.delete_mcp_server(mcp_db, sid) is True
    assert store.get_mcp_server(mcp_db, sid) is None
    # second delete is a no-op, returns False
    assert store.delete_mcp_server(mcp_db, sid) is False


# ---------------------------------------------------------------------------
# tool_mappings
# ---------------------------------------------------------------------------


def test_create_and_get_tool_mapping(mcp_db):
    sid = store.create_mcp_server(mcp_db, "x", "https://x/mcp")
    mapping_id = store.create_tool_mapping(mcp_db, "do_thing", sid)
    assert isinstance(mapping_id, int)

    assert store.get_tool_mapping(mcp_db, "do_thing") == sid
    assert store.get_tool_mapping(mcp_db, "no_such_tool") is None


def test_list_tool_mappings_filtered_by_server(mcp_db):
    sid_a = store.create_mcp_server(mcp_db, "a", "https://a/mcp")
    sid_b = store.create_mcp_server(mcp_db, "b", "https://b/mcp")
    store.create_tool_mapping(mcp_db, "tool_a1", sid_a)
    store.create_tool_mapping(mcp_db, "tool_a2", sid_a)
    store.create_tool_mapping(mcp_db, "tool_b1", sid_b)

    all_maps = store.list_tool_mappings(mcp_db)
    assert {m["tool_name"] for m in all_maps} == {"tool_a1", "tool_a2", "tool_b1"}

    only_a = store.list_tool_mappings(mcp_db, mcp_server_id=sid_a)
    assert {m["tool_name"] for m in only_a} == {"tool_a1", "tool_a2"}


def test_delete_tool_mapping(mcp_db):
    sid = store.create_mcp_server(mcp_db, "x", "https://x/mcp")
    store.create_tool_mapping(mcp_db, "do_thing", sid)
    assert store.delete_tool_mapping(mcp_db, "do_thing") is True
    assert store.get_tool_mapping(mcp_db, "do_thing") is None
    # second delete returns False
    assert store.delete_tool_mapping(mcp_db, "do_thing") is False


# ---------------------------------------------------------------------------
# User permissions
# ---------------------------------------------------------------------------


def test_set_and_check_user_mcp_permission(mcp_db):
    from authmcp_gateway.auth.user_store import create_user

    uid = create_user(mcp_db, "alice", "alice@x.com", "hash")
    sid = store.create_mcp_server(mcp_db, "x", "https://x/mcp")

    # No permission row → defaults to True (allowed).
    assert store.check_user_mcp_access(mcp_db, uid, sid) is True

    # Explicit deny → False.
    store.set_user_mcp_permission(mcp_db, uid, sid, can_access=False)
    assert store.check_user_mcp_access(mcp_db, uid, sid) is False

    # Update to grant → True (upsert path).
    store.set_user_mcp_permission(mcp_db, uid, sid, can_access=True)
    assert store.check_user_mcp_access(mcp_db, uid, sid) is True


def test_get_user_mcp_permissions_returns_only_explicit_rows(mcp_db):
    from authmcp_gateway.auth.user_store import create_user

    uid = create_user(mcp_db, "alice", "alice@x.com", "hash")
    sid_a = store.create_mcp_server(mcp_db, "a", "https://a/mcp")
    sid_b = store.create_mcp_server(mcp_db, "b", "https://b/mcp")
    store.create_mcp_server(mcp_db, "c", "https://c/mcp")  # no row for this one

    store.set_user_mcp_permission(mcp_db, uid, sid_a, can_access=True)
    store.set_user_mcp_permission(mcp_db, uid, sid_b, can_access=False)

    perms = store.get_user_mcp_permissions(mcp_db, uid)
    by_id = {p["mcp_server_id"]: p for p in perms}
    assert by_id[sid_a]["can_access"] == 1
    assert by_id[sid_b]["can_access"] == 0


# ---------------------------------------------------------------------------
# Token audit
# ---------------------------------------------------------------------------


def test_log_token_audit_writes_row(mcp_db):
    sid = store.create_mcp_server(mcp_db, "x", "https://x/mcp")
    now = datetime.now(timezone.utc)

    store.log_token_audit(
        mcp_db,
        mcp_server_id=sid,
        event_type="refresh",
        success=True,
        old_expires_at=now - timedelta(hours=1),
        new_expires_at=now + timedelta(hours=1),
        triggered_by="proactive",
    )

    rows = store.get_token_audit_logs(mcp_db, mcp_server_id=sid)
    assert len(rows) == 1
    row = rows[0]
    assert row["event_type"] == "refresh"
    assert row["success"] == 1
    assert row["triggered_by"] == "proactive"


def test_get_token_audit_logs_filters_by_server_and_limit(mcp_db):
    sid_a = store.create_mcp_server(mcp_db, "a", "https://a/mcp")
    sid_b = store.create_mcp_server(mcp_db, "b", "https://b/mcp")

    for i in range(3):
        store.log_token_audit(mcp_db, mcp_server_id=sid_a, event_type=f"refresh-{i}")
    store.log_token_audit(mcp_db, mcp_server_id=sid_b, event_type="refresh-b")

    only_a = store.get_token_audit_logs(mcp_db, mcp_server_id=sid_a)
    assert len(only_a) == 3

    limited = store.get_token_audit_logs(mcp_db, mcp_server_id=sid_a, limit=2)
    assert len(limited) == 2


# ---------------------------------------------------------------------------
# Token refresh helpers
# ---------------------------------------------------------------------------


def test_update_mcp_server_token_replaces_access_token(mcp_db):
    sid = store.create_mcp_server(
        mcp_db, "x", "https://x/mcp", auth_type="bearer", auth_token="old-token"
    )
    new_exp = datetime.now(timezone.utc) + timedelta(hours=1)
    store.update_mcp_server_token(mcp_db, sid, "new-access-token", new_exp)

    server = store.get_mcp_server(mcp_db, sid)
    assert server["auth_token"] == "new-access-token"
    # token_expires_at is stored as ISO timestamp.
    assert server["token_expires_at"]


def test_get_servers_needing_refresh_returns_only_expiring(mcp_db):
    """Only servers with token_expires_at within `threshold_minutes` AND
    a refresh_token_hash (so they're capable of refresh) are returned."""
    sid_soon = store.create_mcp_server(mcp_db, "soon", "https://soon/mcp")
    sid_late = store.create_mcp_server(mcp_db, "late", "https://late/mcp")
    sid_no_refresh = store.create_mcp_server(mcp_db, "noref", "https://noref/mcp")

    soon = (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat()
    late = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    store.update_mcp_server(mcp_db, sid_soon, token_expires_at=soon, refresh_token_hash="sha-soon")
    store.update_mcp_server(mcp_db, sid_late, token_expires_at=late, refresh_token_hash="sha-late")
    # noref: has token_expires_at soon, but no refresh_token_hash → excluded.
    store.update_mcp_server(mcp_db, sid_no_refresh, token_expires_at=soon)

    needing = store.get_servers_needing_refresh(mcp_db, threshold_minutes=10)
    names = {s["name"] for s in needing}
    assert names == {"soon"}
