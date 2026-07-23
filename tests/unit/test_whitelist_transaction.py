"""Regression coverage for one-time high-risk approval authorizations."""

import sqlite3
from datetime import datetime, timedelta, timezone

from authmcp_gateway.auth.password import hash_password
from authmcp_gateway.auth.user_store import create_user, init_database
from authmcp_gateway.auth.whitelist_transaction import (
    consume_authorization,
    prepare_authorization,
    unconsume_authorization,
)
from authmcp_gateway.mcp.store import create_mcp_server, get_mcp_server, init_mcp_database


def _authorization(db_path, user_id, session_jti, server_id):
    _, challenge = prepare_authorization(
        db_path,
        user_id=user_id,
        admin_session_jti=session_jti,
        action="approve",
        resource_type="server",
        resource_id=server_id,
        rp_id="admin.example.test",
    )
    server = get_mcp_server(db_path, server_id)
    now = datetime.now(timezone.utc)
    with sqlite3.connect(db_path) as connection:
        challenge_id = connection.execute(
            "SELECT id FROM whitelist_challenges WHERE challenge_digest IS NOT NULL ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
        cursor = connection.execute(
            """INSERT INTO whitelist_action_authorizations
               (user_id, admin_session_jti, action, resource_type, resource_id, config_fingerprint,
                challenge_id, authorized_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                user_id,
                session_jti,
                "approve",
                "server",
                server_id,
                server["config_fingerprint"],
                challenge_id,
                now.isoformat(),
                (now + timedelta(minutes=2)).isoformat(),
            ),
        )
    return int(cursor.lastrowid), server["config_fingerprint"], challenge


def test_fingerprint_mismatch_returns_stale_without_consuming_authorization(db_path):
    init_database(db_path)
    init_mcp_database(db_path)
    user_id = create_user(
        db_path, "admin", "admin@example.test", hash_password("Password123!"), is_superuser=True
    )
    server_id = create_mcp_server(
        db_path, name="local-command", url="", transport_type="stdio", command="python"
    )
    authorization_id, fingerprint, _ = _authorization(db_path, user_id, "session-jti", server_id)

    result, trusted_fingerprint = consume_authorization(
        db_path,
        authorization_id=authorization_id,
        user_id=user_id,
        admin_session_jti="session-jti",
        action="approve",
        resource_type="server",
        resource_id=server_id,
        expected_fingerprint="stale-browser-fingerprint",
    )

    assert (result, trusted_fingerprint) == ("stale", None)
    with sqlite3.connect(db_path) as connection:
        assert (
            connection.execute(
                "SELECT consumed_at FROM whitelist_action_authorizations WHERE id = ?",
                (authorization_id,),
            ).fetchone()[0]
            is None
        )

    assert consume_authorization(
        db_path,
        authorization_id=authorization_id,
        user_id=user_id,
        admin_session_jti="session-jti",
        action="approve",
        resource_type="server",
        resource_id=server_id,
        expected_fingerprint=fingerprint,
    ) == ("consumed", fingerprint)


def test_authorization_is_bound_to_its_session_and_one_time(db_path):
    init_database(db_path)
    init_mcp_database(db_path)
    user_id = create_user(
        db_path, "admin", "admin@example.test", hash_password("Password123!"), is_superuser=True
    )
    server_id = create_mcp_server(
        db_path, name="local-command", url="", transport_type="stdio", command="python"
    )
    authorization_id, fingerprint, _ = _authorization(db_path, user_id, "session-jti", server_id)

    assert consume_authorization(
        db_path,
        authorization_id=authorization_id,
        user_id=user_id,
        admin_session_jti="different-session",
        action="approve",
        resource_type="server",
        resource_id=server_id,
        expected_fingerprint=fingerprint,
    ) == ("invalid", None)


def test_failed_fenced_update_can_restore_a_fresh_authorization(db_path):
    init_database(db_path)
    init_mcp_database(db_path)
    user_id = create_user(
        db_path, "admin", "admin@example.test", hash_password("Password123!"), is_superuser=True
    )
    server_id = create_mcp_server(
        db_path, name="local-command", url="", transport_type="stdio", command="python"
    )
    authorization_id, fingerprint, _ = _authorization(db_path, user_id, "session-jti", server_id)
    assert consume_authorization(
        db_path,
        authorization_id=authorization_id,
        user_id=user_id,
        admin_session_jti="session-jti",
        action="approve",
        resource_type="server",
        resource_id=server_id,
        expected_fingerprint=fingerprint,
    ) == ("consumed", fingerprint)
    assert unconsume_authorization(
        db_path,
        authorization_id=authorization_id,
        user_id=user_id,
        admin_session_jti="session-jti",
        action="approve",
        resource_type="server",
        resource_id=server_id,
        config_fingerprint=fingerprint,
    )
    assert consume_authorization(
        db_path,
        authorization_id=authorization_id,
        user_id=user_id,
        admin_session_jti="session-jti",
        action="approve",
        resource_type="server",
        resource_id=server_id,
        expected_fingerprint=fingerprint,
    ) == ("consumed", fingerprint)
    assert consume_authorization(
        db_path,
        authorization_id=authorization_id,
        user_id=user_id,
        admin_session_jti="session-jti",
        action="approve",
        resource_type="server",
        resource_id=server_id,
        expected_fingerprint=fingerprint,
    ) == ("invalid", None)
