"""Persistent short-lived sessions used only by Whitelist actions."""

from __future__ import annotations

import base64
import hashlib
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Optional


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _new_handle() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")


def invalidate_user_security_state(connection: sqlite3.Connection, user_id: int) -> None:
    """Fail closed when a user's Whitelist credential set changes.

    The caller supplies its existing transaction so credential revocation and
    invalidation cannot leave a derived session or authorization usable.
    """
    now = _iso(_now())
    connection.execute(
        "UPDATE whitelist_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
        (now, user_id),
    )
    connection.execute(
        """UPDATE whitelist_challenges SET consumed_at = ?, expires_at = ?
           WHERE user_id = ? AND consumed_at IS NULL""",
        (now, now, user_id),
    )
    connection.execute(
        """UPDATE whitelist_action_authorizations SET consumed_at = ?, expires_at = ?
           WHERE user_id = ? AND consumed_at IS NULL""",
        (now, now, user_id),
    )


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _ensure_column(connection: sqlite3.Connection, table: str, definition: str) -> None:
    column = definition.split()[0]
    columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")


@contextmanager
def _database(db_path: str):
    """Yield a transaction-scoped connection and always close its handle."""
    conn = _connect(db_path)
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init_whitelist_database(db_path: str) -> None:
    """Create Whitelist-related tables if missing (idempotent, safe to call repeatedly).

    ``admin_session_id`` on ``whitelist_sessions`` stores the admin JWT ``jti``
    (not a cookie hash) — the column name is kept to avoid a migration.
    """
    with _database(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS whitelist_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                handle_digest TEXT NOT NULL UNIQUE,
                user_id INTEGER NOT NULL,
                admin_session_id TEXT NOT NULL,
                method TEXT NOT NULL,
                assurance_level TEXT NOT NULL DEFAULT 'legacy',
                credential_type TEXT,
                credential_id TEXT,
                credential_rp_id TEXT,
                credential_generation INTEGER NOT NULL DEFAULT 0,
                verified_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """)
        _ensure_column(conn, "whitelist_sessions", "assurance_level TEXT NOT NULL DEFAULT 'legacy'")
        _ensure_column(conn, "whitelist_sessions", "credential_type TEXT")
        _ensure_column(conn, "whitelist_sessions", "credential_id TEXT")
        _ensure_column(conn, "whitelist_sessions", "credential_rp_id TEXT")
        _ensure_column(conn, "whitelist_sessions", "credential_generation INTEGER NOT NULL DEFAULT 0")
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_whitelist_sessions_binding
            ON whitelist_sessions(user_id, admin_session_id, expires_at)
            """)
        # Consumed by later parts (WebAuthn passkeys, TOTP fallback, recovery,
        # high-risk transaction authorization) — schema created now so no
        # migration is needed later.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS whitelist_passkeys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                credential_id TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL,
                sign_count INTEGER NOT NULL DEFAULT 0,
                rp_id TEXT NOT NULL,
                label TEXT,
                created_at TEXT NOT NULL,
                last_used_at TEXT,
                revoked_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS whitelist_challenges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                challenge_digest TEXT NOT NULL UNIQUE,
                user_id INTEGER NOT NULL,
                admin_session_jti TEXT NOT NULL,
                rp_id TEXT NOT NULL,
                purpose TEXT NOT NULL,
                resource_type TEXT,
                resource_id INTEGER,
                config_fingerprint TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS whitelist_totp_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                secret_encrypted TEXT NOT NULL,
                confirmed_at TEXT,
                last_used_time_step INTEGER,
                created_at TEXT NOT NULL,
                revoked_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS whitelist_recovery_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                code_digest TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS whitelist_action_authorizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                admin_session_jti TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id INTEGER NOT NULL,
                config_fingerprint TEXT NOT NULL,
                challenge_id INTEGER,
                authorized_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (challenge_id) REFERENCES whitelist_challenges(id) ON DELETE SET NULL
            )
            """)


def create_whitelist_session(
    db_path: str,
    *,
    user_id: int,
    admin_session_id: str,
    method: str,
    ttl_minutes: int,
    assurance_level: str | None = None,
    credential_type: str | None = None,
    credential_id: str | None = None,
    credential_rp_id: str | None = None,
    credential_generation: int = 0,
) -> tuple[str, dict[str, Any]]:
    init_whitelist_database(db_path)
    if not admin_session_id:
        raise ValueError("Admin session binding is required")
    if ttl_minutes <= 0:
        raise ValueError("Whitelist session lifetime must be positive")
    assurance_level = assurance_level or method
    if assurance_level not in {"legacy", "totp", "passkey"} or credential_generation < 0:
        raise ValueError("Invalid Whitelist session assurance")

    handle = _new_handle()
    now = _now()
    expires_at = now + timedelta(minutes=ttl_minutes)

    with _database(db_path) as conn:
        conn.execute(
            """
            UPDATE whitelist_sessions
            SET revoked_at = ?
            WHERE user_id = ? AND admin_session_id = ? AND revoked_at IS NULL
            """,
            (_iso(now), user_id, admin_session_id),
        )
        cursor = conn.execute(
            """
            INSERT INTO whitelist_sessions (
                handle_digest, user_id, admin_session_id, method, assurance_level, credential_type,
                credential_id, credential_rp_id, credential_generation, verified_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _digest(handle), user_id, admin_session_id, method, assurance_level, credential_type,
                credential_id, credential_rp_id, credential_generation, _iso(now), _iso(expires_at),
            ),
        )

    return handle, {
        "id": int(cursor.lastrowid),
        "user_id": user_id,
        "admin_session_id": admin_session_id,
        "method": method,
        "assurance_level": assurance_level,
        "credential_type": credential_type,
        "credential_id": credential_id,
        "credential_rp_id": credential_rp_id,
        "credential_generation": credential_generation,
        "verified_at": _iso(now),
        "expires_at": _iso(expires_at),
    }


def get_active_whitelist_session(
    db_path: str,
    *,
    handle: Optional[str],
    user_id: int,
    admin_session_id: str,
) -> Optional[dict[str, Any]]:
    init_whitelist_database(db_path)
    if not handle or not admin_session_id:
        return None

    with _database(db_path) as conn:
        row = conn.execute(
            """
            SELECT id, user_id, admin_session_id, method, assurance_level, credential_type,
                   credential_id, credential_rp_id, credential_generation, verified_at, expires_at, revoked_at
            FROM whitelist_sessions
            WHERE handle_digest = ? AND user_id = ? AND admin_session_id = ?
            """,
            (_digest(handle), user_id, admin_session_id),
        ).fetchone()
        if row is None or row["revoked_at"]:
            return None

        try:
            expires_at = datetime.fromisoformat(str(row["expires_at"]))
        except ValueError:
            return None
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= _now():
            conn.execute(
                "UPDATE whitelist_sessions SET revoked_at = ? WHERE id = ?",
                (_iso(_now()), int(row["id"])),
            )
            return None
        return dict(row)


def revoke_whitelist_session(
    db_path: str,
    *,
    handle: Optional[str],
    user_id: int,
    admin_session_id: str,
) -> bool:
    init_whitelist_database(db_path)
    if not handle or not admin_session_id:
        return False
    with _database(db_path) as conn:
        cursor = conn.execute(
            """
            UPDATE whitelist_sessions
            SET revoked_at = ?
            WHERE handle_digest = ? AND user_id = ? AND admin_session_id = ?
              AND revoked_at IS NULL
            """,
            (_iso(_now()), _digest(handle), user_id, admin_session_id),
        )
    return cursor.rowcount > 0


def consume_challenge(db_path: str, challenge_id: int) -> Optional[dict[str, Any]]:
    """Atomically consume one unexpired WebAuthn challenge.

    The row is returned only to the request that successfully marked it used;
    concurrent or replayed submissions receive ``None``.
    """
    now = _now()
    now_iso = _iso(now)
    with _database(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM whitelist_challenges WHERE id = ?", (challenge_id,)
        ).fetchone()
        if row is None:
            return None
        cursor = conn.execute(
            """
            UPDATE whitelist_challenges
            SET consumed_at = ?
            WHERE id = ? AND consumed_at IS NULL AND expires_at > ?
            """,
            (now_iso, challenge_id, now_iso),
        )
        if cursor.rowcount != 1:
            return None
        return dict(row)


def consume_action_authorization(db_path: str, authorization_id: int) -> bool:
    """Atomically consume one unexpired high-risk action authorization."""
    now_iso = _iso(_now())
    with _database(db_path) as conn:
        cursor = conn.execute(
            """
            UPDATE whitelist_action_authorizations
            SET consumed_at = ?
            WHERE id = ? AND consumed_at IS NULL AND expires_at > ?
            """,
            (now_iso, authorization_id, now_iso),
        )
    return cursor.rowcount == 1
