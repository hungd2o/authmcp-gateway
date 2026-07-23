"""Local, one-time recovery codes for restoring Whitelist security methods."""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from authmcp_gateway.auth.whitelist_store import init_whitelist_database, invalidate_user_security_state

_GRANT_TTL = timedelta(minutes=10)


def _now() -> datetime:
    return datetime.now(timezone.utc)


@contextmanager
def _database(db_path: str):
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _digest(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def _new_handle() -> str:
    return secrets.token_urlsafe(32)


def _init_grants(connection: sqlite3.Connection) -> None:
    connection.execute("""CREATE TABLE IF NOT EXISTS whitelist_recovery_grants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            handle_digest TEXT NOT NULL UNIQUE,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )""")


def create_recovery_code(db_path: str, user_id: int) -> str:
    """Rotate existing recovery codes and create one five-minute CSPRNG code."""
    if user_id <= 0:
        raise ValueError("Invalid user")
    init_whitelist_database(db_path)
    code, now = secrets.token_urlsafe(24), _now()
    with _database(db_path) as connection:
        connection.execute(
            """UPDATE whitelist_recovery_credentials SET consumed_at = ?
               WHERE user_id = ? AND consumed_at IS NULL""",
            (now.isoformat(), user_id),
        )
        connection.execute(
            """INSERT INTO whitelist_recovery_credentials
               (user_id, code_digest, created_at, expires_at) VALUES (?, ?, ?, ?)""",
            (user_id, _digest(code), now.isoformat(), (now + timedelta(minutes=5)).isoformat()),
        )
        invalidate_user_security_state(connection, user_id)
    return code


def consume_recovery_code(db_path: str, code: str) -> int | None:
    """Atomically consume a non-expired recovery code and return its user ID."""
    if not isinstance(code, str) or not code:
        return None
    now = _now().isoformat()
    with _database(db_path) as connection:
        row = connection.execute(
            """SELECT id, user_id FROM whitelist_recovery_credentials
               WHERE code_digest = ? AND consumed_at IS NULL AND expires_at > ?""",
            (_digest(code), now),
        ).fetchone()
        if row is None:
            return None
        changed = connection.execute(
            """UPDATE whitelist_recovery_credentials SET consumed_at = ?
               WHERE id = ? AND consumed_at IS NULL AND expires_at > ?""",
            (now, int(row["id"]), now),
        )
    return int(row["user_id"]) if changed.rowcount == 1 else None


def redeem_recovery_code(db_path: str, code: str) -> tuple[str, int] | None:
    """Consume a recovery code and create a separate, recovery-only browser grant."""
    if not isinstance(code, str) or not code:
        return None
    init_whitelist_database(db_path)
    now = _now()
    with _database(db_path) as connection:
        _init_grants(connection)
        row = connection.execute(
            """SELECT id, user_id FROM whitelist_recovery_credentials
               WHERE code_digest = ? AND consumed_at IS NULL AND expires_at > ?""",
            (_digest(code), now.isoformat()),
        ).fetchone()
        if row is None:
            return None
        changed = connection.execute(
            """UPDATE whitelist_recovery_credentials SET consumed_at = ?
               WHERE id = ? AND consumed_at IS NULL AND expires_at > ?""",
            (now.isoformat(), int(row["id"]), now.isoformat()),
        )
        if changed.rowcount != 1:
            return None
        handle = _new_handle()
        connection.execute(
            """INSERT INTO whitelist_recovery_grants
               (handle_digest, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)""",
            (_digest(handle), int(row["user_id"]), now.isoformat(), (now + _GRANT_TTL).isoformat()),
        )
    return handle, int(row["user_id"])


def get_recovery_grant(db_path: str, handle: str | None) -> int | None:
    """Return the grant's user only while its opaque recovery handle is active."""
    if not handle:
        return None
    with _database(db_path) as connection:
        _init_grants(connection)
        row = connection.execute(
            """SELECT id, user_id FROM whitelist_recovery_grants
               WHERE handle_digest = ? AND revoked_at IS NULL AND expires_at > ?""",
            (_digest(handle), _now().isoformat()),
        ).fetchone()
    return int(row["user_id"]) if row else None


def revoke_recovery_grant(db_path: str, handle: str | None) -> bool:
    """Invalidate an opaque recovery grant after its sensitive use."""
    if not handle:
        return False
    with _database(db_path) as connection:
        _init_grants(connection)
        result = connection.execute(
            """UPDATE whitelist_recovery_grants SET revoked_at = ?
               WHERE handle_digest = ? AND revoked_at IS NULL""",
            (_now().isoformat(), _digest(handle)),
        )
    return result.rowcount == 1


def recovery_status(db_path: str, user_id: int) -> bool:
    with _database(db_path) as connection:
        row = connection.execute(
            """SELECT 1 FROM whitelist_recovery_credentials
               WHERE user_id = ? AND consumed_at IS NULL AND expires_at > ? LIMIT 1""",
            (user_id, _now().isoformat()),
        ).fetchone()
    return row is not None
