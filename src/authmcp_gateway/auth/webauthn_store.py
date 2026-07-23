"""Server-side WebAuthn challenge and passkey persistence helpers."""

from __future__ import annotations

import base64
import hashlib
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

from starlette.requests import Request

from authmcp_gateway.auth.whitelist_store import init_whitelist_database, invalidate_user_security_state


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid WebAuthn credential identifier") from exc


def _connect(db_path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    return connection


@contextmanager
def _database(db_path: str, *, immediate: bool = False):
    """Yield one committed transaction and always close its SQLite connection."""
    connection = _connect(db_path)
    try:
        if immediate:
            connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def resolve_rp_id(request: Request, config: Any) -> str:
    """Resolve an RP ID strictly from the request host and server allowlist."""
    host = (request.url.hostname or "").lower()
    allowed = {str(value).strip().lower() for value in config.webauthn_rp_ids if value.strip()}
    if not host or host not in allowed:
        raise ValueError("Request host is not an allowed WebAuthn RP ID")
    return host


def resolve_origin(request: Request, config: Any) -> str:
    """Accept only a browser Origin that exactly matches server configuration."""
    origin = (request.headers.get("origin") or "").strip()
    if origin not in set(config.webauthn_allowed_origins):
        raise ValueError("Request origin is not an allowed WebAuthn origin")
    parsed = urlsplit(origin)
    if parsed.scheme != "https" and (parsed.hostname or "").lower() not in {
        "localhost",
        "127.0.0.1",
        "::1",
    }:
        raise ValueError("WebAuthn requires HTTPS except on localhost")
    return origin


def create_challenge(
    db_path: str,
    *,
    user_id: int,
    admin_session_jti: str,
    rp_id: str,
    purpose: str,
    resource_type: str | None = None,
    resource_id: int | None = None,
    config_fingerprint: str | None = None,
    ttl_seconds: int = 120,
) -> tuple[int, bytes]:
    """Create a random, hashed, short-lived challenge bound to its operation."""
    if not admin_session_jti or not rp_id or not purpose or not 0 < ttl_seconds <= 600:
        raise ValueError("Invalid WebAuthn challenge parameters")
    init_whitelist_database(db_path)
    challenge = secrets.token_bytes(32)
    now = _now()
    with _database(db_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO whitelist_challenges (
                challenge_digest, user_id, admin_session_jti, rp_id, purpose,
                resource_type, resource_id, config_fingerprint, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                hashlib.sha256(challenge).hexdigest(),
                user_id,
                admin_session_jti,
                rp_id,
                purpose,
                resource_type,
                resource_id,
                config_fingerprint,
                now.isoformat(),
                (now + timedelta(seconds=ttl_seconds)).isoformat(),
            ),
        )
        return int(cursor.lastrowid), challenge


def get_and_consume_challenge(
    db_path: str,
    *,
    challenge: bytes,
    user_id: int,
    admin_session_jti: str,
    rp_id: str,
    purpose: str,
) -> dict[str, Any] | None:
    """Atomically consume a matching challenge; replays and mismatches return ``None``."""
    now = _now().isoformat()
    with _database(db_path) as connection:
        row = connection.execute(
            """
            SELECT * FROM whitelist_challenges
            WHERE challenge_digest = ? AND user_id = ? AND admin_session_jti = ?
              AND rp_id = ? AND purpose = ? AND consumed_at IS NULL AND expires_at > ?
            """,
            (
                hashlib.sha256(challenge).hexdigest(),
                user_id,
                admin_session_jti,
                rp_id,
                purpose,
                now,
            ),
        ).fetchone()
        if row is None:
            return None
        updated = connection.execute(
            """UPDATE whitelist_challenges SET consumed_at = ?
               WHERE id = ? AND consumed_at IS NULL AND expires_at > ?""",
            (now, int(row["id"]), now),
        )
        return dict(row) if updated.rowcount == 1 else None


def list_passkeys(db_path: str, user_id: int) -> list[dict[str, Any]]:
    with _database(db_path) as connection:
        rows = connection.execute(
            """SELECT credential_id, rp_id, label, created_at, last_used_at FROM whitelist_passkeys
               WHERE user_id = ? AND revoked_at IS NULL ORDER BY created_at""",
            (user_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def create_passkey(
    db_path: str,
    *,
    user_id: int,
    credential_id: bytes,
    public_key: bytes,
    sign_count: int,
    rp_id: str,
    label: str | None = None,
) -> None:
    if not credential_id or not public_key or sign_count < 0 or not rp_id:
        raise ValueError("Invalid passkey data")
    with _database(db_path) as connection:
        connection.execute(
            """INSERT INTO whitelist_passkeys
               (user_id, credential_id, public_key, sign_count, rp_id, label, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                user_id,
                _b64(credential_id),
                _b64(public_key),
                sign_count,
                rp_id,
                label,
                _now().isoformat(),
            ),
        )
        invalidate_user_security_state(connection, user_id)


def get_passkey_by_credential_id(db_path: str, credential_id: str) -> dict[str, Any] | None:
    _unb64(credential_id)
    with _database(db_path) as connection:
        row = connection.execute(
            "SELECT * FROM whitelist_passkeys WHERE credential_id = ? AND revoked_at IS NULL",
            (credential_id,),
        ).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["credential_id_bytes"] = _unb64(credential_id)
    result["public_key_bytes"] = _unb64(str(result["public_key"]))
    return result


def rename_passkey(db_path: str, *, user_id: int, credential_id: str, label: str) -> bool:
    if not label or len(label) > 80:
        raise ValueError("Passkey label must be between 1 and 80 characters")
    with _database(db_path) as connection:
        result = connection.execute(
            """UPDATE whitelist_passkeys SET label = ?
               WHERE user_id = ? AND credential_id = ? AND revoked_at IS NULL""",
            (label, user_id, credential_id),
        )
    return result.rowcount == 1


def revoke_passkey(db_path: str, *, user_id: int, credential_id: str) -> str:
    """Atomically revoke a passkey while preserving a final recovery path.

    The immediate transaction serializes concurrent revoke requests, so two
    requests that both observe two active passkeys cannot revoke both.
    """
    now = _now().isoformat()
    with _database(db_path, immediate=True) as connection:
        found = connection.execute(
            """SELECT 1 FROM whitelist_passkeys
               WHERE user_id = ? AND credential_id = ? AND revoked_at IS NULL""",
            (user_id, credential_id),
        ).fetchone()
        if found is None:
            return "not_found"
        count = connection.execute(
            "SELECT COUNT(*) FROM whitelist_passkeys WHERE user_id = ? AND revoked_at IS NULL",
            (user_id,),
        ).fetchone()[0]
        if count == 1:
            recovery = connection.execute(
                """SELECT 1 FROM whitelist_recovery_credentials
                   WHERE user_id = ? AND consumed_at IS NULL AND expires_at > ? LIMIT 1""",
                (user_id, now),
            ).fetchone()
            if recovery is None:
                return "recovery_required"
        connection.execute(
            """UPDATE whitelist_passkeys SET revoked_at = ?
               WHERE user_id = ? AND credential_id = ? AND revoked_at IS NULL""",
            (now, user_id, credential_id),
        )
        invalidate_user_security_state(connection, user_id)
    return "revoked"


def update_sign_count(db_path: str, *, credential_id: str, sign_count: int) -> bool:
    if sign_count < 0:
        raise ValueError("Passkey sign count cannot be negative")
    with _database(db_path) as connection:
        result = connection.execute(
            """UPDATE whitelist_passkeys SET sign_count = ?, last_used_at = ?
               WHERE credential_id = ? AND revoked_at IS NULL
                 AND (sign_count < ? OR (sign_count = 0 AND ? = 0))""",
            (sign_count, _now().isoformat(), credential_id, sign_count, sign_count),
        )
    return result.rowcount == 1


def credential_id_to_bytes(credential_id: str) -> bytes:
    return _unb64(credential_id)
