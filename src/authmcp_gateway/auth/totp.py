"""Encrypted RFC 6238 TOTP credentials for Whitelist verification."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import sqlite3
import struct
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from authmcp_gateway.auth.whitelist_store import init_whitelist_database, invalidate_user_security_state

_fernet: Fernet | None = None
_STEP_SECONDS = 30


def initialize_whitelist_crypto(key: str) -> None:
    global _fernet
    _fernet = Fernet(key.encode("ascii"))


def _crypto() -> Fernet:
    if _fernet is None:
        raise RuntimeError("Whitelist credential encryption has not been initialized")
    return _fernet


def generate_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def totp_at(secret: str, time_step: int) -> str:
    if time_step < 0:
        raise ValueError("TOTP time step cannot be negative")
    try:
        key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8), casefold=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid TOTP secret") from exc
    digest = hmac.new(key, struct.pack(">Q", time_step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def verify_totp(
    secret: str,
    code: str,
    *,
    window: int = 1,
    last_used_time_step: int | None = None,
    now: float | None = None,
) -> int | None:
    if (
        window < 0
        or window > 2
        or not isinstance(code, str)
        or len(code) != 6
        or not code.isdigit()
    ):
        return None
    current = int((time.time() if now is None else now) // _STEP_SECONDS)
    for step in range(current - window, current + window + 1):
        if step >= 0 and (last_used_time_step is None or step > last_used_time_step):
            if hmac.compare_digest(totp_at(secret, step), code):
                return step
    return None


def encrypt_totp_secret(secret: str) -> str:
    return _crypto().encrypt(secret.encode("ascii")).decode("ascii")


def decrypt_totp_secret(value: str) -> str:
    try:
        return _crypto().decrypt(value.encode("ascii")).decode("ascii")
    except (InvalidToken, UnicodeDecodeError) as exc:
        raise ValueError("Stored TOTP credential cannot be decrypted") from exc


def _connect(db_path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    return connection


@contextmanager
def _database(db_path: str):
    """Yield one committed transaction and always close its SQLite connection."""
    connection = _connect(db_path)
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def create_totp_pending(db_path: str, user_id: int, secret: str) -> None:
    init_whitelist_database(db_path)
    with _database(db_path) as connection:
        connection.execute(
            """INSERT INTO whitelist_totp_credentials (user_id, secret_encrypted, created_at)
               VALUES (?, ?, ?)
               ON CONFLICT(user_id) DO UPDATE SET secret_encrypted = excluded.secret_encrypted,
                 confirmed_at = NULL, last_used_time_step = NULL, created_at = excluded.created_at,
                 revoked_at = NULL""",
            (user_id, encrypt_totp_secret(secret), datetime.now(timezone.utc).isoformat()),
        )


def get_totp_credential(
    db_path: str, user_id: int, *, confirmed_only: bool = False
) -> dict[str, Any] | None:
    clause = " AND confirmed_at IS NOT NULL" if confirmed_only else ""
    with _database(db_path) as connection:
        row = connection.execute(
            "SELECT * FROM whitelist_totp_credentials WHERE user_id = ? AND revoked_at IS NULL"
            + clause,
            (user_id,),
        ).fetchone()
    return dict(row) if row else None


def confirm_totp(db_path: str, user_id: int, time_step: int) -> bool:
    with _database(db_path) as connection:
        result = connection.execute(
            """UPDATE whitelist_totp_credentials SET confirmed_at = ?, last_used_time_step = ?
               WHERE user_id = ? AND revoked_at IS NULL AND confirmed_at IS NULL""",
            (datetime.now(timezone.utc).isoformat(), time_step, user_id),
        )
        if result.rowcount == 1:
            invalidate_user_security_state(connection, user_id)
    return result.rowcount == 1


def mark_totp_used(db_path: str, user_id: int, time_step: int) -> bool:
    with _database(db_path) as connection:
        result = connection.execute(
            """UPDATE whitelist_totp_credentials SET last_used_time_step = ?
               WHERE user_id = ? AND confirmed_at IS NOT NULL AND revoked_at IS NULL
                 AND (last_used_time_step IS NULL OR last_used_time_step < ?)""",
            (time_step, user_id, time_step),
        )
    return result.rowcount == 1


def remove_totp(db_path: str, user_id: int) -> bool:
    with _database(db_path) as connection:
        result = connection.execute(
            "UPDATE whitelist_totp_credentials SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            (datetime.now(timezone.utc).isoformat(), user_id),
        )
        if result.rowcount == 1:
            invalidate_user_security_state(connection, user_id)
    return result.rowcount == 1
