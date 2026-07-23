"""One-time passkey authorization for high-risk Whitelist approvals."""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

from webauthn import verify_authentication_response
from webauthn.helpers import parse_authentication_credential_json

from authmcp_gateway.auth import webauthn_store
from authmcp_gateway.auth.whitelist_store import init_whitelist_database
from authmcp_gateway.mcp.trust import build_server_fingerprint, build_virtual_tool_fingerprint

_PURPOSE = "transaction_authorization"


def _now() -> datetime:
    return datetime.now(timezone.utc)


@contextmanager
def _database(db_path: str, *, immediate: bool = False):
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
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


def _resource(
    db_path: str, resource_type: str, resource_id: int
) -> tuple[dict[str, Any], str] | None:
    if resource_type == "server":
        from authmcp_gateway.mcp.store import get_mcp_server

        resource = get_mcp_server(db_path, resource_id)
        return (resource, build_server_fingerprint(resource)) if resource else None
    if resource_type == "virtual_tool":
        from authmcp_gateway.mcp.store import get_virtual_tool

        resource = get_virtual_tool(db_path, resource_id)
        return (resource, build_virtual_tool_fingerprint(resource)) if resource else None
    return None


def _validate(action: str, resource_type: str, resource_id: int) -> None:
    if action != "approve" or resource_type not in {"server", "virtual_tool"} or resource_id <= 0:
        raise ValueError("Invalid high-risk authorization target")


def prepare_authorization(
    db_path: str,
    *,
    user_id: int,
    admin_session_jti: str,
    action: str,
    resource_type: str,
    resource_id: int,
    rp_id: str,
    ttl_seconds: int = 120,
) -> tuple[int, bytes]:
    """Bind a short-lived passkey challenge to the current resource fingerprint."""
    _validate(action, resource_type, resource_id)
    current = _resource(db_path, resource_type, resource_id)
    if current is None:
        raise ValueError("Whitelist resource was not found")
    _, fingerprint = current
    return webauthn_store.create_challenge(
        db_path,
        user_id=user_id,
        admin_session_jti=admin_session_jti,
        rp_id=rp_id,
        purpose=_PURPOSE,
        resource_type=resource_type,
        resource_id=resource_id,
        config_fingerprint=fingerprint,
        ttl_seconds=ttl_seconds,
    )


def _challenge(response: dict[str, Any]) -> bytes:
    try:
        encoded = response["response"]["clientDataJSON"]
        decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        challenge = json.loads(decoded)["challenge"]
        raw = base64.urlsafe_b64decode(challenge + "=" * (-len(challenge) % 4))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("Malformed WebAuthn credential response") from exc
    if len(raw) != 32:
        raise ValueError("Invalid WebAuthn challenge")
    return raw


def _consume_challenge(
    db_path: str,
    *,
    challenge_id: int,
    challenge: bytes,
    user_id: int,
    admin_session_jti: str,
    rp_id: str,
) -> dict[str, Any] | None:
    now = _now().isoformat()
    with _database(db_path) as connection:
        row = connection.execute(
            """SELECT * FROM whitelist_challenges
               WHERE id = ? AND challenge_digest = ? AND user_id = ?
                 AND admin_session_jti = ? AND rp_id = ? AND purpose = ?
                 AND consumed_at IS NULL AND expires_at > ?""",
            (
                challenge_id,
                hashlib.sha256(challenge).hexdigest(),
                user_id,
                admin_session_jti,
                rp_id,
                _PURPOSE,
                now,
            ),
        ).fetchone()
        if row is None:
            return None
        changed = connection.execute(
            """UPDATE whitelist_challenges SET consumed_at = ?
               WHERE id = ? AND challenge_digest = ? AND consumed_at IS NULL AND expires_at > ?""",
            (now, challenge_id, hashlib.sha256(challenge).hexdigest(), now),
        )
        return dict(row) if changed.rowcount == 1 else None


def verify_and_create_authorization(
    db_path: str,
    *,
    challenge_id: int,
    webauthn_response: dict[str, Any],
    user_id: int,
    admin_session_jti: str,
    rp_id: str,
    origin: str,
    fresh_seconds: int = 120,
) -> dict[str, Any]:
    """Verify a fresh assertion and persist one short-lived action authorization."""
    if not 0 < fresh_seconds <= 600:
        raise ValueError("Invalid passkey authorization lifetime")
    credential = parse_authentication_credential_json(webauthn_response)
    challenge = _challenge(webauthn_response)
    row = _consume_challenge(
        db_path,
        challenge_id=challenge_id,
        challenge=challenge,
        user_id=user_id,
        admin_session_jti=admin_session_jti,
        rp_id=rp_id,
    )
    if row is None:
        raise ValueError("Authorization challenge is expired or already used")
    passkey = webauthn_store.get_passkey_by_credential_id(db_path, credential.id)
    if passkey is None or int(passkey["user_id"]) != user_id or passkey["rp_id"] != rp_id:
        raise ValueError("Unknown passkey")
    verified = verify_authentication_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=rp_id,
        expected_origin=origin,
        credential_public_key=passkey["public_key_bytes"],
        credential_current_sign_count=int(passkey["sign_count"]),
        require_user_verification=True,
    )
    if not webauthn_store.update_sign_count(
        db_path, credential_id=credential.id, sign_count=verified.new_sign_count
    ):
        raise ValueError("Passkey sign count was rejected")
    now = _now()
    expires_at = now + timedelta(seconds=fresh_seconds)
    with _database(db_path, immediate=True) as connection:
        active = connection.execute(
            """SELECT 1 FROM whitelist_passkeys
               WHERE user_id = ? AND credential_id = ? AND rp_id = ? AND revoked_at IS NULL""",
            (user_id, credential.id, rp_id),
        ).fetchone()
        if active is None:
            raise ValueError("Passkey was revoked during authorization")
        cursor = connection.execute(
            """INSERT INTO whitelist_action_authorizations
               (user_id, admin_session_jti, action, resource_type, resource_id, config_fingerprint,
                challenge_id, authorized_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                user_id,
                admin_session_jti,
                "approve",
                row["resource_type"],
                row["resource_id"],
                row["config_fingerprint"],
                challenge_id,
                now.isoformat(),
                expires_at.isoformat(),
            ),
        )
    return {"authorization_id": int(cursor.lastrowid), "expires_at": expires_at.isoformat()}


def consume_authorization(
    db_path: str,
    *,
    authorization_id: int,
    user_id: int,
    admin_session_jti: str,
    action: str,
    resource_type: str,
    resource_id: int,
    expected_fingerprint: str,
) -> tuple[str, str | None]:
    """Consume an authorization only when its resource fingerprint is still current.

    ``stale`` leaves the authorization usable after the user reloads and reviews;
    ``consumed`` returns its trusted fingerprint for the final store update.  The
    caller's reviewed fingerprint is checked before the authorization is spent,
    so an out-of-date browser cannot turn a valid assertion into an approval.
    """
    _validate(action, resource_type, resource_id)
    now = _now().isoformat()
    with _database(db_path, immediate=True) as connection:
        row = connection.execute(
            """SELECT * FROM whitelist_action_authorizations
               WHERE id = ? AND user_id = ? AND admin_session_jti = ? AND action = ?
                 AND resource_type = ? AND resource_id = ? AND consumed_at IS NULL AND expires_at > ?""",
            (authorization_id, user_id, admin_session_jti, action, resource_type, resource_id, now),
        ).fetchone()
        if row is None:
            return "invalid", None
        if expected_fingerprint != row["config_fingerprint"]:
            return "stale", None
        current = _resource(db_path, resource_type, resource_id)
        if current is None or current[1] != row["config_fingerprint"]:
            return "stale", None
        changed = connection.execute(
            """UPDATE whitelist_action_authorizations SET consumed_at = ?
               WHERE id = ? AND user_id = ? AND admin_session_jti = ? AND consumed_at IS NULL
                 AND expires_at > ? AND config_fingerprint = ?""",
            (now, authorization_id, user_id, admin_session_jti, now, row["config_fingerprint"]),
        )
    return (
        ("consumed", str(row["config_fingerprint"])) if changed.rowcount == 1 else ("invalid", None)
    )


def unconsume_authorization(
    db_path: str,
    *,
    authorization_id: int,
    user_id: int,
    admin_session_jti: str,
    action: str,
    resource_type: str,
    resource_id: int,
    config_fingerprint: str,
) -> bool:
    """Restore a just-consumed authorization when the fenced target update loses a race."""
    _validate(action, resource_type, resource_id)
    with _database(db_path, immediate=True) as connection:
        changed = connection.execute(
            """UPDATE whitelist_action_authorizations SET consumed_at = NULL
               WHERE id = ? AND user_id = ? AND admin_session_jti = ? AND action = ?
                 AND resource_type = ? AND resource_id = ? AND config_fingerprint = ?
                 AND consumed_at IS NOT NULL AND expires_at > ?""",
            (
                authorization_id,
                user_id,
                admin_session_jti,
                action,
                resource_type,
                resource_id,
                config_fingerprint,
                _now().isoformat(),
            ),
        )
    return changed.rowcount == 1
