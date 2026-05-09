"""Helpers for single active access token per user."""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone
from typing import Optional, Tuple

import jwt

from authmcp_gateway.auth.jwt_handler import create_access_token, decode_token_unsafe, verify_token
from authmcp_gateway.auth.user_store import (
    blacklist_token,
    get_admin_access_token,
    get_user_access_token,
    is_token_blacklisted,
    upsert_admin_access_token,
    upsert_user_access_token,
)
from authmcp_gateway.config import JWTConfig

logger = logging.getLogger(__name__)


def _parse_expires_at(expires_at) -> Optional[datetime]:
    if not expires_at:
        return None
    if isinstance(expires_at, datetime):
        return expires_at if expires_at.tzinfo else expires_at.replace(tzinfo=timezone.utc)
    try:
        exp_dt = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        return exp_dt
    except (ValueError, TypeError):
        return None


def format_expires_in(exp_dt: Optional[datetime]) -> str:
    if not exp_dt:
        return ""
    now = datetime.now(timezone.utc)
    minutes = max(1, int((exp_dt - now).total_seconds() // 60))
    if minutes >= 1440:
        days = minutes // 1440
        return f"{days} day{'s' if days > 1 else ''}"
    if minutes >= 60:
        hours = minutes // 60
        return f"{hours} hour{'s' if hours > 1 else ''}"
    return f"{minutes} minute{'s' if minutes > 1 else ''}"


def _try_reuse_current_token(
    db_path: str,
    config: JWTConfig,
    current_token: str,
    stored_jti: Optional[str],
    exp_dt: Optional[datetime],
) -> Optional[Tuple[str, datetime]]:
    """Return (token, exp) if *current_token* is still valid for the stored session.

    Returns None whenever the caller should fall through to rotation:
    expired/invalid signature, JTI mismatch, expired stored window, blacklist,
    or a transient DB error checking the blacklist (a missed cache read here
    is recoverable; the new token issued downstream is still safe).
    """
    try:
        payload = verify_token(current_token, "access", config)
    except jwt.PyJWTError as exc:
        logger.debug("Current access token failed verification, will rotate: %s", exc)
        return None

    token_jti = payload.get("jti")
    if not (
        stored_jti and token_jti == stored_jti and exp_dt and exp_dt > datetime.now(timezone.utc)
    ):
        return None

    try:
        if is_token_blacklisted(db_path, token_jti):
            return None
    except sqlite3.Error as exc:
        logger.warning(
            "Blacklist check failed during token reuse, falling through to rotation: %s", exc
        )
        return None
    return current_token, exp_dt


def _blacklist_old_session(db_path: str, jti: str, exp_dt: datetime) -> None:
    """Blacklist an outgoing session token; log loudly on failure.

    Failure here means the previous session may remain usable until expiry.
    The caller still issues a new token, so the user is not locked out, but
    the operator must see this in the logs to investigate the DB.
    """
    try:
        blacklist_token(db_path, jti, exp_dt)
    except sqlite3.Error:
        logger.error(
            "Failed to blacklist previous session token jti=%s — old session may "
            "remain valid until %s",
            jti,
            exp_dt.isoformat(),
            exc_info=True,
        )


def _exp_dt_from_payload(payload: dict) -> datetime:
    exp = payload.get("exp")
    if exp:
        return datetime.fromtimestamp(int(exp), tz=timezone.utc)
    return datetime.now(timezone.utc)


def get_or_create_user_token(
    db_path: str,
    user_id: int,
    username: str,
    is_superuser: bool,
    config: JWTConfig,
    expire_minutes: int,
    current_token: Optional[str] = None,
) -> Tuple[str, datetime]:
    """Return valid token if current token matches stored JTI, otherwise rotate."""
    existing = get_user_access_token(db_path, user_id)
    exp_dt = _parse_expires_at(existing.get("expires_at")) if existing else None
    stored_jti = existing.get("token_jti") if existing else None

    if current_token:
        reused = _try_reuse_current_token(db_path, config, current_token, stored_jti, exp_dt)
        if reused is not None:
            return reused

    if (
        config.enforce_single_session
        and stored_jti
        and exp_dt
        and not is_token_blacklisted(db_path, stored_jti)
    ):
        _blacklist_old_session(db_path, stored_jti, exp_dt)

    token = create_access_token(
        user_id=user_id,
        username=username,
        is_superuser=is_superuser,
        config=config,
        expire_minutes=expire_minutes,
    )
    payload = decode_token_unsafe(token)
    token_jti = payload.get("jti") or ""
    new_exp = _exp_dt_from_payload(payload)
    upsert_user_access_token(db_path, user_id, token, token_jti, new_exp)
    return token, new_exp


def get_or_create_admin_token(
    db_path: str,
    user_id: int,
    username: str,
    is_superuser: bool,
    config: JWTConfig,
    expire_minutes: int,
    current_token: Optional[str] = None,
) -> Tuple[str, datetime]:
    """Return valid admin token if current token matches stored JTI, otherwise rotate."""
    existing = get_admin_access_token(db_path, user_id)
    exp_dt = _parse_expires_at(existing.get("expires_at")) if existing else None
    stored_jti = existing.get("token_jti") if existing else None

    if current_token:
        reused = _try_reuse_current_token(db_path, config, current_token, stored_jti, exp_dt)
        if reused is not None:
            return reused

    if (
        config.enforce_single_session
        and stored_jti
        and exp_dt
        and not is_token_blacklisted(db_path, stored_jti)
    ):
        _blacklist_old_session(db_path, stored_jti, exp_dt)

    token = create_access_token(
        user_id=user_id,
        username=username,
        is_superuser=is_superuser,
        config=config,
        expire_minutes=expire_minutes,
    )
    payload = decode_token_unsafe(token)
    token_jti = payload.get("jti") or ""
    new_exp = _exp_dt_from_payload(payload)
    upsert_admin_access_token(db_path, user_id, token, token_jti, new_exp)
    return token, new_exp


def _blacklist_current_for_rotate(db_path: str, current_token: str) -> None:
    """Best-effort blacklist of an outgoing token during explicit rotation.

    A malformed token is decode-only here (no signature verification), so a
    bad payload simply means there is nothing useful to blacklist. Real
    sqlite errors must be logged so the operator can act.
    """
    try:
        payload = decode_token_unsafe(current_token)
    except jwt.PyJWTError as exc:
        logger.debug("rotate: could not decode current_token, skipping blacklist: %s", exc)
        return

    jti = payload.get("jti")
    if not jti:
        return
    exp_dt = _exp_dt_from_payload(payload)
    try:
        blacklist_token(db_path, jti, exp_dt)
    except sqlite3.Error:
        logger.error(
            "Failed to blacklist rotated token jti=%s — old session may remain valid until %s",
            jti,
            exp_dt.isoformat(),
            exc_info=True,
        )


def rotate_user_token(
    db_path: str,
    user_id: int,
    username: str,
    is_superuser: bool,
    config: JWTConfig,
    expire_minutes: int,
    current_token: Optional[str] = None,
) -> Tuple[str, datetime]:
    """Blacklist current token (if provided) and issue a new one."""
    if current_token:
        _blacklist_current_for_rotate(db_path, current_token)

    token = create_access_token(
        user_id=user_id,
        username=username,
        is_superuser=is_superuser,
        config=config,
        expire_minutes=expire_minutes,
    )
    payload = decode_token_unsafe(token)
    token_jti = payload.get("jti") or ""
    new_exp = _exp_dt_from_payload(payload)
    upsert_user_access_token(db_path, user_id, token, token_jti, new_exp)
    return token, new_exp


def rotate_admin_token(
    db_path: str,
    user_id: int,
    username: str,
    is_superuser: bool,
    config: JWTConfig,
    expire_minutes: int,
    current_token: Optional[str] = None,
) -> Tuple[str, datetime]:
    """Blacklist current admin token (if provided) and issue a new one."""
    if current_token:
        _blacklist_current_for_rotate(db_path, current_token)

    token = create_access_token(
        user_id=user_id,
        username=username,
        is_superuser=is_superuser,
        config=config,
        expire_minutes=expire_minutes,
    )
    payload = decode_token_unsafe(token)
    token_jti = payload.get("jti") or ""
    new_exp = _exp_dt_from_payload(payload)
    upsert_admin_access_token(db_path, user_id, token, token_jti, new_exp)
    return token, new_exp
