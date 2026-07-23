"""Unit coverage for encrypted, replay-safe RFC 6238 credentials."""

from cryptography.fernet import Fernet

from authmcp_gateway.auth import totp
from authmcp_gateway.auth.password import hash_password
from authmcp_gateway.auth.user_store import create_user, init_database
from authmcp_gateway.auth.whitelist_store import init_whitelist_database


def _user(db_path: str) -> int:
    init_database(db_path)
    init_whitelist_database(db_path)
    return create_user(db_path, "admin", "admin@example.test", hash_password("Password123!"), True)


def test_rfc6238_code_is_valid_once_and_replay_is_rejected():
    secret, now = "JBSWY3DPEHPK3PXP", 1_700_000_000.0
    step = int(now // 30)
    code = totp.totp_at(secret, step)
    assert totp.verify_totp(secret, code, now=now) == step
    assert totp.verify_totp(secret, code, now=now, last_used_time_step=step) is None
    assert totp.verify_totp(secret, "invalid", now=now) is None


def test_pending_credential_is_encrypted_confirmed_and_revocable(db_path):
    totp.initialize_whitelist_crypto(Fernet.generate_key().decode("ascii"))
    user_id, secret = _user(db_path), totp.generate_secret()
    totp.create_totp_pending(db_path, user_id, secret)
    pending = totp.get_totp_credential(db_path, user_id)
    assert pending and pending["secret_encrypted"] != secret and pending["confirmed_at"] is None
    step = int(1_700_000_000 // 30)
    assert totp.confirm_totp(db_path, user_id, step)
    assert totp.mark_totp_used(db_path, user_id, step + 1)
    assert not totp.mark_totp_used(db_path, user_id, step)
    assert totp.remove_totp(db_path, user_id)
    assert totp.get_totp_credential(db_path, user_id) is None
