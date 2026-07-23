"""Regression coverage for local Whitelist recovery credentials."""

import sqlite3

from authmcp_gateway.auth.password import hash_password
from authmcp_gateway.auth.user_store import create_user, init_database
from authmcp_gateway.auth.whitelist_recovery import (
    consume_recovery_code,
    create_recovery_code,
    recovery_status,
)


def test_recovery_code_is_hashed_and_consumable_once(db_path):
    init_database(db_path)
    user_id = create_user(
        db_path, "admin", "admin@example.test", hash_password("Password123!"), is_superuser=True
    )
    code = create_recovery_code(db_path, user_id)

    with sqlite3.connect(db_path) as connection:
        stored_digest = connection.execute(
            "SELECT code_digest FROM whitelist_recovery_credentials WHERE user_id = ?", (user_id,)
        ).fetchone()[0]
    assert code not in stored_digest
    assert recovery_status(db_path, user_id) is True
    assert consume_recovery_code(db_path, code) == user_id
    assert consume_recovery_code(db_path, code) is None
    assert recovery_status(db_path, user_id) is False


def test_rotating_recovery_code_invalidates_the_previous_code(db_path):
    init_database(db_path)
    user_id = create_user(
        db_path, "admin", "admin@example.test", hash_password("Password123!"), is_superuser=True
    )
    previous = create_recovery_code(db_path, user_id)
    current = create_recovery_code(db_path, user_id)

    assert consume_recovery_code(db_path, previous) is None
    assert consume_recovery_code(db_path, current) == user_id
