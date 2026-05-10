"""Tests for password hashing and validation."""

import bcrypt
import pytest

from authmcp_gateway.auth.password import (
    hash_password,
    is_password_valid,
    validate_password_strength,
    verify_password,
    verify_password_with_rehash,
)
from authmcp_gateway.config import AuthConfig


@pytest.fixture
def strict_policy():
    """AuthConfig with all password requirements enabled."""
    return AuthConfig(
        password_min_length=8,
        password_require_uppercase=True,
        password_require_lowercase=True,
        password_require_digit=True,
        password_require_special=True,
    )


@pytest.fixture
def relaxed_policy():
    """AuthConfig with minimal password requirements."""
    return AuthConfig(
        password_min_length=4,
        password_require_uppercase=False,
        password_require_lowercase=False,
        password_require_digit=False,
        password_require_special=False,
    )


def test_hash_and_verify():
    """Hashed password verifies correctly."""
    pw = "MyPassword123!"
    hashed = hash_password(pw)
    assert verify_password(pw, hashed)


def test_wrong_password_rejected():
    """Incorrect password returns False."""
    hashed = hash_password("correct")
    assert not verify_password("wrong", hashed)


def test_invalid_hash_rejected():
    """Malformed hash returns False gracefully."""
    assert not verify_password("any", "not-a-valid-hash")


def test_verify_with_rehash_upgrades_low_cost_hash():
    """Successful verification should request rehash for weak bcrypt cost."""
    low_cost_hash = bcrypt.hashpw(b"Password123!", bcrypt.gensalt(rounds=10)).decode("utf-8")
    ok, upgraded_hash = verify_password_with_rehash("Password123!", low_cost_hash)
    assert ok
    assert upgraded_hash is not None
    assert verify_password("Password123!", upgraded_hash)


def test_verify_with_rehash_keeps_current_hash():
    """Current bcrypt format/cost should not trigger rehash."""
    current_hash = hash_password("Password123!")
    ok, upgraded_hash = verify_password_with_rehash("Password123!", current_hash)
    assert ok
    assert upgraded_hash is None


def test_validate_min_length(strict_policy):
    """Short passwords fail validation."""
    valid, msg = validate_password_strength("Ab1!", strict_policy)
    assert not valid
    assert "at least 8 characters" in msg


def test_validate_require_uppercase(strict_policy):
    """Missing uppercase fails when required."""
    valid, msg = validate_password_strength("abcdefg1!", strict_policy)
    assert not valid
    assert "uppercase" in msg


def test_validate_require_lowercase(strict_policy):
    """Missing lowercase fails when required."""
    valid, msg = validate_password_strength("ABCDEFG1!", strict_policy)
    assert not valid
    assert "lowercase" in msg


def test_validate_require_digit(strict_policy):
    """Missing digit fails when required."""
    valid, msg = validate_password_strength("Abcdefgh!", strict_policy)
    assert not valid
    assert "digit" in msg


def test_validate_require_special(strict_policy):
    """Missing special char fails when required."""
    valid, msg = validate_password_strength("Abcdefg1", strict_policy)
    assert not valid
    assert "special" in msg


def test_validate_all_pass(strict_policy):
    """Strong password passes all checks."""
    valid, msg = validate_password_strength("MyPass12!", strict_policy)
    assert valid
    assert msg is None


def test_is_password_valid_wrapper(strict_policy, relaxed_policy):
    """is_password_valid() returns bool correctly."""
    assert is_password_valid("MyPass12!", strict_policy)
    assert not is_password_valid("weak", strict_policy)
    assert is_password_valid("weak", relaxed_policy)
