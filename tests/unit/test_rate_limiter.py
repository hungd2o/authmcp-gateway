"""Tests for the rate limiter."""

import threading
from datetime import datetime, timedelta
from unittest.mock import patch

from authmcp_gateway.rate_limiter import RateLimiter


def test_first_request_allowed():
    """First request always passes."""
    limiter = RateLimiter()
    allowed, retry = limiter.check_limit("ip1", limit=5, window=60)
    assert allowed is True
    assert retry == 0


def test_within_limit_allowed():
    """Requests within limit pass."""
    limiter = RateLimiter()
    for _ in range(4):
        allowed, _ = limiter.check_limit("ip1", limit=5, window=60)
        assert allowed is True


def test_over_limit_rejected():
    """Requests over limit return (False, retry_after > 0)."""
    limiter = RateLimiter()
    for _ in range(5):
        limiter.check_limit("ip1", limit=5, window=60)

    allowed, retry = limiter.check_limit("ip1", limit=5, window=60)
    assert allowed is False
    assert retry > 0


def test_window_reset():
    """Counter resets after window expires."""
    limiter = RateLimiter()
    # Fill the limit
    for _ in range(5):
        limiter.check_limit("ip1", limit=5, window=60)

    # Advance time past window
    future = datetime.now() + timedelta(seconds=61)
    with patch("authmcp_gateway.rate_limiter.datetime") as mock_dt:
        mock_dt.now.return_value = future
        allowed, _ = limiter.check_limit("ip1", limit=5, window=60)
        assert allowed is True


def test_reset_identifier():
    """Manual reset clears limiter state."""
    limiter = RateLimiter()
    limiter.check_limit("ip1", limit=5, window=60)
    assert limiter.reset("ip1") is True
    assert limiter.reset("nonexistent") is False


def test_cleanup_expired():
    """Old entries removed by cleanup."""
    limiter = RateLimiter()
    limiter.check_limit("ip1", limit=5, window=60)

    # Make entry appear old
    limiter._limits["ip1"]["window_start"] = datetime.now() - timedelta(hours=2)
    removed = limiter.cleanup_expired(max_age_seconds=3600)
    assert removed == 1
    assert "ip1" not in limiter._limits


def test_get_stats():
    """Stats reflect current state."""
    limiter = RateLimiter()
    stats = limiter.get_stats()
    assert stats["total_identifiers"] == 0

    limiter.check_limit("ip1", limit=5, window=60)
    limiter.check_limit("ip2", limit=5, window=60)
    stats = limiter.get_stats()
    assert stats["total_identifiers"] == 2
    assert stats["active_limits"] == 2


def test_thread_safety():
    """Concurrent access doesn't corrupt state."""
    limiter = RateLimiter()
    errors = []

    def worker():
        try:
            for _ in range(100):
                limiter.check_limit("shared", limit=10000, window=60)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0
    stats = limiter.get_stats()
    assert stats["total_identifiers"] == 1


def test_security_event_logs_clean_ip_not_composite_identifier(monkeypatch, tmp_path):
    """When the rate limit fires, security_events.ip_address must contain the
    actual IP, not the composite `bucket:ip` identifier callers use to keep
    per-endpoint counters isolated. Regression for production-DB pollution
    where rows showed `register:9.9.9.9`, `oauth_login:9.9.9.9` instead of
    just `9.9.9.9`."""
    import sqlite3

    from authmcp_gateway.auth.user_store import init_database
    from authmcp_gateway.config import AppConfig, AuthConfig, JWTConfig, RateLimitConfig

    db = str(tmp_path / "rate.db")
    init_database(db)
    config = AppConfig(
        auth=AuthConfig(sqlite_path=db),
        jwt=JWTConfig(algorithm="HS256", secret_key="x" * 32),
        rate_limit=RateLimitConfig(),
        mcp_public_url="https://test.local",
    )
    monkeypatch.setattr("authmcp_gateway.config.get_config", lambda: config)

    limiter = RateLimiter()
    for _ in range(3):
        limiter.check_limit("login:1.2.3.4", limit=2, window=60, ip_address="1.2.3.4")

    with sqlite3.connect(db) as conn:
        rows = conn.execute(
            "SELECT ip_address, details FROM security_events WHERE event_type='rate_limited'"
        ).fetchall()

    assert rows, "rate_limited event was not logged"
    for ip, _details in rows:
        assert ip == "1.2.3.4", f"expected clean IP, got {ip!r}"


def test_security_event_falls_back_to_identifier_when_ip_not_passed(monkeypatch, tmp_path):
    """Backward-compat: callers that don't pass ip_address still get *something*
    in the log. We log the identifier verbatim — same behavior as before the
    fix, just no longer the only option."""
    import sqlite3

    from authmcp_gateway.auth.user_store import init_database
    from authmcp_gateway.config import AppConfig, AuthConfig, JWTConfig, RateLimitConfig

    db = str(tmp_path / "rate.db")
    init_database(db)
    config = AppConfig(
        auth=AuthConfig(sqlite_path=db),
        jwt=JWTConfig(algorithm="HS256", secret_key="x" * 32),
        rate_limit=RateLimitConfig(),
        mcp_public_url="https://test.local",
    )
    monkeypatch.setattr("authmcp_gateway.config.get_config", lambda: config)

    limiter = RateLimiter()
    for _ in range(3):
        limiter.check_limit("plain-id", limit=2, window=60)

    with sqlite3.connect(db) as conn:
        rows = conn.execute(
            "SELECT ip_address FROM security_events WHERE event_type='rate_limited'"
        ).fetchall()

    assert rows
    assert all(r[0] == "plain-id" for r in rows)
