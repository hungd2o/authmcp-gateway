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
