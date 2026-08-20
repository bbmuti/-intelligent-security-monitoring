from app.rate_limit import SlidingWindowRateLimiter


def test_rate_limiter_bounds_unique_key_memory_and_enforces_limit():
    limiter = SlidingWindowRateLimiter(limit=2, window_seconds=300, max_buckets=3)
    for key in ("one", "two", "three", "four"):
        assert limiter.allow(key)
    assert len(limiter.attempts) == 3
    assert limiter.allow("target")
    assert limiter.allow("target")
    assert limiter.allow("target") is False
    limiter.reset("target")
    assert limiter.allow("target")
