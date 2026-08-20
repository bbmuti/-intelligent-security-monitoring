from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
from threading import Lock


class SlidingWindowRateLimiter:
    def __init__(self, limit: int, window_seconds: int, max_buckets: int = 10_000) -> None:
        self.limit = limit
        self.window = timedelta(seconds=window_seconds)
        self.max_buckets = max_buckets
        self.attempts: dict[str, deque[datetime]] = defaultdict(deque)
        self.lock = Lock()

    def allow(self, key: str) -> bool:
        now = datetime.now(UTC)
        with self.lock:
            if key not in self.attempts and len(self.attempts) >= self.max_buckets:
                for candidate, candidate_bucket in list(self.attempts.items()):
                    while candidate_bucket and now - candidate_bucket[0] > self.window:
                        candidate_bucket.popleft()
                    if not candidate_bucket:
                        self.attempts.pop(candidate, None)
                while len(self.attempts) >= self.max_buckets:
                    self.attempts.pop(next(iter(self.attempts)))
            bucket = self.attempts[key]
            while bucket and now - bucket[0] > self.window:
                bucket.popleft()
            if len(bucket) >= self.limit:
                return False
            bucket.append(now)
            return True

    def reset(self, key: str) -> None:
        with self.lock:
            self.attempts.pop(key, None)
