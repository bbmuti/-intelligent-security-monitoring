from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
from threading import Lock


class SlidingWindowRateLimiter:
    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window = timedelta(seconds=window_seconds)
        self.attempts: dict[str, deque[datetime]] = defaultdict(deque)
        self.lock = Lock()

    def allow(self, key: str) -> bool:
        now = datetime.now(UTC)
        with self.lock:
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
