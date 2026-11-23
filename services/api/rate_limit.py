"""Simple in-process sliding-window rate limits (lab scale)."""

from __future__ import annotations

import time
from collections import defaultdict
from threading import Lock

from fastapi import HTTPException, Request


class SlidingWindowLimiter:
    def __init__(self, limit: int, window_sec: float) -> None:
        self.limit = max(1, int(limit))
        self.window = float(window_sec)
        self._buckets: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets[key]
            cutoff = now - self.window
            while bucket and bucket[0] < cutoff:
                bucket.pop(0)
            if len(bucket) >= self.limit:
                return False
            bucket.append(now)
            return True

    def retry_after_sec(self) -> int:
        return max(1, int(self.window))


_login_limiter = SlidingWindowLimiter(10, 60.0)
_ingest_limiter = SlidingWindowLimiter(60, 60.0)


def client_ip(request: Request) -> str:
    forwarded = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    if forwarded:
        return forwarded
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def enforce_login_rate(request: Request) -> None:
    ip = client_ip(request)
    if not _login_limiter.allow(f"login:{ip}"):
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts",
            headers={"Retry-After": str(_login_limiter.retry_after_sec())},
        )


def enforce_ingest_rate(request: Request, *, identity: str) -> None:
    ip = client_ip(request)
    key = f"ingest:{identity}:{ip}"
    if not _ingest_limiter.allow(key):
        raise HTTPException(
            status_code=429,
            detail="Ingest rate limit exceeded",
            headers={"Retry-After": str(_ingest_limiter.retry_after_sec())},
        )


def reset_limiters_for_tests() -> None:
    """Clear buckets (tests only)."""
    global _login_limiter, _ingest_limiter
    _login_limiter = SlidingWindowLimiter(10, 60.0)
    _ingest_limiter = SlidingWindowLimiter(60, 60.0)
