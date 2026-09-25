from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from typing import Callable

from .input_limits import MAX_SYSLOG_BYTES, SYSLOG_RATE_LIMIT, SYSLOG_RATE_WINDOW_SEC

logger = logging.getLogger("syslog")


class _RateLimiter:
    """Simple per-host token window (in-memory, lab-scale)."""

    def __init__(self, limit: int, window_sec: float) -> None:
        self.limit = limit
        self.window = window_sec
        self._buckets: dict[str, list[float]] = defaultdict(list)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        bucket = self._buckets[key]
        cutoff = now - self.window
        while bucket and bucket[0] < cutoff:
            bucket.pop(0)
        if len(bucket) >= self.limit:
            return False
        bucket.append(now)
        return True


class SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, on_message: Callable[[str, str], None]):
        self.on_message = on_message
        self._limiter = _RateLimiter(SYSLOG_RATE_LIMIT, SYSLOG_RATE_WINDOW_SEC)
        self._dropped = 0

    def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[no-untyped-def]
        try:
            host = addr[0] if addr else "unknown"
            if len(data) > MAX_SYSLOG_BYTES:
                self._dropped += 1
                if self._dropped % 50 == 1:
                    logger.warning(
                        "Syslog datagram too large from %s (%s bytes, max %s)",
                        host,
                        len(data),
                        MAX_SYSLOG_BYTES,
                    )
                return
            if not self._limiter.allow(host):
                self._dropped += 1
                if self._dropped % 100 == 1:
                    logger.warning("Syslog rate limit hit for %s (dropped=%s)", host, self._dropped)
                return
            text = data.decode("utf-8", errors="replace").strip()
            if not text:
                return
            self.on_message(text, host)
        except Exception:
            logger.exception("Failed to handle syslog datagram")


async def start_syslog_server(host: str, port: int, on_message: Callable[[str, str], None]):
    loop = asyncio.get_running_loop()
    transport, _protocol = await loop.create_datagram_endpoint(
        lambda: SyslogProtocol(on_message),
        local_addr=(host, port),
    )
    logger.info("Syslog UDP listening on %s:%s (max %s bytes)", host, port, MAX_SYSLOG_BYTES)
    return transport
