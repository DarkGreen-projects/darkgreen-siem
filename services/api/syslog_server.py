from __future__ import annotations

import asyncio
import hmac
import logging
import time
from collections import defaultdict
from typing import Callable

from .config import get_settings
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
        # Drop idle keys so unique UDP sources cannot grow memory without bound.
        if len(self._buckets) > 256:
            stale = [k for k, stamps in self._buckets.items() if not stamps or stamps[-1] < cutoff]
            for k in stale[:64]:
                self._buckets.pop(k, None)
        return True


def _prefix_matches(raw: str, prefix: str) -> bool:
    """Constant-time compare for the secret prefix (padding-safe)."""
    if len(raw) < len(prefix):
        return False
    return hmac.compare_digest(raw[: len(prefix)].encode("utf-8"), prefix.encode("utf-8"))


def strip_syslog_shared_secret(text: str, secret: str) -> str | None:
    """
    Accept only messages prefixed with `SECRET ` or `#dg-token=SECRET `.
    Empty secret rejects all datagrams (hard requirement for UDP ingest).
    """
    sec = (secret or "").strip()
    if not sec:
        return None
    raw = text or ""
    prefix_space = f"{sec} "
    prefix_hdr = f"#dg-token={sec} "
    if _prefix_matches(raw, prefix_space):
        return raw[len(prefix_space) :].lstrip()
    if _prefix_matches(raw, prefix_hdr):
        return raw[len(prefix_hdr) :].lstrip()
    # Also allow secret alone as first token after PRI
    if raw.startswith("<") and ">" in raw[:6]:
        pri, rest = raw.split(">", 1)
        stripped = strip_syslog_shared_secret(rest.lstrip(), sec)
        if stripped is None:
            return None
        return f"{pri}>{stripped}"
    return None


class SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(
        self,
        on_message: Callable[[str, str], None],
        *,
        shared_secret: str = "",
        rate_limit: int = SYSLOG_RATE_LIMIT,
        rate_window: float = SYSLOG_RATE_WINDOW_SEC,
    ):
        self.on_message = on_message
        self.shared_secret = shared_secret or ""
        self._limiter = _RateLimiter(rate_limit, rate_window)
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
            body = strip_syslog_shared_secret(text, self.shared_secret)
            if body is None:
                self._dropped += 1
                if self._dropped % 50 == 1:
                    logger.warning(
                        "Syslog shared-secret mismatch from %s (dropped=%s)",
                        host,
                        self._dropped,
                    )
                return
            if not body.strip():
                return
            # Offload sync DB ingest so UDP bursts do not stall the event loop.
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                self.on_message(body, host)
                return
            loop.run_in_executor(None, self.on_message, body, host)
        except Exception:
            logger.exception("Failed to handle syslog datagram")


async def start_syslog_server(host: str, port: int, on_message: Callable[[str, str], None]):
    settings = get_settings()
    secret = (getattr(settings, "syslog_shared_secret", "") or "").strip()
    if not secret:
        logger.error(
            "SYSLOG_SHARED_SECRET empty: UDP ingest will drop all datagrams until configured"
        )
    loop = asyncio.get_running_loop()
    transport, _protocol = await loop.create_datagram_endpoint(
        lambda: SyslogProtocol(on_message, shared_secret=secret),
        local_addr=(host, port),
    )
    logger.info(
        "Syslog UDP listening on %s:%s (max %s bytes, shared_secret=%s)",
        host,
        port,
        MAX_SYSLOG_BYTES,
        "on" if secret else "REQUIRED_MISSING",
    )
    return transport
