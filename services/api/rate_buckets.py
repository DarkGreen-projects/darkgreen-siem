"""Postgres-backed fixed-window rate counters with in-memory fallback."""

from __future__ import annotations

import logging
import time
from threading import Lock

from sqlalchemy.orm import Session

logger = logging.getLogger("darkgreen-siem.rate")

_mem_lock = Lock()
_mem: dict[str, tuple[int, int]] = {}  # key -> (window_id, count)


def _window_id(window_sec: float) -> int:
    w = max(1, int(window_sec))
    return int(time.time()) // w


def allow_memory(key: str, *, limit: int, window_sec: float) -> bool:
    wid = _window_id(window_sec)
    full = f"{key}:{wid}"
    with _mem_lock:
        cur_wid, count = _mem.get(full, (wid, 0))
        if cur_wid != wid:
            count = 0
        if count >= max(1, int(limit)):
            return False
        _mem[full] = (wid, count + 1)
        # prune old keys occasionally
        if len(_mem) > 2000:
            for k in list(_mem.keys())[:400]:
                if not k.endswith(f":{wid}"):
                    _mem.pop(k, None)
        return True


def allow_db(
    db: Session | None,
    key: str,
    *,
    limit: int,
    window_sec: float,
    tenant_id: str = "lab",
) -> bool:
    """Increment fixed-window counter. Falls back to memory if db is None/errors."""
    if db is None:
        return allow_memory(key, limit=limit, window_sec=window_sec)
    try:
        from .models import RateBucket

        wid = _window_id(window_sec)
        bucket_key = f"{tenant_id}:{key}:{wid}"
        row = db.get(RateBucket, bucket_key)
        if row is None:
            db.add(
                RateBucket(
                    bucket_key=bucket_key,
                    tenant_id=tenant_id,
                    window_id=wid,
                    count=1,
                )
            )
            db.commit()
            return True
        if int(row.count or 0) >= max(1, int(limit)):
            return False
        row.count = int(row.count or 0) + 1
        db.commit()
        return True
    except Exception:
        logger.debug("rate_buckets db fallback to memory", exc_info=True)
        try:
            db.rollback()
        except Exception:
            pass
        return allow_memory(key, limit=limit, window_sec=window_sec)


def reset_memory_for_tests() -> None:
    with _mem_lock:
        _mem.clear()
