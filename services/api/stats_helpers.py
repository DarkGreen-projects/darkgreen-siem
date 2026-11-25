from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

KNOWN_SOURCES = ("firewall", "windows", "cloud_auth", "siem_export")

# range_key -> (window, bucket_size, bucket_count)
RANGE_SPECS: dict[str, tuple[timedelta, timedelta, int]] = {
    "1h": (timedelta(hours=1), timedelta(minutes=5), 12),
    "1d": (timedelta(days=1), timedelta(hours=1), 24),
    "7d": (timedelta(days=7), timedelta(hours=6), 28),
    "30d": (timedelta(days=30), timedelta(days=1), 30),
    "1y": (timedelta(days=365), timedelta(days=30), 12),
}


def normalize_range(range_key: str | None) -> str:
    key = (range_key or "1h").strip().lower()
    return key if key in RANGE_SPECS else "1h"


def build_bucket_bounds(
    range_key: str, now: datetime | None = None
) -> list[tuple[datetime, datetime]]:
    """Return chronological list of [start, end) bucket bounds for the range."""
    key = normalize_range(range_key)
    _window, bucket, count = RANGE_SPECS[key]
    now = now or datetime.now(timezone.utc)
    bounds: list[tuple[datetime, datetime]] = []
    for i in range(count - 1, -1, -1):
        start = now - bucket * (i + 1)
        end = now - bucket * i
        bounds.append((start, end))
    return bounds


def build_timeline(
    db: Session,
    *,
    tenant_id: str,
    range_key: str,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Single-query timeline buckets (source counts) for a range."""
    from .models import Event

    now = now or datetime.now(timezone.utc)
    key = normalize_range(range_key)
    bounds = build_bucket_bounds(key, now)
    if not bounds:
        return []
    _window, bucket, count = RANGE_SPECS[key]
    bucket_sec = max(1, int(bucket.total_seconds()))
    window_start = bounds[0][0]
    window_end = bounds[-1][1]
    start_epoch = window_start.timestamp()

    bucket_idx = func.floor(
        (func.extract("epoch", Event.timestamp) - start_epoch) / float(bucket_sec)
    )
    rows = db.execute(
        select(bucket_idx, Event.source_type, func.count())
        .where(
            and_(
                Event.tenant_id == tenant_id,
                Event.timestamp >= window_start,
                Event.timestamp < window_end,
            )
        )
        .group_by(bucket_idx, Event.source_type)
    ).all()

    by_bucket: dict[int, dict[str, int]] = {i: {} for i in range(count)}
    for idx, source_type, n in rows:
        try:
            i = int(idx)
        except (TypeError, ValueError):
            continue
        if i < 0 or i >= count:
            continue
        by_bucket[i][str(source_type)] = int(n)

    timeline: list[dict[str, Any]] = []
    for i, (start, _end) in enumerate(bounds):
        by_src = by_bucket.get(i) or {}
        timeline.append(
            {
                "bucket": start.isoformat(),
                "count": sum(by_src.values()),
                "by_source": by_src,
            }
        )
    return timeline


def health_status(
    silent_for_seconds: int | None,
    *,
    stale_minutes: int = 5,
    silent_minutes: int = 30,
) -> str:
    if silent_for_seconds is None:
        return "silent"
    stale_sec = max(1, int(stale_minutes)) * 60
    silent_sec = max(stale_sec, int(silent_minutes) * 60)
    if silent_for_seconds < stale_sec:
        return "ok"
    if silent_for_seconds < silent_sec:
        return "stale"
    return "silent"


def threat_brief_lookup(rules: list[dict[str, Any]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for rule in rules:
        rid = str(rule.get("id") or "")
        brief = (rule.get("threat_brief") or "").strip()
        if rid and brief:
            out[rid] = brief
    return out


def resolve_threat_brief(
    rule_id: str,
    evidence: dict[str, Any] | None,
    briefs: dict[str, str],
) -> str | None:
    if evidence:
        existing = evidence.get("threat_brief")
        if isinstance(existing, str) and existing.strip():
            return existing.strip()
    return briefs.get(rule_id)
