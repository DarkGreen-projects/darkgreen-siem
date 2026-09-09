from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

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


def health_status(silent_for_seconds: int | None) -> str:
    if silent_for_seconds is None:
        return "silent"
    if silent_for_seconds < 5 * 60:
        return "ok"
    if silent_for_seconds < 30 * 60:
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
