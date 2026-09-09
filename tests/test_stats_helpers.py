"""Unit tests for stats range helpers and threat brief resolution."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.api.stats_helpers import (
    build_bucket_bounds,
    health_status,
    normalize_range,
    resolve_threat_brief,
    threat_brief_lookup,
)


def test_normalize_range_default_and_invalid():
    assert normalize_range(None) == "1h"
    assert normalize_range("1d") == "1d"
    assert normalize_range("nope") == "1h"


def test_build_bucket_bounds_1h():
    now = datetime(2026, 9, 9, 12, 0, tzinfo=timezone.utc)
    bounds = build_bucket_bounds("1h", now)
    assert len(bounds) == 12
    assert bounds[0][0] == datetime(2026, 9, 9, 11, 0, tzinfo=timezone.utc)
    assert bounds[-1][1] == now


def test_build_bucket_bounds_1d():
    now = datetime(2026, 9, 9, 12, 0, tzinfo=timezone.utc)
    bounds = build_bucket_bounds("1d", now)
    assert len(bounds) == 24


def test_health_status_thresholds():
    assert health_status(30) == "ok"
    assert health_status(600) == "stale"
    assert health_status(3600) == "silent"
    assert health_status(None) == "silent"


def test_resolve_threat_brief_fallback():
    briefs = threat_brief_lookup(
        [{"id": "r1", "threat_brief": "  From rules  "}, {"id": "r2"}]
    )
    assert briefs["r1"] == "From rules"
    assert resolve_threat_brief("r1", {"threat_brief": "From evidence"}, briefs) == "From evidence"
    assert resolve_threat_brief("r1", {}, briefs) == "From rules"
    assert resolve_threat_brief("missing", {}, briefs) is None
