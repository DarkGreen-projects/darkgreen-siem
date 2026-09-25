"""Alert SLA: defaults, ack/close met/breach, disabled=0, setup normalize."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.api.sla import (
    DEFAULT_SLA_ACK_MINUTES,
    DEFAULT_SLA_CLOSE_MINUTES,
    alert_matches_sla_filter,
    compute_alert_sla,
    normalize_sla_map,
)


def test_default_maps():
    assert DEFAULT_SLA_ACK_MINUTES["critical"] == 15
    assert DEFAULT_SLA_CLOSE_MINUTES["high"] == 480


def test_normalize_partial_and_zero():
    m = normalize_sla_map({"critical": 5, "high": 0}, defaults=DEFAULT_SLA_ACK_MINUTES)
    assert m["critical"] == 5
    assert m["high"] == 0
    assert m["medium"] == DEFAULT_SLA_ACK_MINUTES["medium"]


def test_normalize_rejects_bad_key_value():
    try:
        normalize_sla_map({"critical": -1})
        assert False, "expected error"
    except ValueError:
        pass


def test_ack_met_within_target():
    created = datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)
    alert = SimpleNamespace(
        severity="critical",
        status="acked",
        created_at=created,
        acked_at=created + timedelta(minutes=10),
        closed_at=None,
    )
    sla = compute_alert_sla(
        alert,
        ack_map={"critical": 15, "high": 30, "medium": 240, "low": 1440},
        close_map=DEFAULT_SLA_CLOSE_MINUTES,
        now=created + timedelta(minutes=20),
    )
    assert sla["sla_ack_status"] == "met"
    assert sla["sla_close_status"] == "ok"


def test_ack_breached_still_open():
    created = datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)
    alert = SimpleNamespace(
        severity="high",
        status="open",
        created_at=created,
        acked_at=None,
        closed_at=None,
    )
    sla = compute_alert_sla(
        alert,
        ack_map={"critical": 15, "high": 30, "medium": 240, "low": 1440},
        close_map=DEFAULT_SLA_CLOSE_MINUTES,
        now=created + timedelta(minutes=45),
    )
    assert sla["sla_ack_status"] == "breached"


def test_ack_at_risk():
    created = datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)
    alert = SimpleNamespace(
        severity="high",
        status="open",
        created_at=created,
        acked_at=None,
        closed_at=None,
    )
    # 30 min target, 80% = 24 min
    sla = compute_alert_sla(
        alert,
        ack_map={"critical": 15, "high": 30, "medium": 240, "low": 1440},
        close_map=DEFAULT_SLA_CLOSE_MINUTES,
        now=created + timedelta(minutes=25),
    )
    assert sla["sla_ack_status"] == "at_risk"


def test_close_met_and_breached():
    created = datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)
    met = SimpleNamespace(
        severity="critical",
        status="closed",
        created_at=created,
        acked_at=created + timedelta(minutes=5),
        closed_at=created + timedelta(minutes=60),
    )
    s1 = compute_alert_sla(
        met,
        ack_map=DEFAULT_SLA_ACK_MINUTES,
        close_map={"critical": 120, "high": 480, "medium": 1440, "low": 10080},
        now=created + timedelta(hours=3),
    )
    assert s1["sla_close_status"] == "met"

    late = SimpleNamespace(
        severity="critical",
        status="closed",
        created_at=created,
        acked_at=created + timedelta(minutes=5),
        closed_at=created + timedelta(minutes=200),
    )
    s2 = compute_alert_sla(
        late,
        ack_map=DEFAULT_SLA_ACK_MINUTES,
        close_map={"critical": 120, "high": 480, "medium": 1440, "low": 10080},
        now=created + timedelta(hours=5),
    )
    assert s2["sla_close_status"] == "breached"


def test_zero_minutes_is_na():
    created = datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)
    alert = SimpleNamespace(
        severity="low",
        status="open",
        created_at=created,
        acked_at=None,
        closed_at=None,
    )
    sla = compute_alert_sla(
        alert,
        ack_map={"critical": 15, "high": 30, "medium": 240, "low": 0},
        close_map={"critical": 120, "high": 480, "medium": 1440, "low": 0},
        now=created + timedelta(days=2),
    )
    assert sla["sla_ack_status"] == "na"
    assert sla["sla_close_status"] == "na"


def test_sla_filter_match():
    fields = {"sla_ack_status": "breached", "sla_close_status": "ok"}
    assert alert_matches_sla_filter(fields, "breached")
    assert alert_matches_sla_filter(fields, "ok")
    assert not alert_matches_sla_filter(fields, "met")
