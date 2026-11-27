"""Triage disposition, scoring, similar alerts."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.api.triage_score import (
    compute_triage_score,
    count_disposition_priors,
    find_similar_alerts,
)


def test_score_high_severity_signal():
    alert = SimpleNamespace(
        severity="critical",
        mitre="T1059.001",
        evidence={"occurrences": 1},
    )
    out = compute_triage_score(alert, priors={})
    assert out["risk_score"] >= 60
    assert out["noise_hint"] == "likely_signal"


def test_score_fp_priors_likely_noise():
    alert = SimpleNamespace(
        severity="medium",
        mitre=None,
        evidence={"occurrences": 1},
    )
    out = compute_triage_score(
        alert,
        priors={"false_positive": 3, "benign": 0, "true_positive": 0},
    )
    assert out["noise_hint"] == "likely_noise"
    assert out["risk_score"] < 40


def test_score_ti_malicious_floor():
    alert = SimpleNamespace(
        severity="low",
        mitre=None,
        evidence={"occurrences": 1},
    )
    out = compute_triage_score(alert, priors={}, ti_malicious=True)
    assert out["risk_score"] >= 65
    assert out["noise_hint"] == "likely_signal"


def test_score_zero_clamp():
    alert = SimpleNamespace(severity="low", mitre=None, evidence={})
    out = compute_triage_score(
        alert,
        priors={"false_positive": 10, "true_positive": 0, "benign": 0},
    )
    assert 0 <= out["risk_score"] <= 100


def test_find_similar_by_entity_key():
    now = datetime.now(timezone.utc)
    target = SimpleNamespace(
        id=1,
        tenant_id="lab",
        rule_id="r1",
        evidence={"entity_key": "host:ws1"},
    )
    others = [
        SimpleNamespace(
            id=2,
            tenant_id="lab",
            rule_id="r1",
            evidence={"entity_key": "host:ws1"},
            disposition="false_positive",
            created_at=now - timedelta(hours=1),
            closed_at=now,
            status="closed",
            title="a",
            severity="high",
            noise_hint="likely_noise",
            risk_score=20,
        ),
        SimpleNamespace(
            id=3,
            tenant_id="lab",
            rule_id="r1",
            evidence={"entity_key": "host:other"},
            disposition=None,
            created_at=now - timedelta(hours=1),
            closed_at=None,
            status="open",
            title="b",
            severity="high",
            noise_hint=None,
            risk_score=None,
        ),
    ]
    db = MagicMock()
    db.scalars.return_value.all.return_value = others
    found = find_similar_alerts(db, target, days=30, limit=10)
    assert len(found) == 1
    assert found[0].id == 2


def test_count_disposition_priors_filters_entity():
    now = datetime.now(timezone.utc)
    rows = [
        SimpleNamespace(
            disposition="false_positive",
            evidence={"entity_key": "src_ip:1.2.3.4"},
            created_at=now,
        ),
        SimpleNamespace(
            disposition="false_positive",
            evidence={"entity_key": "src_ip:9.9.9.9"},
            created_at=now,
        ),
        SimpleNamespace(
            disposition="true_positive",
            evidence={"entity_key": "src_ip:1.2.3.4"},
            created_at=now,
        ),
    ]
    db = MagicMock()
    db.scalars.return_value.all.return_value = rows
    counts = count_disposition_priors(
        db, tenant_id="lab", rule_id="r1", entity_key="src_ip:1.2.3.4", days=30
    )
    assert counts["false_positive"] == 1
    assert counts["true_positive"] == 1
