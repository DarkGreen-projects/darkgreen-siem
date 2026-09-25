"""Correlation, syslog detect, VT cache classify, audit helpers."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.api.rule_validate import RuleValidationError, validate_rule_payload
from services.api.rules_engine import evaluate_correlation_rule
from services.api.syslog_detect import detect_syslog_source
from services.api.vt_enrich import _classify


def test_validate_correlation_ok():
    rule = validate_rule_payload(
        {
            "id": "spray-then-success",
            "name": "Spray then success",
            "type": "correlation",
            "severity": "critical",
            "join_on": "src_ip",
            "window_minutes": 30,
            "steps": [
                {"match": {"source_type": "windows", "action": "login_failed"}, "min_count": 5},
                {"match": {"source_type": "windows", "action": "login_success"}, "min_count": 1},
            ],
        }
    )
    assert rule["type"] == "correlation"
    assert rule["join_on"] == "src_ip"
    assert len(rule["steps"]) == 2


def test_validate_correlation_needs_two_steps():
    try:
        validate_rule_payload(
            {
                "id": "bad-corr",
                "name": "x",
                "type": "correlation",
                "steps": [{"match": {"action": "deny"}, "min_count": 1}],
            }
        )
        assert False, "expected error"
    except RuleValidationError as exc:
        assert "2 steps" in str(exc)


def test_yaml_spray_then_success_loads():
    import yaml

    raw = yaml.safe_load((ROOT / "rules" / "spray-then-success.yml").read_text(encoding="utf-8"))
    validated = validate_rule_payload(raw)
    assert validated["id"] == "spray-then-success"


def _ev(i: int, action: str, src: str) -> SimpleNamespace:
    return SimpleNamespace(
        id=i,
        action=action,
        source_type="windows",
        src_ip=src,
        dst_ip=None,
        user="u",
        host="h",
        message=action,
        timestamp=datetime.now(timezone.utc),
    )


def test_correlation_joins_fail_then_success():
    events = [_ev(i, "login_failed", "203.0.113.45") for i in range(1, 7)]
    events.append(_ev(99, "login_success", "203.0.113.45"))
    events.append(_ev(100, "login_failed", "198.51.100.1"))

    db = MagicMock()
    db.scalars.return_value.all.return_value = events
    db.scalar.return_value = 0  # no recent alert

    rule = {
        "id": "spray-then-success",
        "name": "Spray then success",
        "type": "correlation",
        "join_on": "src_ip",
        "window_minutes": 30,
        "cooldown_minutes": 60,
        "severity": "critical",
        "steps": [
            {"match": {"source_type": "windows", "action": "login_failed"}, "min_count": 5},
            {"match": {"source_type": "windows", "action": "login_success"}, "min_count": 1},
        ],
    }
    alert, _ = evaluate_correlation_rule(db, rule)
    assert alert is not None
    assert alert.evidence["join_key"] == "203.0.113.45"


def test_detect_syslog_windows_json():
    assert (
        detect_syslog_source(
            '{"EventID":4625,"Channel":"Security","Computer":"win-dc01"}'
        )
        == "windows"
    )
    assert detect_syslog_source('devname="fw" action=deny') == "firewall"


def test_vt_classify():
    assert _classify({"malicious": 2, "harmless": 10})[0] == "malicious"
    assert _classify({"suspicious": 1, "harmless": 10})[0] == "suspicious"
    assert _classify({"harmless": 40})[0] == "harmless"


def test_collectors_doc_exists():
    assert (ROOT / "docs" / "collectors-windows-syslog.md").exists()
    assert (ROOT / "docs" / "samples" / "nxlog-windows.conf").exists()
