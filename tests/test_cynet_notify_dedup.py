"""Cynet normalizer, labels.* match, MITRE, dry-run, notify, alert merge."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.api.notify import notify_alert_opened
from services.api.rule_validate import RuleValidationError, validate_rule_payload
from services.api.rules_engine import (
    _entity_key,
    _finalize_alert,
    _merge_alert,
    dry_run_rules,
    evaluate_match_rule,
)
from services.normalizers import normalize_event


def test_cynet_field_map_process_hash_mitre():
    payload = {
        "Product": "Cynet",
        "Activity": "Malware Detected",
        "Severity": "Critical",
        "Hostname": "win-ws42.lab.local",
        "User": "svc.backup",
        "SourceIP": "10.0.20.42",
        "category": "malware",
        "FileHash": "a" * 64,
        "ProcessName": "invoice.exe",
        "ProcessPath": "C:\\Temp\\invoice.exe",
        "CommandLine": "invoice.exe /silent",
        "ParentProcess": "explorer.exe",
        "MitreTechnique": "T1204.002",
        "SensorId": "CY-SENSOR-42",
        "FileName": "invoice.exe",
        "DetectionName": "Trojan.Generic.KD",
    }
    ev = normalize_event(payload, source_type="siem_export")
    assert ev.source_type == "siem_export"
    assert ev.vendor == "Cynet"
    assert ev.action == "malware_detected"
    assert ev.severity == "critical"
    assert ev.labels.get("hash") == "a" * 64
    assert ev.labels.get("hash_type") == "sha256"
    assert ev.labels.get("process") == "invoice.exe"
    assert ev.labels.get("cmdline") == "invoice.exe /silent"
    assert ev.labels.get("parent_process") == "explorer.exe"
    assert ev.labels.get("technique") == "T1204.002"
    assert ev.labels.get("sensor_id") == "CY-SENSOR-42"


def test_labels_match_filter():
    from services.api.rules_engine import _match_filters

    ev = SimpleNamespace(
        source_type="siem_export",
        action="malware_detected",
        labels={"hash": "abc", "category": "malware", "process": "powershell.exe"},
    )
    assert _match_filters(
        ev,
        {
            "source_type": "siem_export",
            "labels.hash": "abc",
            "labels.category": "malware",
        },
    )
    assert not _match_filters(ev, {"labels.hash": "zzz"})


def test_mitre_validate_string_and_list():
    base = {
        "id": "demo-mitre",
        "name": "Demo",
        "type": "match",
        "severity": "high",
        "match": {"action": "deny"},
    }
    out = validate_rule_payload({**base, "mitre": "T1059.001"})
    assert out["mitre"] == "T1059.001"
    out2 = validate_rule_payload({**base, "mitre": ["T1204", "T1059.001"]})
    assert "T1204" in out2["mitre"]
    try:
        validate_rule_payload({**base, "mitre": "not-a-technique"})
        assert False, "expected validation error"
    except RuleValidationError:
        pass


def test_merge_increments_occurrences():
    existing = SimpleNamespace(
        evidence={"occurrences": 1, "count": 3, "event_ids": [1], "entity_key": "host:a"}
    )
    merged = _merge_alert(
        existing,  # type: ignore[arg-type]
        {"count": 5, "event_ids": [2, 3], "entity_key": "host:a", "sample": {"host": "a"}},
    )
    assert merged.evidence["occurrences"] == 2
    assert 2 in merged.evidence["event_ids"]
    assert merged.evidence["count"] == 5


def test_entity_key_from_sample():
    key = _entity_key(
        {"id": "r1"},
        {"sample": {"src_ip": "1.2.3.4", "host": "h1"}},
    )
    assert key == "src_ip:1.2.3.4"


def test_finalize_dry_run_no_db_write():
    db = MagicMock()
    alert = SimpleNamespace(
        tenant_id="lab",
        rule_id="r1",
        mitre=None,
        evidence={"sample": {"host": "win1"}, "count": 1},
    )
    rule = {"id": "r1", "mitre": "T1059.001"}
    out, created = _finalize_alert(db, rule, alert, cooldown_minutes=15, dry_run=True)  # type: ignore[arg-type]
    assert created is True
    assert out is not None
    assert out.mitre == "T1059.001"
    assert out.evidence.get("entity_key") == "host:win1"
    db.add.assert_not_called()


def test_dry_run_rules_match_without_persist(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "cynet-malware-hash.yml").write_text(
        """
id: cynet-malware-hash
name: Cynet malware
title: Malware
type: match
severity: critical
enabled: true
mitre: T1204.002
window_minutes: 60
cooldown_minutes: 30
match:
  source_type: siem_export
  action: malware_detected
  labels.category: malware
""".strip(),
        encoding="utf-8",
    )
    events = [
        {
            "Product": "Cynet",
            "Activity": "Malware Detected",
            "Severity": "high",
            "Hostname": "win-ws42.lab.local",
            "category": "malware",
            "Sha256": "b" * 64,
        }
    ]
    db = MagicMock()
    hits, n = dry_run_rules(db, rules_dir, events, tenant_id="lab")
    assert n == 1
    assert len(hits) == 1
    assert hits[0]["rule_id"] == "cynet-malware-hash"
    assert hits[0]["mitre"] == "T1204.002"
    db.add.assert_not_called()
    db.commit.assert_not_called()


def test_notify_slack_payload_mocked():
    alert = SimpleNamespace(
        id=7,
        title="Malware",
        severity="critical",
        status="open",
        rule_id="cynet-malware-hash",
        rule_name="cynet-malware-hash",
        description="hash present",
        mitre="T1204.002",
        evidence={},
    )
    state = SimpleNamespace(
        notify_webhook_url="https://hooks.example/webhook",
        notify_format="slack",
        notify_min_severity="high",
    )
    with (
        patch("services.api.notify.get_lab_state", return_value=state),
        patch("services.api.notify.httpx.Client") as client_cls,
    ):
        client = MagicMock()
        client.__enter__.return_value = client
        client.__exit__.return_value = False
        client.post.return_value = MagicMock(status_code=200, raise_for_status=MagicMock())
        client_cls.return_value = client
        assert notify_alert_opened(alert) is True
        assert client.post.called
        body = client.post.call_args.kwargs.get("json") or client.post.call_args[1].get("json")
        assert "text" in body
        assert "Malware" in body["text"]


def test_notify_skips_low_severity():
    alert = SimpleNamespace(
        id=1,
        title="x",
        severity="low",
        status="open",
        rule_id="r",
        rule_name="r",
        description="",
        mitre=None,
        evidence={},
    )
    state = SimpleNamespace(
        notify_webhook_url="https://hooks.example/webhook",
        notify_format="slack",
        notify_min_severity="high",
    )
    with patch("services.api.notify.get_lab_state", return_value=state):
        assert notify_alert_opened(alert) is False
