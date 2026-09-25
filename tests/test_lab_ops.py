"""Lab ops: setup, health thresholds, CSV export, quick queries (no DB)."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.api.alert_export import alerts_to_csv
from services.api.config import Settings
from services.api.lab_settings import reset_lab_state_for_tests, update_lab_state
from services.api.stats_helpers import health_status


def test_health_status_custom_thresholds():
    assert health_status(60, stale_minutes=2, silent_minutes=10) == "ok"
    assert health_status(180, stale_minutes=2, silent_minutes=10) == "stale"
    assert health_status(700, stale_minutes=2, silent_minutes=10) == "silent"
    assert health_status(None, stale_minutes=2, silent_minutes=10) == "silent"


def test_health_status_defaults_unchanged():
    assert health_status(30) == "ok"
    assert health_status(600) == "stale"
    assert health_status(3600) == "silent"


def test_lab_settings_patch_roundtrip():
    reset_lab_state_for_tests(
        Settings(
            retention_days=7,
            health_stale_minutes=5,
            health_silent_minutes=30,
            silence_alerts_enabled=True,
            purge_interval_sec=300,
        )
    )
    state = update_lab_state(
        retention_days=0,
        health_stale_minutes=3,
        health_silent_minutes=15,
        silence_alerts_enabled=False,
    )
    assert state.retention_days == 0
    assert state.health_stale_minutes == 3
    assert state.health_silent_minutes == 15
    assert state.silence_alerts_enabled is False


def test_lab_settings_rejects_silent_lt_stale():
    reset_lab_state_for_tests(Settings(health_stale_minutes=10, health_silent_minutes=30))
    try:
        update_lab_state(health_silent_minutes=5)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_alerts_csv_header_and_iocs():
    alert = SimpleNamespace(
        id=1,
        rule_id="firewall-deny-hot-dst",
        rule_name="Hot dst",
        severity="high",
        title="Deny to 203.0.113.200",
        description="blocked",
        status="open",
        evidence={
            "sample": {
                "src_ip": "10.0.20.15",
                "dst_ip": "203.0.113.200",
                "user": "j.doe",
                "host": "fw-edge-01",
                "message": "deny",
            }
        },
        created_at=datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc),
    )
    csv_text = alerts_to_csv([alert])
    lines = csv_text.strip().splitlines()
    assert lines[0].startswith(
        "id,created_at,status,rule_id,rule_name,severity,title,src_ip,dst_ip,user,host,iocs"
    )
    assert "firewall-deny-hot-dst" in lines[1]
    assert "203.0.113.200" in lines[1]


def test_quick_queries_include_audit_cleared():
    text = (ROOT / "web" / "src" / "savedQueries.ts").read_text(encoding="utf-8")
    assert "action:audit_cleared" in text
    assert text.count("id:") >= 5
    panel = (ROOT / "web" / "src" / "components" / "SearchPanel.tsx").read_text(encoding="utf-8")
    assert "Ricerche predefinite" in panel
