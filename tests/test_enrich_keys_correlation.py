"""Enrichment API keys, multi-provider enrich, correlation enrich steps."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.api.config import Settings
from services.api.enrich_providers import classify_vt_stats, enrich_ioc, keys_matching_enrich
from services.api.lab_settings import (
    enrichment_keys_public,
    mask_secret,
    reset_lab_state_for_tests,
    update_lab_state,
)
from services.api.rule_validate import validate_rule_payload
from services.api.rules_engine import evaluate_correlation_rule


def test_mask_secret():
    assert mask_secret("") is None
    assert mask_secret("abcd") == "****"
    assert mask_secret("supersecretkey") == "****tkey"


def test_setup_keys_patch_and_clear():
    reset_lab_state_for_tests(
        Settings(vt_api_key="", abuseipdb_api_key="", otx_api_key="")
    )
    update_lab_state(vt_api_key="vt-secret-12345", abuseipdb_api_key="abuse-abcdef")
    pub = enrichment_keys_public()
    assert pub["vt_configured"] is True
    assert pub["vt_api_key_masked"] == "****2345"
    assert pub["abuseipdb_configured"] is True
    update_lab_state(vt_api_key="CLEAR")
    pub2 = enrichment_keys_public()
    assert pub2["vt_configured"] is False


def test_enrich_skip_without_key():
    reset_lab_state_for_tests(Settings(vt_api_key=""))
    db = MagicMock()
    res = enrich_ioc(db, provider="vt", ioc_type="ip", value="203.0.113.1")
    assert res["available"] is False
    assert "not configured" in (res.get("message") or "")


def test_classify_vt_stats():
    assert classify_vt_stats({"malicious": 3})[0] == "malicious"
    assert classify_vt_stats({"suspicious": 1})[0] == "suspicious"


def test_validate_correlation_enrich_step():
    rule = validate_rule_payload(
        {
            "id": "spray-then-malicious-ip",
            "name": "Spray malicious",
            "type": "correlation",
            "join_on": "src_ip",
            "steps": [
                {"match": {"source_type": "windows", "action": "login_failed"}, "min_count": 5},
                {
                    "enrich": {
                        "providers": ["vt", "abuseipdb"],
                        "verdicts": ["malicious"],
                        "ioc_type": "ip",
                    }
                },
            ],
        }
    )
    assert rule["steps"][1]["enrich"]["providers"] == ["vt", "abuseipdb"]


def test_yaml_spray_then_malicious_loads():
    import yaml

    raw = yaml.safe_load(
        (ROOT / "rules" / "spray-then-malicious-ip.yml").read_text(encoding="utf-8")
    )
    validated = validate_rule_payload(raw)
    assert validated["id"] == "spray-then-malicious-ip"
    assert "enrich" in validated["steps"][1]


def test_correlation_enrich_uses_cache_keys():
    events = [
        SimpleNamespace(
            id=i,
            action="login_failed",
            source_type="windows",
            src_ip="203.0.113.45",
            dst_ip=None,
            user="u",
            host="h",
            message="fail",
            timestamp=datetime.now(timezone.utc),
        )
        for i in range(6)
    ]
    db = MagicMock()
    db.scalars.return_value.all.return_value = events
    db.scalar.return_value = 0

    rule = {
        "id": "spray-then-malicious-ip",
        "name": "x",
        "join_on": "src_ip",
        "window_minutes": 30,
        "cooldown_minutes": 60,
        "steps": [
            {"match": {"source_type": "windows", "action": "login_failed"}, "min_count": 5},
            {
                "enrich": {
                    "providers": ["vt"],
                    "verdicts": ["malicious"],
                    "ioc_type": "ip",
                }
            },
        ],
    }
    with patch(
        "services.api.rules_engine.keys_matching_enrich",
        return_value={"203.0.113.45"},
    ):
        alert, _ = evaluate_correlation_rule(db, rule)
        alert = alert[0] if isinstance(alert, tuple) else alert
    assert alert is not None
    assert alert.evidence["join_key"] == "203.0.113.45"
