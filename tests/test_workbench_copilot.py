"""Workbench queue ranking, briefing, and LLM copilot fail-soft."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.api.copilot import suggest_closure
from services.api.triage_brief import build_alert_brief, queue_sort_key


def _alert_out(**kwargs):
    base = {
        "severity": "medium",
        "noise_hint": "unclear",
        "sla_ack_status": "ok",
        "sla_close_status": "ok",
        "created_at": datetime.now(timezone.utc),
    }
    base.update(kwargs)
    return SimpleNamespace(**base)


def test_queue_sort_sla_breached_first():
    now = datetime.now(timezone.utc)
    breached = _alert_out(
        severity="low",
        noise_hint="likely_noise",
        sla_ack_status="breached",
        created_at=now,
    )
    signal = _alert_out(
        severity="critical",
        noise_hint="likely_signal",
        sla_ack_status="ok",
        created_at=now - timedelta(hours=1),
    )
    rows = [signal, breached]
    rows.sort(key=queue_sort_key)
    assert rows[0] is breached


def test_queue_sort_signal_before_noise():
    now = datetime.now(timezone.utc)
    noise = _alert_out(noise_hint="likely_noise", severity="high", created_at=now)
    signal = _alert_out(noise_hint="likely_signal", severity="high", created_at=now)
    rows = [noise, signal]
    rows.sort(key=queue_sort_key)
    assert rows[0] is signal


def test_build_alert_brief_entities_and_pivot():
    alert = SimpleNamespace(
        id=42,
        title="Suspicious login",
        severity="high",
        status="open",
        mitre="T1110",
        rule_id="r-login",
        rule_name="Login spray",
        noise_hint="likely_signal",
        risk_score=70,
        evidence={
            "sample": {"src_ip": "203.0.113.9", "host": "ws1", "user": "alice"},
            "threat_brief": "Possible spray",
        },
        created_at=datetime.now(timezone.utc),
        acked_at=None,
        closed_at=None,
    )
    with patch("services.api.triage_brief.find_similar_alerts", return_value=[]):
        brief = build_alert_brief(alert, db=MagicMock(), prior_days=30)
    assert brief["alert_id"] == 42
    assert "Suspicious login" in brief["summary"]
    assert brief["entities"]["src_ip"] == "203.0.113.9"
    assert brief["pivot_query"] == "src_ip:203.0.113.9"
    assert brief["mitre"] == "T1110"
    assert brief["similar_count"] == 0


def test_build_alert_brief_counts_similar_fp_tp():
    alert = SimpleNamespace(
        id=1,
        title="t",
        severity="medium",
        status="open",
        mitre=None,
        rule_id="r1",
        rule_name="r",
        noise_hint=None,
        risk_score=None,
        evidence={"sample": {"host": "h1"}},
        created_at=datetime.now(timezone.utc),
        acked_at=None,
        closed_at=None,
    )
    similar = [
        SimpleNamespace(disposition="false_positive"),
        SimpleNamespace(disposition="benign"),
        SimpleNamespace(disposition="true_positive"),
    ]
    with patch("services.api.triage_brief.find_similar_alerts", return_value=similar):
        brief = build_alert_brief(alert, db=MagicMock())
    assert brief["similar_count"] == 3
    assert brief["similar_fp"] == 2
    assert brief["similar_tp"] == 1
    assert brief["pivot_query"] == "host:h1"


def test_copilot_soft_fail_without_key():
    state = SimpleNamespace(
        llm_enabled=True,
        llm_api_key="",
        llm_api_url="https://api.openai.com/v1/chat/completions",
        llm_model="gpt-4o-mini",
    )
    with patch("services.api.copilot.get_lab_state", return_value=state):
        out = suggest_closure({"summary": "test"})
    assert out["available"] is False
    assert out["suggested_disposition"] is None
    assert "LLM" in (out["message"] or "")


def test_copilot_soft_fail_when_disabled():
    state = SimpleNamespace(
        llm_enabled=False,
        llm_api_key="sk-test",
        llm_api_url="https://api.openai.com/v1/chat/completions",
        llm_model="gpt-4o-mini",
    )
    with patch("services.api.copilot.get_lab_state", return_value=state):
        out = suggest_closure({"summary": "test"})
    assert out["available"] is False


def test_copilot_suggest_parses_llm_json():
    state = SimpleNamespace(
        llm_enabled=True,
        llm_api_key="sk-test",
        llm_api_url="https://example.test/v1/chat/completions",
        llm_model="gpt-4o-mini",
    )
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": (
                        '{"disposition":"false_positive",'
                        '"note":"Verificato traffic benigno da scanner interno.",'
                        '"rationale":"Molti FP simili"}'
                    )
                }
            }
        ]
    }
    fake_client = MagicMock()
    fake_client.__enter__.return_value = fake_client
    fake_client.__exit__.return_value = None
    fake_client.post.return_value = fake_resp

    with (
        patch("services.api.copilot.get_lab_state", return_value=state),
        patch(
            "services.api.url_safety.validate_egress_url",
            side_effect=lambda u, purpose="egress": u,
        ),
        patch("services.api.copilot.httpx.Client", return_value=fake_client),
    ):
        out = suggest_closure(
            {
                "summary": "Alert #1",
                "similar_fp": 1,
                "similar_tp": 1,
                "noise_hint": "unclear",
                "cases": [],
            }
        )
    assert out["available"] is True
    assert out["source"] == "llm_rag"
    assert out["suggested_disposition"] == "false_positive"
    assert "scanner" in (out["suggested_note"] or "").lower()
    fake_client.post.assert_called_once()


def test_copilot_http_error_fail_soft():
    state = SimpleNamespace(
        llm_enabled=True,
        llm_api_key="sk-test",
        llm_api_url="https://example.test/v1/chat/completions",
        llm_model="gpt-4o-mini",
    )
    fake_resp = MagicMock()
    fake_resp.status_code = 500
    fake_resp.text = "boom"
    fake_client = MagicMock()
    fake_client.__enter__.return_value = fake_client
    fake_client.__exit__.return_value = None
    fake_client.post.return_value = fake_resp

    with (
        patch("services.api.copilot.get_lab_state", return_value=state),
        patch(
            "services.api.url_safety.validate_egress_url",
            side_effect=lambda u, purpose="egress": u,
        ),
        patch("services.api.copilot.httpx.Client", return_value=fake_client),
    ):
        out = suggest_closure({"summary": "x"})
    assert out["available"] is False
    assert out["message"] == "LLM unavailable"
