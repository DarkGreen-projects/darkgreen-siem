"""Alert graph, entity_norm, fingerprint, and copilot related_alert_ids."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.api.alert_fingerprint import build_alert_fingerprint
from services.api.alert_graph import (
    _history_count,
    _mitre_chain_score,
    connected_alerts,
    link_alert,
    links_payload,
)
from services.api.copilot import suggest_closure
from services.api.entity_norm import (
    apply_entity_normalization,
    collect_entity_keys,
    entity_keys_overlap,
    primary_entity_key,
)
from services.api.lab_settings import LabState, reset_lab_state_for_tests
from services.api.models import AlertLink


def test_entity_norm_join_and_src_ip():
    keys = collect_entity_keys(
        {"join_on": "src_ip", "join_key": "10.0.0.5", "sample": {"src_ip": "10.0.0.5"}}
    )
    assert "join:10.0.0.5" in keys
    assert "src_ip:10.0.0.5" in keys
    primary = primary_entity_key(
        {"join_on": "src_ip", "join_key": "10.0.0.5", "sample": {"src_ip": "10.0.0.5"}}
    )
    assert primary.startswith("src_ip:")
    ev = apply_entity_normalization(
        {"join_on": "src_ip", "join_key": "10.0.0.5"}, rule_id="corr-1"
    )
    assert ev["entity_key"]
    assert "entity_keys" in ev
    assert entity_keys_overlap(keys, ["src_ip:10.0.0.5", "host:x"]) == ["src_ip:10.0.0.5"]


def test_mitre_chain_score_follows():
    assert _mitre_chain_score("T1110", "T1078") >= 25
    assert _mitre_chain_score("T1110", "T1110") == 15
    assert _mitre_chain_score(None, "T1059") == 0


def test_link_alert_same_entity_under_history_threshold():
    reset_lab_state_for_tests()
    state = LabState(
        graph_enabled=True,
        graph_window_minutes=120,
        graph_min_history=100,
    )
    now = datetime.now(timezone.utc)
    alert = SimpleNamespace(
        id=10,
        tenant_id="lab",
        created_at=now,
        mitre="T1059",
        evidence={
            "entity_keys": ["src_ip:1.2.3.4", "host:ws1"],
            "entity_key": "src_ip:1.2.3.4",
            "sample": {"src_ip": "1.2.3.4", "host": "ws1"},
        },
    )
    peer = SimpleNamespace(
        id=9,
        tenant_id="lab",
        created_at=now - timedelta(minutes=10),
        mitre="T1110",
        evidence={
            "entity_keys": ["src_ip:1.2.3.4"],
            "entity_key": "src_ip:1.2.3.4",
            "sample": {"src_ip": "1.2.3.4"},
        },
    )
    db = MagicMock()
    db.scalars.return_value.all.return_value = [peer]
    db.scalar.return_value = None
    # history under threshold
    with patch("services.api.lab_settings.get_lab_state", return_value=state), patch(
        "services.api.alert_graph._history_count", return_value=2
    ):
        n = link_alert(db, alert)
    assert n >= 1
    added = [c.args[0] for c in db.add.call_args_list if c.args]
    relations = {getattr(a, "relation", None) for a in added if isinstance(a, AlertLink)}
    assert "same_entity" in relations
    assert "temporal_follows" not in relations
    assert "mitre_chain" not in relations


def test_link_alert_mature_adds_temporal_and_mitre():
    state = LabState(
        graph_enabled=True,
        graph_window_minutes=120,
        graph_min_history=5,
    )
    now = datetime.now(timezone.utc)
    alert = SimpleNamespace(
        id=20,
        tenant_id="lab",
        created_at=now,
        mitre="T1078",
        evidence={
            "entity_keys": ["src_ip:9.9.9.9"],
            "entity_key": "src_ip:9.9.9.9",
            "sample": {"src_ip": "9.9.9.9"},
        },
    )
    peer = SimpleNamespace(
        id=19,
        tenant_id="lab",
        created_at=now - timedelta(minutes=5),
        mitre="T1110",
        evidence={
            "entity_keys": ["src_ip:9.9.9.9"],
            "entity_key": "src_ip:9.9.9.9",
            "sample": {"src_ip": "9.9.9.9"},
        },
    )
    db = MagicMock()
    db.scalars.return_value.all.return_value = [peer]
    db.scalar.return_value = None
    with patch("services.api.lab_settings.get_lab_state", return_value=state), patch(
        "services.api.alert_graph._history_count", return_value=50
    ):
        n = link_alert(db, alert)
    assert n >= 2
    added = [c.args[0] for c in db.add.call_args_list if c.args]
    relations = {getattr(a, "relation", None) for a in added if isinstance(a, AlertLink)}
    assert "same_entity" in relations
    assert "temporal_follows" in relations
    assert "mitre_chain" in relations


def test_connected_alerts_and_links_payload():
    alert = SimpleNamespace(id=1, tenant_id="lab")
    link = AlertLink(
        id=1,
        tenant_id="lab",
        src_alert_id=2,
        dst_alert_id=1,
        relation="same_entity",
        score=70,
        shared_keys=["src_ip:1.1.1.1"],
    )
    other = SimpleNamespace(
        id=2,
        title="Older spray",
        rule_id="r1",
        severity="high",
        status="closed",
        disposition="true_positive",
        mitre="T1110",
        tenant_id="lab",
    )
    db = MagicMock()
    db.scalars.return_value.all.return_value = [link]
    db.get.return_value = other
    rows = connected_alerts(db, alert, limit=5)
    assert len(rows) == 1
    assert rows[0]["id"] == 2
    assert rows[0]["direction"] == "in"
    payload = links_payload(db, alert)
    assert payload["count"] == 1
    assert payload["alert_id"] == 1


def test_fingerprint_includes_connected_and_entities():
    alert = SimpleNamespace(
        id=7,
        title="T",
        description="desc " * 50,
        severity="high",
        status="open",
        rule_id="r",
        rule_name="Rule",
        mitre="T1059",
        noise_hint="likely_signal",
        risk_score=80,
        evidence={
            "entity_keys": ["src_ip:8.8.8.8", "host:ws"],
            "entity_key": "src_ip:8.8.8.8",
            "sample": {"src_ip": "8.8.8.8", "host": "ws"},
            "occurrences": 3,
            "steps": [{"index": 0, "count": 5, "matched": True}],
        },
    )
    fp = build_alert_fingerprint(
        alert,
        connected=[{"id": 3, "title": "Peer", "relation": "same_entity", "score": 60, "direction": "in"}],
        cases=[{"alert_id": 99, "disposition": "false_positive", "note_excerpt": "known"}],
    )
    assert fp["alert_id"] == 7
    assert "src_ip:8.8.8.8" in fp["entity_keys"]
    assert fp["connected"][0]["id"] == 3
    assert fp["cases"][0]["alert_id"] == 99
    assert fp["occurrences"] == 3


def test_copilot_related_alert_ids_from_graph_local():
    brief = {
        "summary": "x",
        "similar_fp": 3,
        "similar_tp": 0,
        "cases": [
            {
                "alert_id": 50,
                "disposition": "false_positive",
                "note_excerpt": "Known scanner traffic from lab subnet",
            }
        ],
        "connected": [
            {"id": 11, "relation": "temporal_follows", "score": 70, "direction": "in"},
            {"id": 12, "relation": "same_entity", "score": 40, "direction": "out"},
        ],
        "fingerprint": {},
    }
    with patch("services.api.copilot.get_lab_state", return_value=LabState(llm_enabled=False)):
        out = suggest_closure(brief)
    assert out["available"] is True
    assert 11 in out["related_alert_ids"]
    assert out["relation_hint"]


def test_copilot_filters_llm_related_to_allowed():
    brief = {
        "summary": "x",
        "similar_fp": 0,
        "similar_tp": 0,
        "cases": [],
        "connected": [{"id": 5, "relation": "shared_ioc", "score": 80, "direction": "out"}],
        "fingerprint": {"connected": [{"id": 5}], "cases": []},
    }
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": (
                        '{"disposition":"true_positive","note":"Investigate linked spray then auth",'
                        '"rationale":"chain","related_alert_ids":[5,999],"relation_hint":"mitre"}'
                    )
                }
            }
        ]
    }
    state = LabState(
        llm_enabled=True,
        llm_api_key="sk-test",
        llm_api_url="https://api.openai.com/v1/chat/completions",
    )
    with (
        patch("services.api.copilot.get_lab_state", return_value=state),
        patch("services.api.url_safety.egress_post", return_value=fake_resp),
    ):
        out = suggest_closure(brief)
    assert out["available"] is True
    assert out["related_alert_ids"] == [5]
    assert 999 not in out["related_alert_ids"]


def test_history_count_sums_memory_and_open():
    db = MagicMock()
    db.scalar.side_effect = [3, 7]
    assert _history_count(db, "lab") == 10
