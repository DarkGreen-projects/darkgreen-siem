"""Alert Memory RAG: upsert, retrieve boosts, local-first copilot."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.api.copilot import suggest_closure
from services.api.rag_memory import (
    _build_memory_text,
    _lexical_score,
    _tokenize,
    export_memory,
    local_suggest_from_cases,
    majority_fallback_from_cases,
    upsert_alert_memory,
)


def test_build_memory_text_and_tokenize():
    text = _build_memory_text(
        title="Spray login",
        rule_id="login-spray",
        entity_key="user:alice",
        mitre="T1110",
        note="Verified expected scanner traffic",
    )
    assert "Spray login" in text
    assert "login-spray" in text
    toks = _tokenize("Spray login alice T1110")
    assert "spray" in toks or "alice" in toks
    assert _lexical_score(text, ["login", "alice"]) > 0


def test_upsert_alert_memory_requires_closed_note():
    db = MagicMock()
    db.get.return_value = None
    alert = SimpleNamespace(
        id=9,
        status="open",
        disposition="false_positive",
        closure_note="long enough note here",
        tenant_id="lab",
        rule_id="r1",
        title="t",
        mitre=None,
        evidence={},
        closed_at=None,
    )
    assert upsert_alert_memory(db, alert) is None

    alert.status = "closed"
    alert.closure_note = "short"
    assert upsert_alert_memory(db, alert) is None

    alert.closure_note = "Verified expected scanner from internal range"
    alert.evidence = {"entity_key": "host:ws1"}
    alert.closed_at = datetime.now(timezone.utc)
    row = upsert_alert_memory(db, alert)
    assert row is not None
    db.add.assert_called()
    db.flush.assert_called()


def test_retrieve_prefers_same_rule_entity_via_lexical_path():
    from services.api.rag_memory import retrieve_cases
    from services.api.models import AlertMemory

    alert = SimpleNamespace(
        id=100,
        tenant_id="lab",
        rule_id="rule-a",
        title="Suspicious process",
        mitre="T1059",
        evidence={"entity_key": "host:ws1", "sample": {"host": "ws1"}},
    )
    mem = [
        AlertMemory(
            alert_id=1,
            tenant_id="lab",
            rule_id="rule-a",
            entity_key="host:ws1",
            disposition="false_positive",
            mitre="T1059",
            title="Old spray",
            note_excerpt="Known FP from scanner",
            memory_text="Suspicious process rule-a host:ws1 T1059 Known FP from scanner",
            closed_at=datetime.now(timezone.utc),
        ),
        AlertMemory(
            alert_id=2,
            tenant_id="lab",
            rule_id="other",
            entity_key="host:other",
            disposition="true_positive",
            mitre=None,
            title="Unrelated",
            note_excerpt="Real malware",
            memory_text="Unrelated other malware",
            closed_at=datetime.now(timezone.utc),
        ),
    ]
    db = MagicMock()
    # Force FTS path to fail → ORM lexical
    db.execute.side_effect = RuntimeError("no fts")
    db.scalars.return_value.all.return_value = mem

    with patch("services.api.rag_memory.find_similar_alerts", return_value=[]):
        cases = retrieve_cases(db, alert, top_k=3, prior_days=30, rag_enabled=True)
    assert cases
    assert cases[0]["alert_id"] == 1
    assert cases[0]["disposition"] == "false_positive"


def test_local_suggest_strong_fp_priors():
    cases = [
        {
            "alert_id": 1,
            "disposition": "false_positive",
            "note_excerpt": "Scanner interno confermato su stessa subnet.",
        }
    ]
    out = local_suggest_from_cases(cases, similar_fp=3, similar_tp=0)
    assert out is not None
    assert out["source"] == "local_memory"
    assert out["suggested_disposition"] == "false_positive"
    assert out["available"] is True


def test_local_suggest_majority_vote():
    cases = [
        {"alert_id": i, "disposition": "benign", "note_excerpt": "Change window approved by CAB."}
        for i in (1, 2, 3)
    ]
    out = local_suggest_from_cases(cases, similar_fp=0, similar_tp=0)
    assert out is not None
    assert out["suggested_disposition"] == "benign"


def test_copilot_local_first_skips_httpx():
    brief = {
        "summary": "Alert #1",
        "similar_fp": 4,
        "similar_tp": 0,
        "cases": [
            {
                "alert_id": 7,
                "disposition": "false_positive",
                "note_excerpt": "Verified scanner noise on this host repeatedly.",
            }
        ],
    }
    with patch("services.api.copilot.get_lab_state") as gs:
        gs.return_value = SimpleNamespace(
            llm_enabled=True,
            llm_api_key="sk-test",
            llm_api_url="https://api.openai.com/v1/chat/completions",
            llm_model="gpt-4o-mini",
            rag_top_k=5,
        )
        with patch("services.api.url_safety.egress_post") as post:
            out = suggest_closure(brief)
            post.assert_not_called()
    assert out["source"] == "local_memory"
    assert out["available"] is True


def test_copilot_llm_receives_cases(monkeypatch):
    state = SimpleNamespace(
        llm_enabled=True,
        llm_api_key="sk-test",
        llm_api_url="https://api.openai.com/v1/chat/completions",
        llm_model="gpt-4o-mini",
        rag_top_k=5,
        rag_enabled=True,
    )
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": (
                        '{"disposition":"tuning_needed",'
                        '"note":"Serve tuning regola dopo casi simili.",'
                        '"rationale":"Mix FP/TP"}'
                    )
                }
            }
        ]
    }

    brief = {
        "summary": "Alert ambiguous",
        "similar_fp": 1,
        "similar_tp": 1,
        "entities": {"host": "ws1"},
        "cases": [
            {
                "alert_id": 3,
                "disposition": "tuning_needed",
                "note_excerpt": "Rule needs exclude for backup user",
                "rule_id": "r1",
                "score": 4.0,
            }
        ],
    }
    with (
        patch("services.api.copilot.get_lab_state", return_value=state),
        patch("services.api.url_safety.egress_post", return_value=fake_resp) as post,
    ):
        out = suggest_closure(brief)
    assert out["available"] is True
    assert out["source"] == "llm_rag"
    assert out["suggested_disposition"] == "tuning_needed"
    body = post.call_args.kwargs["json"]
    user = body["messages"][1]["content"]
    assert "cases" in user
    assert "backup user" in user


def test_majority_fallback_and_export_shape():
    cases = [
        {"alert_id": 1, "disposition": "true_positive", "note_excerpt": "Confirmed C2 beacon activity."},
        {"alert_id": 2, "disposition": "true_positive", "note_excerpt": "Same IOC again."},
    ]
    fb = majority_fallback_from_cases(cases)
    assert fb and fb["source"] == "local_memory"

    db = MagicMock()
    row = SimpleNamespace(
        alert_id=1,
        rule_id="r",
        entity_key="host:x",
        disposition="false_positive",
        mitre=None,
        title="t",
        note_excerpt="n",
        closed_at=datetime.now(timezone.utc),
    )
    db.scalars.return_value.all.return_value = [row]
    exported = export_memory(db, tenant_id="lab", limit=10)
    assert exported["version"] == 1
    assert exported["tenant_id"] == "lab"
    assert exported["count"] == 1
    assert exported["cases"][0]["alert_id"] == 1
