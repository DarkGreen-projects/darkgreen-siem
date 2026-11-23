"""Compact structured alert fingerprint for briefing / mini-LLM."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from .entity_norm import alert_entity_keys
from .models import Alert


def build_alert_fingerprint(
    alert: Alert,
    *,
    db: Session | None = None,
    cases: list[dict[str, Any]] | None = None,
    connected: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    evidence = dict(alert.evidence or {})
    sample = evidence.get("sample") if isinstance(evidence.get("sample"), dict) else {}
    labels = evidence.get("labels") if isinstance(evidence.get("labels"), dict) else {}

    iocs: list[str] = []
    for field in ("src_ip", "dst_ip", "host", "user"):
        if sample.get(field):
            iocs.append(f"{field}:{sample[field]}")
    for field in ("hash", "domain", "url"):
        if labels and labels.get(field):
            iocs.append(f"{field}:{labels[field]}")

    steps = evidence.get("steps")
    step_brief: list[dict[str, Any]] = []
    if isinstance(steps, list):
        for s in steps[:6]:
            if not isinstance(s, dict):
                continue
            step_brief.append(
                {
                    "index": s.get("index"),
                    "count": s.get("count"),
                    "matched": s.get("matched"),
                    "enrich": bool(s.get("enrich")),
                }
            )

    if connected is None and db is not None and alert.id:
        try:
            from .alert_graph import connected_alerts

            connected = connected_alerts(db, alert, limit=8)
        except Exception:
            connected = []
    connected = connected or []

    cases_compact = []
    for c in (cases or [])[:5]:
        cases_compact.append(
            {
                "alert_id": c.get("alert_id"),
                "disposition": c.get("disposition"),
                "rule_id": c.get("rule_id"),
                "note": (c.get("note_excerpt") or "")[:120],
                "score": c.get("score"),
            }
        )

    desc = (alert.description or "")[:400]
    threat = (evidence.get("threat_brief") or "")[:300]
    return {
        "alert_id": alert.id,
        "title": alert.title,
        "description": desc,
        "severity": alert.severity,
        "status": alert.status,
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "mitre": getattr(alert, "mitre", None),
        "entity_keys": alert_entity_keys(alert)[:12],
        "entity_key": evidence.get("entity_key"),
        "occurrences": int(evidence.get("occurrences") or evidence.get("count") or 1),
        "noise_hint": getattr(alert, "noise_hint", None),
        "risk_score": getattr(alert, "risk_score", None),
        "join_on": evidence.get("join_on"),
        "join_key": evidence.get("join_key"),
        "steps": step_brief,
        "iocs": iocs[:10],
        "threat_brief": threat or None,
        "connected": [
            {
                "id": c.get("id"),
                "title": (c.get("title") or "")[:80],
                "relation": c.get("relation"),
                "score": c.get("score"),
                "direction": c.get("direction"),
                "disposition": c.get("disposition"),
                "status": c.get("status"),
            }
            for c in connected[:8]
        ],
        "cases": cases_compact,
    }
