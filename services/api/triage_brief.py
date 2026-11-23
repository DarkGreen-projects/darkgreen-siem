"""Local triage briefing and queue ranking for the analyst workbench."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from .lab_settings import get_lab_state
from .models import Alert
from .sla import compute_alert_sla
from .triage_score import find_similar_alerts

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SLA_RANK = {"breached": 0, "at_risk": 1, "ok": 2, "met": 3, "na": 4}
_NOISE_RANK = {"likely_signal": 0, "unclear": 1, "likely_noise": 2}


def _sample(alert: Alert) -> dict[str, Any]:
    ev = dict(alert.evidence or {})
    sample = ev.get("sample")
    return sample if isinstance(sample, dict) else {}


def queue_sort_key(alert_out: Any) -> tuple:
    """Lower tuple = higher priority for workbench queue."""
    sev = (getattr(alert_out, "severity", None) or "medium").lower()
    noise = (getattr(alert_out, "noise_hint", None) or "unclear").lower()
    sla_ack = (getattr(alert_out, "sla_ack_status", None) or "na").lower()
    sla_close = (getattr(alert_out, "sla_close_status", None) or "na").lower()
    sla_best = min(_SLA_RANK.get(sla_ack, 4), _SLA_RANK.get(sla_close, 4))
    created = getattr(alert_out, "created_at", None) or datetime.now(timezone.utc)
    ts = created.timestamp() if hasattr(created, "timestamp") else 0.0
    return (
        sla_best,
        _NOISE_RANK.get(noise, 1),
        _SEV_RANK.get(sev, 2),
        ts,
    )


def build_alert_brief(
    alert: Alert,
    *,
    db: Session | None = None,
    ack_map: dict[str, int] | None = None,
    close_map: dict[str, int] | None = None,
    prior_days: int = 30,
) -> dict[str, Any]:
    evidence = dict(alert.evidence or {})
    sample = _sample(alert)
    sla = compute_alert_sla(alert, ack_map=ack_map, close_map=close_map)
    similar = find_similar_alerts(db, alert, days=prior_days, limit=10) if db is not None else []
    fp_n = sum(
        1
        for s in similar
        if (getattr(s, "disposition", None) or "") in {"false_positive", "benign"}
    )
    tp_n = sum(1 for s in similar if (getattr(s, "disposition", None) or "") == "true_positive")

    entities = {
        k: sample.get(k)
        for k in ("src_ip", "dst_ip", "host", "user")
        if sample.get(k)
    }
    iocs: list[str] = []
    for k in ("src_ip", "dst_ip"):
        if sample.get(k):
            iocs.append(str(sample[k]))
    for key in ("hash", "domain", "url"):
        labels = evidence.get("labels") if isinstance(evidence.get("labels"), dict) else {}
        val = labels.get(key) if labels else None
        if val:
            iocs.append(str(val))

    lines = [
        f"Alert #{alert.id}: {alert.title}",
        f"Severity {alert.severity} · status {alert.status}"
        + (f" · MITRE {alert.mitre}" if alert.mitre else ""),
        f"Rule `{alert.rule_id}` ({alert.rule_name})",
    ]
    if alert.noise_hint or alert.risk_score is not None:
        lines.append(
            f"Stima: {alert.noise_hint or 'n/a'}"
            + (f" (score {alert.risk_score})" if alert.risk_score is not None else "")
        )
    lines.append(
        f"SLA ack={sla.get('sla_ack_status')} close={sla.get('sla_close_status')}"
    )
    if entities:
        lines.append("Entity: " + ", ".join(f"{k}={v}" for k, v in entities.items()))
    brief = (evidence.get("threat_brief") or "").strip()
    if brief:
        lines.append(f"Threat brief: {brief[:400]}")
    if similar:
        lines.append(
            f"Simili (ultimi {prior_days}g): {len(similar)} · FP/benign {fp_n} · TP {tp_n}"
        )
    if iocs:
        lines.append("IOC: " + ", ".join(iocs[:8]))

    cases: list[dict[str, Any]] = []
    if db is not None:
        try:
            from .rag_memory import retrieve_cases

            lab = get_lab_state()
            cases = retrieve_cases(
                db,
                alert,
                top_k=int(getattr(lab, "rag_top_k", 5) or 5),
                prior_days=prior_days,
                rag_enabled=bool(getattr(lab, "rag_enabled", True)),
            )
            if cases:
                lines.append(
                    "Memoria casi: "
                    + "; ".join(
                        f"#{c['alert_id']} {c.get('disposition') or '?'}"
                        for c in cases[:5]
                    )
                )
        except Exception:
            cases = []

    connected: list[dict[str, Any]] = []
    if db is not None:
        try:
            from .alert_graph import connected_alerts

            connected = connected_alerts(db, alert, limit=8)
            if connected:
                lines.append(
                    "Collegati: "
                    + "; ".join(
                        f"#{c['id']} {c.get('relation')}({c.get('score')})"
                        for c in connected[:5]
                    )
                )
        except Exception:
            connected = []

    fingerprint: dict[str, Any] = {}
    try:
        from .alert_fingerprint import build_alert_fingerprint

        fingerprint = build_alert_fingerprint(
            alert, db=db, cases=cases, connected=connected
        )
    except Exception:
        fingerprint = {}

    pivot = None
    for field in ("src_ip", "host", "user"):
        if sample.get(field):
            pivot = f"{field}:{sample[field]}"
            break

    return {
        "alert_id": alert.id,
        "summary": "\n".join(lines),
        "entities": entities,
        "pivot_query": pivot,
        "similar_count": len(similar),
        "similar_fp": fp_n,
        "similar_tp": tp_n,
        "sla": {
            "ack": sla.get("sla_ack_status"),
            "close": sla.get("sla_close_status"),
        },
        "noise_hint": getattr(alert, "noise_hint", None),
        "risk_score": getattr(alert, "risk_score", None),
        "mitre": getattr(alert, "mitre", None),
        "threat_brief": brief or None,
        "cases": cases,
        "connected": connected,
        "fingerprint": fingerprint,
    }
