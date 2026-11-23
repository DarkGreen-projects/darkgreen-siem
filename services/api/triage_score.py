"""Heuristic triage scoring from severity, TI, and past dispositions (suggest-only)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from .models import Alert

_SEV_BASE = {"critical": 70, "high": 55, "medium": 35, "low": 20, "info": 10}


def count_disposition_priors(
    db: Session,
    *,
    tenant_id: str,
    rule_id: str,
    entity_key: str,
    days: int = 30,
) -> dict[str, int]:
    since = datetime.now(timezone.utc) - timedelta(days=max(1, days))
    counts = {
        "false_positive": 0,
        "benign": 0,
        "true_positive": 0,
        "duplicate": 0,
        "tuning_needed": 0,
    }
    candidates = list(
        db.scalars(
            select(Alert)
            .where(
                and_(
                    Alert.tenant_id == tenant_id,
                    Alert.rule_id == rule_id,
                    Alert.status == "closed",
                    Alert.created_at >= since,
                    Alert.disposition.is_not(None),
                )
            )
            .order_by(Alert.created_at.desc())
            .limit(100)
        ).all()
    )
    from .entity_norm import alert_entity_keys, collect_entity_keys, entity_keys_overlap

    target_keys = collect_entity_keys({"entity_key": entity_key}) if entity_key else []
    if entity_key and entity_key not in target_keys:
        target_keys = [entity_key] + target_keys
    for a in candidates:
        other = alert_entity_keys(a)
        if not entity_keys_overlap(target_keys, other):
            continue
        d = (getattr(a, "disposition", None) or "").strip().lower()
        if d in counts:
            counts[d] += 1
    return counts


def compute_triage_score(
    alert: Any,
    *,
    priors: dict[str, int] | None = None,
    ti_malicious: bool = False,
    ti_suspicious: bool = False,
) -> dict[str, Any]:
    sev = (getattr(alert, "severity", None) or "medium").strip().lower()
    score = int(_SEV_BASE.get(sev, 35))
    if getattr(alert, "mitre", None) or (getattr(alert, "evidence", None) or {}).get("mitre"):
        score += 10
    evidence = dict(getattr(alert, "evidence", None) or {})
    occ = int(evidence.get("occurrences") or evidence.get("count") or 1)
    if occ > 1:
        score += min(15, int(5 * (occ ** 0.5)))
    if ti_malicious:
        score += 15
    elif ti_suspicious:
        score += 8

    priors = priors or {}
    fp_n = int(priors.get("false_positive") or 0) + int(priors.get("benign") or 0)
    tp_n = int(priors.get("true_positive") or 0)
    score -= min(35, fp_n * 12)
    score += min(15, tp_n * 8)
    score = max(0, min(100, score))

    if fp_n >= 2 and fp_n > tp_n:
        hint = "likely_noise"
    elif score >= 60 or tp_n >= 1 or ti_malicious:
        hint = "likely_signal"
    else:
        hint = "unclear"

    return {
        "risk_score": score,
        "noise_hint": hint,
        "priors": {
            "false_positive": fp_n,
            "true_positive": tp_n,
            "benign": int(priors.get("benign") or 0),
        },
    }


def apply_score_to_alert(
    db: Session,
    alert: Alert,
    *,
    days: int = 30,
    enabled: bool = True,
) -> Alert:
    if not enabled:
        return alert
    evidence = dict(alert.evidence or {})
    entity = str(evidence.get("entity_key") or "")
    priors = (
        count_disposition_priors(
            db,
            tenant_id=alert.tenant_id or "lab",
            rule_id=alert.rule_id,
            entity_key=entity,
            days=days,
        )
        if entity
        else {}
    )
    result = compute_triage_score(alert, priors=priors)
    alert.risk_score = int(result["risk_score"])
    alert.noise_hint = str(result["noise_hint"])
    evidence["triage"] = result
    alert.evidence = evidence
    return alert


def find_similar_alerts(
    db: Session,
    alert: Alert,
    *,
    days: int = 30,
    limit: int = 10,
) -> list[Alert]:
    from .entity_norm import alert_entity_keys, entity_keys_overlap

    keys = alert_entity_keys(alert)
    if not keys:
        return []
    since = datetime.now(timezone.utc) - timedelta(days=max(1, days))
    rows = list(
        db.scalars(
            select(Alert)
            .where(
                and_(
                    Alert.tenant_id == (alert.tenant_id or "lab"),
                    Alert.rule_id == alert.rule_id,
                    Alert.id != alert.id,
                    Alert.created_at >= since,
                )
            )
            .order_by(Alert.created_at.desc())
            .limit(80)
        ).all()
    )
    out: list[Alert] = []
    for row in rows:
        if not entity_keys_overlap(keys, alert_entity_keys(row)):
            continue
        out.append(row)
        if len(out) >= limit:
            break
    return out
