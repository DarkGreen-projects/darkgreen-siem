"""Heuristic triage scoring from severity, TI, and past dispositions (suggest-only)."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from .models import Alert

_SEV_BASE = {"critical": 70, "high": 55, "medium": 35, "low": 20, "info": 10}
BACKFILL_CAP = 500


def compute_fingerprint_hash(alert: Any) -> str:
    """Stable sha256[:32] of rule_id|entity_key|sorted iocs."""
    evidence = dict(getattr(alert, "evidence", None) or {})
    entity = str(evidence.get("entity_key") or "")
    sample = evidence.get("sample") if isinstance(evidence.get("sample"), dict) else {}
    labels = evidence.get("labels") if isinstance(evidence.get("labels"), dict) else {}
    iocs: list[str] = []
    for field in ("src_ip", "dst_ip", "host", "user"):
        if sample.get(field):
            iocs.append(f"{field}:{sample[field]}".lower())
    for field in ("hash", "sha256", "domain", "url"):
        if labels and labels.get(field):
            iocs.append(f"{field}:{labels[field]}".lower())
    parts = [
        str(getattr(alert, "rule_id", None) or ""),
        entity.lower(),
        "|".join(sorted(set(iocs))),
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


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


def _mitre_is_tactics_heavy(mitre: str | None) -> bool:
    """True for common high-signal MITRE technique families (T1xxx)."""
    if not mitre:
        return False
    text = str(mitre).upper()
    return any(
        tok in text
        for tok in (
            "T1059",
            "T1003",
            "T1021",
            "T1078",
            "T1110",
            "T1204",
            "T1566",
            "T1041",
            "T1105",
        )
    )


def compute_triage_score(
    alert: Any,
    *,
    priors: dict[str, int] | None = None,
    ti_malicious: bool = False,
    ti_suspicious: bool = False,
) -> dict[str, Any]:
    sev = (getattr(alert, "severity", None) or "medium").strip().lower()
    score = int(_SEV_BASE.get(sev, 35))
    mitre = getattr(alert, "mitre", None) or (getattr(alert, "evidence", None) or {}).get(
        "mitre"
    )
    if mitre:
        score += 10
        if _mitre_is_tactics_heavy(str(mitre)):
            score += 12
    evidence = dict(getattr(alert, "evidence", None) or {})
    labels = evidence.get("labels") if isinstance(evidence.get("labels"), dict) else {}
    if labels and (labels.get("hash") or labels.get("sha256")):
        score += 8
    occ = int(evidence.get("occurrences") or evidence.get("count") or 1)
    if occ > 1:
        score += min(20, int(6 * (occ ** 0.5)))
    if ti_malicious:
        score += 20
        score = max(score, 65)  # floor for malicious TI
    elif ti_suspicious:
        score += 8

    priors = priors or {}
    fp_n = int(priors.get("false_positive") or 0) + int(priors.get("benign") or 0)
    tp_n = int(priors.get("true_positive") or 0)
    score -= min(45, fp_n * 14)
    score += min(18, tp_n * 8)
    score = max(0, min(100, score))

    # Aggressive demote when fingerprint has FP priors and no TP.
    if fp_n >= 2 and tp_n == 0:
        hint = "likely_noise"
        score = min(score, 35)
    elif fp_n >= 2 and fp_n > tp_n:
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
    fp_hash = compute_fingerprint_hash(alert)
    alert.fingerprint_hash = fp_hash
    evidence["fingerprint_hash"] = fp_hash
    evidence["triage"] = result
    alert.evidence = evidence
    return alert


def backfill_open_scores(
    db: Session,
    *,
    tenant_id: str = "lab",
    batch_size: int = 200,
    days: int = 30,
) -> int:
    """Score open/in_progress alerts missing noise_hint. Returns rows updated."""
    from .lab_settings import get_lab_state

    lab = get_lab_state()
    if not getattr(lab, "triage_scoring_enabled", True):
        return 0
    prior_days = int(getattr(lab, "triage_prior_days", days) or days)
    rows = list(
        db.scalars(
            select(Alert)
            .where(
                and_(
                    Alert.tenant_id == tenant_id,
                    Alert.status.in_(["open", "in_progress", "acked"]),
                    or_(Alert.noise_hint.is_(None), Alert.fingerprint_hash.is_(None)),
                )
            )
            .order_by(Alert.created_at.desc())
            .limit(min(BACKFILL_CAP, max(1, batch_size)))
        ).all()
    )
    n = 0
    for alert in rows:
        apply_score_to_alert(db, alert, days=prior_days, enabled=True)
        n += 1
    return n


def refresh_open_after_disposition(
    db: Session,
    *,
    tenant_id: str,
    rule_id: str,
    entity_key: str,
    limit: int = 20,
    days: int = 30,
) -> int:
    """Re-score open alerts with same rule+entity after a close (priors changed)."""
    if not rule_id:
        return 0
    rows = list(
        db.scalars(
            select(Alert)
            .where(
                and_(
                    Alert.tenant_id == tenant_id,
                    Alert.rule_id == rule_id,
                    Alert.status.in_(["open", "in_progress", "acked"]),
                )
            )
            .order_by(Alert.created_at.desc())
            .limit(max(1, limit))
        ).all()
    )
    n = 0
    for alert in rows:
        ev = dict(alert.evidence or {})
        if entity_key and str(ev.get("entity_key") or "") != entity_key:
            # Still allow fingerprint match
            if (getattr(alert, "fingerprint_hash", None) or "") == "":
                continue
        apply_score_to_alert(db, alert, days=days, enabled=True)
        n += 1
    return n


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
