from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from .models import Alert, Event
from .enrich_providers import keys_matching_enrich
from .lab_settings import get_lab_state
from .rule_store import (
    delete_rule,
    get_rule,
    load_rules,
    save_rule,
    set_rule_enabled,
)
from .rule_validate import (
    RuleConflictError,
    RuleValidationError,
    validate_rule_id,
    validate_rule_payload,
)

__all__ = [
    "RuleConflictError",
    "RuleValidationError",
    "load_rules",
    "validate_rule_payload",
    "validate_rule_id",
    "save_rule",
    "delete_rule",
    "set_rule_enabled",
    "get_rule",
    "run_rules",
    "evaluate_match_rule",
    "evaluate_threshold_rule",
    "evaluate_correlation_rule",
]


def _match_filters(event: Event, filters: dict[str, Any]) -> bool:
    for key, expected in filters.items():
        actual = getattr(event, key, None)
        if actual is None:
            return False
        if isinstance(expected, list):
            if str(actual).lower() not in {str(x).lower() for x in expected}:
                return False
        else:
            if str(actual).lower() != str(expected).lower():
                return False
    return True


def _recent_alert_exists(
    db: Session, rule_id: str, window_minutes: int, *, tenant_id: str = "lab"
) -> bool:
    since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    stmt = (
        select(func.count())
        .select_from(Alert)
        .where(
            and_(
                Alert.rule_id == rule_id,
                Alert.created_at >= since,
                Alert.tenant_id == tenant_id,
            )
        )
    )
    return (db.scalar(stmt) or 0) > 0


def evaluate_match_rule(
    db: Session, rule: dict[str, Any], *, tenant_id: str = "lab"
) -> Alert | None:
    filters = rule.get("match") or rule.get("filters") or {}
    window = int(rule.get("window_minutes") or 10)
    since = datetime.now(timezone.utc) - timedelta(minutes=window)
    stmt = (
        select(Event)
        .where(and_(Event.timestamp >= since, Event.tenant_id == tenant_id))
        .order_by(Event.timestamp.desc())
        .limit(500)
    )
    events = list(db.scalars(stmt).all())
    hits = [e for e in events if _match_filters(e, filters)]
    if not hits:
        return None
    if _recent_alert_exists(
        db, rule["id"], int(rule.get("cooldown_minutes") or window), tenant_id=tenant_id
    ):
        return None
    sample = hits[0]
    brief = (rule.get("threat_brief") or "").strip() or None
    return Alert(
        tenant_id=tenant_id,
        rule_id=rule["id"],
        rule_name=rule.get("name") or rule["id"],
        severity=rule.get("severity") or "medium",
        title=rule.get("title") or rule.get("name") or rule["id"],
        description=rule.get("description") or f"Matched {len(hits)} event(s)",
        status="open",
        evidence={
            "count": len(hits),
            "event_ids": [h.id for h in hits[:10]],
            "threat_brief": brief,
            "sample": {
                "id": sample.id,
                "user": sample.user,
                "src_ip": sample.src_ip,
                "dst_ip": sample.dst_ip,
                "host": sample.host,
                "action": sample.action,
                "message": sample.message,
            },
        },
    )


def evaluate_threshold_rule(
    db: Session, rule: dict[str, Any], *, tenant_id: str = "lab"
) -> Alert | None:
    filters = rule.get("match") or rule.get("filters") or {}
    window = int(rule.get("window_minutes") or 5)
    threshold = int(rule.get("threshold") or 5)
    group_by = rule.get("group_by") or "user"
    since = datetime.now(timezone.utc) - timedelta(minutes=window)

    col = getattr(Event, group_by, None)
    if col is None:
        return None

    clauses = [Event.timestamp >= since, Event.tenant_id == tenant_id]
    for key, expected in filters.items():
        field = getattr(Event, key, None)
        if field is None:
            continue
        if isinstance(expected, list):
            clauses.append(func.lower(field).in_([str(x).lower() for x in expected]))
        else:
            clauses.append(func.lower(field) == str(expected).lower())

    stmt = (
        select(col, func.count())
        .where(and_(*clauses))
        .group_by(col)
        .having(func.count() >= threshold)
    )
    rows = list(db.execute(stmt).all())
    if not rows:
        return None
    if _recent_alert_exists(
        db, rule["id"], int(rule.get("cooldown_minutes") or window), tenant_id=tenant_id
    ):
        return None

    top_key, top_count = rows[0]
    brief = (rule.get("threat_brief") or "").strip() or None
    return Alert(
        tenant_id=tenant_id,
        rule_id=rule["id"],
        rule_name=rule.get("name") or rule["id"],
        severity=rule.get("severity") or "high",
        title=rule.get("title") or f"{rule.get('name')} ({top_key})",
        description=rule.get("description")
        or f"{top_count} matching events for {group_by}={top_key} in {window}m",
        status="open",
        evidence={
            "group_by": group_by,
            "groups": [{"key": str(k), "count": int(c)} for k, c in rows[:10]],
            "threshold": threshold,
            "window_minutes": window,
            "threat_brief": brief,
            "sample": {"src_ip": str(top_key) if group_by == "src_ip" else None, "key": str(top_key)},
        },
    )


def evaluate_correlation_rule(
    db: Session, rule: dict[str, Any], *, tenant_id: str = "lab"
) -> Alert | None:
    """Join 2+ steps (match and/or enrich) on a shared field within one time window."""
    steps = rule.get("steps") or []
    if len(steps) < 2:
        return None
    join_on = str(rule.get("join_on") or "src_ip")
    if not hasattr(Event, join_on):
        return None
    window = int(rule.get("window_minutes") or 30)
    since = datetime.now(timezone.utc) - timedelta(minutes=window)
    stmt = (
        select(Event)
        .where(and_(Event.timestamp >= since, Event.tenant_id == tenant_id))
        .order_by(Event.timestamp.desc())
        .limit(2000)
    )
    events = list(db.scalars(stmt).all())
    if not events:
        return None

    step_keys: list[set[str]] = []
    step_counts: list[Counter[str]] = []
    candidate_keys: set[str] | None = None

    for step in steps:
        if step.get("enrich"):
            enrich = step["enrich"] or {}
            providers = list(enrich.get("providers") or ["vt"])
            verdicts = list(enrich.get("verdicts") or ["malicious", "suspicious"])
            ioc_type = str(enrich.get("ioc_type") or "ip")
            if candidate_keys is None:
                pool = {
                    str(getattr(e, join_on))
                    for e in events
                    if getattr(e, join_on, None) not in (None, "")
                }
            else:
                pool = set(candidate_keys)
            matched = keys_matching_enrich(
                db,
                pool,
                providers=providers,
                verdicts=verdicts,
                ioc_type=ioc_type,
                state=get_lab_state(),
                tenant_id=tenant_id,
            )
            step_keys.append(matched)
            step_counts.append(Counter({k: 1 for k in matched}))
            candidate_keys = matched if candidate_keys is None else (candidate_keys & matched)
        else:
            filters = step.get("match") or {}
            min_count = int(step.get("min_count") or 1)
            counts: Counter[str] = Counter()
            for ev in events:
                if not _match_filters(ev, filters):
                    continue
                key = getattr(ev, join_on, None)
                if key is None or str(key).strip() == "":
                    continue
                counts[str(key)] += 1
            kept = {k for k, c in counts.items() if c >= min_count}
            step_keys.append(kept)
            step_counts.append(Counter({k: c for k, c in counts.items() if c >= min_count}))
            candidate_keys = kept if candidate_keys is None else (candidate_keys & kept)

        if not candidate_keys:
            return None

    shared = set(candidate_keys)
    if not shared:
        return None
    if _recent_alert_exists(
        db, rule["id"], int(rule.get("cooldown_minutes") or window), tenant_id=tenant_id
    ):
        return None

    top_key = max(shared, key=lambda k: step_counts[0].get(k, 0))
    brief = (rule.get("threat_brief") or "").strip() or None
    step_summary = []
    for i, step in enumerate(steps):
        if step.get("enrich"):
            step_summary.append(
                {
                    "index": i,
                    "enrich": step.get("enrich"),
                    "matched": top_key in step_keys[i],
                }
            )
        else:
            step_summary.append(
                {
                    "index": i,
                    "match": step.get("match") or {},
                    "min_count": int(step.get("min_count") or 1),
                    "count": int(step_counts[i].get(top_key, 0)),
                }
            )

    sample_ev = next(
        (e for e in events if str(getattr(e, join_on, None) or "") == top_key),
        None,
    )
    return Alert(
        tenant_id=tenant_id,
        rule_id=rule["id"],
        rule_name=rule.get("name") or rule["id"],
        severity=rule.get("severity") or "critical",
        title=rule.get("title") or f"{rule.get('name')} ({join_on}={top_key})",
        description=rule.get("description")
        or f"Correlated {len(steps)} signals on {join_on}={top_key} within {window}m",
        status="open",
        evidence={
            "join_on": join_on,
            "join_key": top_key,
            "keys": sorted(shared)[:20],
            "steps": step_summary,
            "window_minutes": window,
            "threat_brief": brief,
            "sample": {
                "src_ip": sample_ev.src_ip if sample_ev else (top_key if join_on == "src_ip" else None),
                "dst_ip": sample_ev.dst_ip if sample_ev else None,
                "user": sample_ev.user if sample_ev else None,
                "host": sample_ev.host if sample_ev else None,
                "action": sample_ev.action if sample_ev else None,
                "message": sample_ev.message if sample_ev else None,
            },
        },
    )


def run_rules(db: Session, rules_dir: str | Path) -> list[Alert]:
    from .models import Tenant

    tenant_ids = list(db.scalars(select(Tenant.id)).all())
    if not tenant_ids:
        tenant_ids = ["lab"]
    created: list[Alert] = []
    for tenant_id in tenant_ids:
        for rule in load_rules(rules_dir):
            if not rule.get("enabled", True):
                continue
            rtype = (rule.get("type") or "match").lower()
            alert: Alert | None = None
            if rtype == "threshold":
                alert = evaluate_threshold_rule(db, rule, tenant_id=tenant_id)
            elif rtype == "correlation":
                alert = evaluate_correlation_rule(db, rule, tenant_id=tenant_id)
            else:
                alert = evaluate_match_rule(db, rule, tenant_id=tenant_id)
            if alert:
                db.add(alert)
                created.append(alert)
    if created:
        db.commit()
        for a in created:
            db.refresh(a)
    return created