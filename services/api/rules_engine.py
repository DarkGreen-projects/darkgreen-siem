from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from .enrich_providers import keys_matching_enrich
from .lab_settings import get_lab_state
from .models import Alert, Event
from .notify import notify_alert_opened
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
    "dry_run_rules",
    "evaluate_match_rule",
    "evaluate_threshold_rule",
    "evaluate_correlation_rule",
]


def _event_labels(event: Any) -> dict[str, Any]:
    labels = getattr(event, "labels", None) or {}
    return labels if isinstance(labels, dict) else {}


def _match_filters(event: Any, filters: dict[str, Any]) -> bool:
    labels = _event_labels(event)
    for key, expected in filters.items():
        if key.startswith("labels."):
            actual = labels.get(key.split(".", 1)[1])
        else:
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


def _rule_mitre(rule: dict[str, Any]) -> str | None:
    raw = rule.get("mitre")
    if raw is None:
        return None
    if isinstance(raw, list):
        return ",".join(str(x).strip() for x in raw if str(x).strip()) or None
    text = str(raw).strip()
    return text or None


def _entity_key(rule: dict[str, Any], evidence: dict[str, Any]) -> str:
    if evidence.get("join_key"):
        return f"join:{evidence['join_key']}"
    if evidence.get("group_by") and evidence.get("sample", {}).get("key") is not None:
        return f"group:{evidence['group_by']}={evidence['sample']['key']}"
    sample = evidence.get("sample") or {}
    for field in ("src_ip", "host", "user"):
        if sample.get(field):
            return f"{field}:{sample[field]}"
    return f"rule:{rule.get('id')}"


def _find_mergeable(
    db: Session,
    *,
    rule_id: str,
    tenant_id: str,
    entity_key: str,
    window_minutes: int,
) -> Alert | None:
    since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    rows = list(
        db.scalars(
            select(Alert)
            .where(
                and_(
                    Alert.rule_id == rule_id,
                    Alert.tenant_id == tenant_id,
                    Alert.created_at >= since,
                    Alert.status != "closed",
                )
            )
            .order_by(Alert.created_at.desc())
            .limit(50)
        ).all()
    )
    for alert in rows:
        ev = dict(getattr(alert, "evidence", None) or {})
        if ev.get("entity_key") == entity_key:
            return alert
    return None


def _merge_alert(existing: Alert, evidence: dict[str, Any]) -> Alert:
    ev = dict(existing.evidence or {})
    prev = int(ev.get("occurrences") or ev.get("count") or 1)
    ev["occurrences"] = prev + 1
    ev["count"] = int(evidence.get("count") or ev.get("count") or prev + 1)
    ev["last_seen"] = datetime.now(timezone.utc).isoformat()
    ids = list(ev.get("event_ids") or [])
    for eid in evidence.get("event_ids") or []:
        if eid not in ids:
            ids.append(eid)
    ev["event_ids"] = ids[:20]
    if evidence.get("sample"):
        ev["sample"] = evidence["sample"]
    if evidence.get("entity_key"):
        ev["entity_key"] = evidence["entity_key"]
    existing.evidence = ev
    return existing


def _finalize_alert(
    db: Session,
    rule: dict[str, Any],
    alert: Alert,
    *,
    cooldown_minutes: int,
    dry_run: bool = False,
) -> tuple[Alert | None, bool]:
    """Return (alert, created). created=False means merged or skipped dry."""
    evidence = dict(alert.evidence or {})
    entity = _entity_key(rule, evidence)
    evidence["entity_key"] = entity
    mitre = _rule_mitre(rule)
    if mitre:
        evidence["mitre"] = mitre
        alert.mitre = mitre
    alert.evidence = evidence

    if dry_run:
        return alert, True

    existing = _find_mergeable(
        db,
        rule_id=rule["id"],
        tenant_id=alert.tenant_id,
        entity_key=entity,
        window_minutes=cooldown_minutes,
    )
    if existing is not None:
        merged = _merge_alert(existing, evidence)
        db.add(merged)
        return merged, False

    db.add(alert)
    return alert, True


def evaluate_match_rule(
    db: Session,
    rule: dict[str, Any],
    *,
    tenant_id: str = "lab",
    events: list[Any] | None = None,
    dry_run: bool = False,
) -> tuple[Alert | None, bool]:
    filters = rule.get("match") or rule.get("filters") or {}
    window = int(rule.get("window_minutes") or 10)
    if events is None:
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
        return None, False
    sample = hits[0]
    brief = (rule.get("threat_brief") or "").strip() or None
    alert = Alert(
        tenant_id=tenant_id,
        rule_id=rule["id"],
        rule_name=rule.get("name") or rule["id"],
        severity=rule.get("severity") or "medium",
        title=rule.get("title") or rule.get("name") or rule["id"],
        description=rule.get("description") or f"Matched {len(hits)} event(s)",
        status="open",
        mitre=_rule_mitre(rule),
        evidence={
            "count": len(hits),
            "occurrences": 1,
            "event_ids": [getattr(h, "id", None) for h in hits[:10] if getattr(h, "id", None)],
            "threat_brief": brief,
            "sample": {
                "id": getattr(sample, "id", None),
                "user": sample.user,
                "src_ip": sample.src_ip,
                "dst_ip": sample.dst_ip,
                "host": sample.host,
                "action": sample.action,
                "message": sample.message,
            },
        },
    )
    return _finalize_alert(
        db,
        rule,
        alert,
        cooldown_minutes=int(rule.get("cooldown_minutes") or window),
        dry_run=dry_run,
    )


def evaluate_threshold_rule(
    db: Session,
    rule: dict[str, Any],
    *,
    tenant_id: str = "lab",
    events: list[Any] | None = None,
    dry_run: bool = False,
) -> tuple[Alert | None, bool]:
    filters = rule.get("match") or rule.get("filters") or {}
    window = int(rule.get("window_minutes") or 5)
    threshold = int(rule.get("threshold") or 5)
    group_by = rule.get("group_by") or "user"
    rows: list[tuple[Any, int]] = []

    if events is not None:
        hits = [e for e in events if _match_filters(e, filters)]
        counts: Counter[str] = Counter()
        for e in hits:
            key = getattr(e, group_by, None)
            if key is None or str(key).strip() == "":
                continue
            counts[str(key)] += 1
        rows = [(k, c) for k, c in counts.items() if c >= threshold]
        if not rows:
            return None, False
        top_key, top_count = max(rows, key=lambda x: x[1])
    else:
        col = getattr(Event, group_by, None)
        if col is None:
            return None, False
        since = datetime.now(timezone.utc) - timedelta(minutes=window)
        clauses = [Event.timestamp >= since, Event.tenant_id == tenant_id]
        for key, expected in filters.items():
            if key.startswith("labels."):
                continue
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
            return None, False
        top_key, top_count = rows[0]

    brief = (rule.get("threat_brief") or "").strip() or None
    alert = Alert(
        tenant_id=tenant_id,
        rule_id=rule["id"],
        rule_name=rule.get("name") or rule["id"],
        severity=rule.get("severity") or "high",
        title=rule.get("title") or f"{rule.get('name')} ({top_key})",
        description=rule.get("description")
        or f"{top_count} matching events for {group_by}={top_key} in {window}m",
        status="open",
        mitre=_rule_mitre(rule),
        evidence={
            "group_by": group_by,
            "groups": [{"key": str(k), "count": int(c)} for k, c in rows[:10]],
            "threshold": threshold,
            "window_minutes": window,
            "count": int(top_count),
            "occurrences": 1,
            "threat_brief": brief,
            "sample": {
                "src_ip": str(top_key) if group_by == "src_ip" else None,
                "key": str(top_key),
            },
        },
    )
    return _finalize_alert(
        db,
        rule,
        alert,
        cooldown_minutes=int(rule.get("cooldown_minutes") or window),
        dry_run=dry_run,
    )


def evaluate_correlation_rule(
    db: Session,
    rule: dict[str, Any],
    *,
    tenant_id: str = "lab",
    events: list[Any] | None = None,
    dry_run: bool = False,
) -> tuple[Alert | None, bool]:
    steps = rule.get("steps") or []
    if len(steps) < 2:
        return None, False
    join_on = str(rule.get("join_on") or "src_ip")
    window = int(rule.get("window_minutes") or 30)
    if events is None:
        if not hasattr(Event, join_on):
            return None, False
        since = datetime.now(timezone.utc) - timedelta(minutes=window)
        stmt = (
            select(Event)
            .where(and_(Event.timestamp >= since, Event.tenant_id == tenant_id))
            .order_by(Event.timestamp.desc())
            .limit(2000)
        )
        events = list(db.scalars(stmt).all())
    if not events:
        return None, False

    step_keys: list[set[str]] = []
    step_counts: list[Counter[str]] = []
    candidate_keys: set[str] | None = None

    for step in steps:
        if step.get("enrich"):
            if dry_run:
                # Skip live enrich fetches in dry-run; treat as no match unless cache hit
                enrich = step["enrich"] or {}
                providers = list(enrich.get("providers") or ["vt"])
                verdicts = list(enrich.get("verdicts") or ["malicious", "suspicious"])
                ioc_type = str(enrich.get("ioc_type") or "ip")
                pool = candidate_keys or {
                    str(getattr(e, join_on))
                    for e in events
                    if getattr(e, join_on, None) not in (None, "")
                }
                matched = keys_matching_enrich(
                    db,
                    pool,
                    providers=providers,
                    verdicts=verdicts,
                    ioc_type=ioc_type,
                    state=get_lab_state(),
                    tenant_id=tenant_id,
                )
            else:
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
            return None, False

    shared = set(candidate_keys)
    if not shared:
        return None, False

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
    alert = Alert(
        tenant_id=tenant_id,
        rule_id=rule["id"],
        rule_name=rule.get("name") or rule["id"],
        severity=rule.get("severity") or "critical",
        title=rule.get("title") or f"{rule.get('name')} ({join_on}={top_key})",
        description=rule.get("description")
        or f"Correlated {len(steps)} signals on {join_on}={top_key} within {window}m",
        status="open",
        mitre=_rule_mitre(rule),
        evidence={
            "join_on": join_on,
            "join_key": top_key,
            "keys": sorted(shared)[:20],
            "steps": step_summary,
            "window_minutes": window,
            "occurrences": 1,
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
    return _finalize_alert(
        db,
        rule,
        alert,
        cooldown_minutes=int(rule.get("cooldown_minutes") or window),
        dry_run=dry_run,
    )


def run_rules(db: Session, rules_dir: str | Path) -> list[Alert]:
    from .models import Tenant

    tenant_ids = list(db.scalars(select(Tenant.id)).all())
    if not tenant_ids:
        tenant_ids = ["lab"]
    created: list[Alert] = []
    touched: list[Alert] = []
    for tenant_id in tenant_ids:
        for rule in load_rules(rules_dir):
            if not rule.get("enabled", True):
                continue
            rtype = (rule.get("type") or "match").lower()
            if rtype == "threshold":
                alert, is_new = evaluate_threshold_rule(db, rule, tenant_id=tenant_id)
            elif rtype == "correlation":
                alert, is_new = evaluate_correlation_rule(db, rule, tenant_id=tenant_id)
            else:
                alert, is_new = evaluate_match_rule(db, rule, tenant_id=tenant_id)
            if alert is None:
                continue
            touched.append(alert)
            if is_new:
                created.append(alert)

    if touched:
        db.commit()
        for a in touched:
            db.refresh(a)
        for a in created:
            notify_alert_opened(a)
    return created


def dry_run_rules(
    db: Session,
    rules_dir: str | Path,
    events: list[Any],
    *,
    rule_ids: list[str] | None = None,
    tenant_id: str = "lab",
) -> tuple[list[dict[str, Any]], int]:
    """Evaluate rules against in-memory events; do not persist alerts.

    Returns (hits, events_normalized_count).
    """
    from services.normalizers import normalize_event

    mem_events: list[Any] = []
    for i, item in enumerate(events):
        if hasattr(item, "source_type") and hasattr(item, "message"):
            mem_events.append(item)
            continue
        hint = None
        payload: Any = item
        if isinstance(item, dict) and "source_type" in item and "raw" not in item and "message" in item:
            # already shaped like a normalized row
            mem_events.append(event_from_normalized({**item, "tenant_id": tenant_id}, fake_id=-(i + 1)))
            continue
        if isinstance(item, dict):
            hint = item.get("source_type") if isinstance(item.get("source_type"), str) else None
            payload = item
        try:
            neo = normalize_event(payload, source_type=hint, ingest_channel="dry-run")
            row = neo.model_dump() if hasattr(neo, "model_dump") else dict(neo)
            row["tenant_id"] = tenant_id
            mem_events.append(event_from_normalized(row, fake_id=-(i + 1)))
        except Exception as exc:
            raise ValueError(f"event[{i}] normalize failed: {exc}") from exc

    wanted = {r.lower() for r in (rule_ids or [])} if rule_ids else None
    out: list[dict[str, Any]] = []
    for rule in load_rules(rules_dir):
        if not rule.get("enabled", True):
            continue
        if wanted is not None and rule["id"].lower() not in wanted:
            continue
        rtype = (rule.get("type") or "match").lower()
        if rtype == "threshold":
            alert, _ = evaluate_threshold_rule(
                db, rule, tenant_id=tenant_id, events=mem_events, dry_run=True
            )
        elif rtype == "correlation":
            alert, _ = evaluate_correlation_rule(
                db, rule, tenant_id=tenant_id, events=mem_events, dry_run=True
            )
        else:
            alert, _ = evaluate_match_rule(
                db, rule, tenant_id=tenant_id, events=mem_events, dry_run=True
            )
        if alert:
            out.append(
                {
                    "rule_id": alert.rule_id,
                    "rule_name": alert.rule_name,
                    "severity": alert.severity,
                    "title": alert.title,
                    "mitre": alert.mitre,
                    "would_create": True,
                    "evidence": alert.evidence,
                }
            )
    return out, len(mem_events)


def event_from_normalized(row: dict[str, Any], *, fake_id: int = 0) -> SimpleNamespace:
    return SimpleNamespace(id=fake_id or None, **row)
