from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from .models import Alert, Event


def load_rules(rules_dir: str | Path) -> list[dict[str, Any]]:
    root = Path(rules_dir)
    if not root.exists():
        return []
    rules: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.yml")) + sorted(root.glob("*.yaml")):
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if not isinstance(data, dict):
            continue
        data.setdefault("id", path.stem)
        data.setdefault("enabled", True)
        data["_path"] = str(path)
        rules.append(data)
    return rules


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


def _recent_alert_exists(db: Session, rule_id: str, window_minutes: int) -> bool:
    since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    stmt = (
        select(func.count())
        .select_from(Alert)
        .where(and_(Alert.rule_id == rule_id, Alert.created_at >= since))
    )
    return (db.scalar(stmt) or 0) > 0


def evaluate_match_rule(db: Session, rule: dict[str, Any]) -> Alert | None:
    filters = rule.get("match") or rule.get("filters") or {}
    window = int(rule.get("window_minutes") or 10)
    since = datetime.now(timezone.utc) - timedelta(minutes=window)
    stmt = select(Event).where(Event.timestamp >= since).order_by(Event.timestamp.desc()).limit(200)
    events = list(db.scalars(stmt).all())
    hits = [e for e in events if _match_filters(e, filters)]
    if not hits:
        return None
    if _recent_alert_exists(db, rule["id"], int(rule.get("cooldown_minutes") or window)):
        return None
    sample = hits[0]
    return Alert(
        rule_id=rule["id"],
        rule_name=rule.get("name") or rule["id"],
        severity=rule.get("severity") or "medium",
        title=rule.get("title") or rule.get("name") or rule["id"],
        description=rule.get("description") or f"Matched {len(hits)} event(s)",
        status="open",
        evidence={
            "count": len(hits),
            "event_ids": [h.id for h in hits[:10]],
            "sample": {
                "id": sample.id,
                "user": sample.user,
                "src_ip": sample.src_ip,
                "action": sample.action,
                "message": sample.message,
            },
        },
    )


def evaluate_threshold_rule(db: Session, rule: dict[str, Any]) -> Alert | None:
    filters = rule.get("match") or rule.get("filters") or {}
    window = int(rule.get("window_minutes") or 5)
    threshold = int(rule.get("threshold") or 5)
    group_by = rule.get("group_by") or "user"
    since = datetime.now(timezone.utc) - timedelta(minutes=window)

    col = getattr(Event, group_by, None)
    if col is None:
        return None

    clauses = [Event.timestamp >= since]
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
    if _recent_alert_exists(db, rule["id"], int(rule.get("cooldown_minutes") or window)):
        return None

    top_key, top_count = rows[0]
    return Alert(
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
        },
    )


def run_rules(db: Session, rules_dir: str | Path) -> list[Alert]:
    created: list[Alert] = []
    for rule in load_rules(rules_dir):
        if not rule.get("enabled", True):
            continue
        rtype = (rule.get("type") or "match").lower()
        alert: Alert | None = None
        if rtype == "threshold":
            alert = evaluate_threshold_rule(db, rule)
        else:
            alert = evaluate_match_rule(db, rule)
        if alert:
            db.add(alert)
            created.append(alert)
    if created:
        db.commit()
        for a in created:
            db.refresh(a)
    return created
