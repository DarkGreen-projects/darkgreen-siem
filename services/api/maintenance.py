"""Retention purge and silent-source ops alerts (tenant-scoped)."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, delete, func, select
from sqlalchemy.orm import Session

from .lab_settings import get_lab_state, record_purge
from .models import Alert, Event, Tenant
from .stats_helpers import KNOWN_SOURCES, health_status

logger = logging.getLogger("darkgreen-siem.maintenance")


def purge_old_events(
    db: Session,
    *,
    retention_days: int | None = None,
    tenant_id: str | None = None,
) -> dict:
    """Delete events older than retention_days. Scoped to tenant_id when set."""
    state = get_lab_state()
    days = state.retention_days if retention_days is None else retention_days
    if days <= 0:
        return {"deleted": 0, "cutoff": None, "skipped": True}

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)
    clauses = [Event.timestamp < cutoff]
    if tenant_id:
        clauses.append(Event.tenant_id == tenant_id)
    result = db.execute(delete(Event).where(and_(*clauses)))
    deleted = int(result.rowcount or 0)
    db.commit()
    record_purge(deleted, now)
    if deleted:
        logger.info(
            "Purged %s event(s) older than %s days (tenant=%s cutoff=%s)",
            deleted,
            days,
            tenant_id or "*",
            cutoff.isoformat(),
        )
    return {"deleted": deleted, "cutoff": cutoff.isoformat(), "skipped": False}


def purge_all_tenants(db: Session, *, retention_days: int | None = None) -> dict:
    """Run retention purge once per known tenant."""
    tenant_ids = list(db.scalars(select(Tenant.id)).all()) or ["lab"]
    total = 0
    cutoff = None
    skipped = True
    for tid in tenant_ids:
        res = purge_old_events(db, retention_days=retention_days, tenant_id=tid)
        total += int(res.get("deleted") or 0)
        if res.get("cutoff"):
            cutoff = res["cutoff"]
        if not res.get("skipped"):
            skipped = False
    return {"deleted": total, "cutoff": cutoff, "skipped": skipped}


def _recent_alert_exists(
    db: Session, rule_id: str, window_minutes: int, *, tenant_id: str
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


def evaluate_silence_alerts(db: Session) -> list[Alert]:
    """Create ops alerts for source_types that have gone silent (per tenant)."""
    state = get_lab_state()
    if not state.silence_alerts_enabled:
        return []

    now = datetime.now(timezone.utc)
    tenant_ids = list(db.scalars(select(Tenant.id)).all()) or ["lab"]
    created: list[Alert] = []
    cooldown = state.health_silent_minutes

    for tenant_id in tenant_ids:
        last_by_source = {
            str(k): v
            for k, v in db.execute(
                select(Event.source_type, func.max(Event.timestamp))
                .where(Event.tenant_id == tenant_id)
                .group_by(Event.source_type)
            ).all()
        }

        for source_type in KNOWN_SOURCES:
            last_at = last_by_source.get(source_type)
            if last_at is None:
                silent_sec = None
            else:
                if last_at.tzinfo is None:
                    last_at = last_at.replace(tzinfo=timezone.utc)
                silent_sec = int((now - last_at).total_seconds())
            status = health_status(
                silent_sec,
                stale_minutes=state.health_stale_minutes,
                silent_minutes=state.health_silent_minutes,
            )
            if status != "silent":
                continue

            rule_id = f"source-silent-{source_type}"
            if _recent_alert_exists(db, rule_id, cooldown, tenant_id=tenant_id):
                continue

            silent_label = (
                "never received" if silent_sec is None else f"{silent_sec // 60} minutes"
            )
            alert = Alert(
                tenant_id=tenant_id,
                rule_id=rule_id,
                rule_name=f"Sorgente silenziosa: {source_type}",
                severity="medium",
                title=f"Nessun evento da {source_type}",
                description=(
                    f"La sorgente {source_type} non riceve eventi da {silent_label} "
                    f"(soglia silent={state.health_silent_minutes}m). "
                    "Verifica collector, agent o pipeline di ingest."
                ),
                status="open",
                evidence={
                    "source_type": source_type,
                    "silent_for_seconds": silent_sec,
                    "status": status,
                    "tenant_id": tenant_id,
                    "threat_brief": (
                        "Sorgente silenziosa: spesso crash collector, ACL, o log-generator spento. "
                        "Confronta con le altre sorgenti e i canali in Setup/Sorgenti."
                    ),
                },
            )
            db.add(alert)
            created.append(alert)

    if created:
        db.commit()
        for a in created:
            db.refresh(a)
        logger.info("Created %s silence alert(s)", len(created))
    return created
