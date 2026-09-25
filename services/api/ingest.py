from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from services.normalizers import normalize_event

from .config import get_settings
from .models import Event, IngestStat


def bump_channel(
    db: Session, channel: str, when: datetime | None = None, *, tenant_id: str = "lab"
) -> None:
    when = when or datetime.now(timezone.utc)
    tid = tenant_id or "lab"
    stat = db.get(IngestStat, {"tenant_id": tid, "channel": channel})
    if stat is None:
        stat = IngestStat(tenant_id=tid, channel=channel, count=0)
        db.add(stat)
        db.flush()
    stat.count = int(stat.count or 0) + 1
    stat.last_event_at = when


def insert_normalized(db: Session, event_data: dict[str, Any]) -> Event:
    if "tenant_id" not in event_data or not event_data.get("tenant_id"):
        event_data = {**event_data, "tenant_id": get_settings().default_tenant_id}
    row = Event(**event_data)
    db.add(row)
    db.flush()
    bump_channel(db, row.ingest_channel, row.timestamp, tenant_id=row.tenant_id)
    return row


def ingest_payload(
    db: Session,
    payload: Any,
    *,
    source_type: str | None = None,
    ingest_channel: str = "http",
    tenant_id: str | None = None,
) -> Event:
    normalized = normalize_event(
        payload, source_type=source_type, ingest_channel=ingest_channel
    )
    row_data = normalized.to_row()
    row_data["tenant_id"] = tenant_id or get_settings().default_tenant_id
    return insert_normalized(db, row_data)


def ingest_many(
    db: Session,
    items: list[tuple[Any, str | None, str]],
    *,
    tenant_id: str | None = None,
) -> list[int]:
    ids: list[int] = []
    tid = tenant_id or get_settings().default_tenant_id
    for payload, source_type, channel in items:
        row = ingest_payload(
            db, payload, source_type=source_type, ingest_channel=channel, tenant_id=tid
        )
        ids.append(row.id)
    db.commit()
    return ids


def list_sources(db: Session, *, tenant_id: str | None = None) -> list[IngestStat]:
    stmt = select(IngestStat).order_by(IngestStat.channel)
    if tenant_id:
        stmt = stmt.where(IngestStat.tenant_id == tenant_id)
    return list(db.scalars(stmt).all())
