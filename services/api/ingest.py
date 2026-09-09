from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from services.normalizers import normalize_event

from .models import Event, IngestStat


def bump_channel(db: Session, channel: str, when: datetime | None = None) -> None:
    when = when or datetime.now(timezone.utc)
    stat = db.get(IngestStat, channel)
    if stat is None:
        stat = IngestStat(channel=channel, count=0)
        db.add(stat)
        db.flush()
    stat.count = int(stat.count or 0) + 1
    stat.last_event_at = when


def insert_normalized(db: Session, event_data: dict[str, Any]) -> Event:
    row = Event(**event_data)
    db.add(row)
    db.flush()
    bump_channel(db, row.ingest_channel, row.timestamp)
    return row


def ingest_payload(
    db: Session,
    payload: Any,
    *,
    source_type: str | None = None,
    ingest_channel: str = "http",
) -> Event:
    normalized = normalize_event(
        payload, source_type=source_type, ingest_channel=ingest_channel
    )
    return insert_normalized(db, normalized.to_row())


def ingest_many(
    db: Session,
    items: list[tuple[Any, str | None, str]],
) -> list[int]:
    ids: list[int] = []
    for payload, source_type, channel in items:
        row = ingest_payload(db, payload, source_type=source_type, ingest_channel=channel)
        ids.append(row.id)
    db.commit()
    return ids


def list_sources(db: Session) -> list[IngestStat]:
    return list(db.scalars(select(IngestStat).order_by(IngestStat.channel)).all())
