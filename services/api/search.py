"""Search helpers built on the demo query parser."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import Select, and_, cast, func, or_, select
from sqlalchemy.orm import Session
from sqlalchemy.types import String

from .models import Event
from .query_parse import parse_query

FIELD_MAP = {
    "src_ip": Event.src_ip,
    "dst_ip": Event.dst_ip,
    "user": Event.user,
    "host": Event.host,
    "action": Event.action,
    "severity": Event.severity,
    "source_type": Event.source_type,
    "vendor": Event.vendor,
    "device": Event.device,
    "ingest_channel": Event.ingest_channel,
    "message": Event.message,
}


def build_search_query(
    q: str = "",
    *,
    source_type: str | None = None,
    severity: str | None = None,
    since_minutes: int | None = None,
    limit: int = 100,
    offset: int = 0,
) -> Select:
    stmt = select(Event)
    clauses = []

    field_filters, free_terms = parse_query(q)
    for field, value in field_filters:
        col = FIELD_MAP.get(field)
        if col is None:
            continue
        if field == "message":
            clauses.append(col.ilike(f"%{value}%"))
        else:
            clauses.append(func.lower(cast(col, String)) == value.lower())

    for term in free_terms:
        like = f"%{term}%"
        clauses.append(
            or_(
                Event.message.ilike(like),
                Event.raw.ilike(like),
                Event.user.ilike(like),
                Event.host.ilike(like),
                Event.src_ip.ilike(like),
                Event.dst_ip.ilike(like),
                Event.action.ilike(like),
            )
        )

    if source_type:
        clauses.append(Event.source_type == source_type)
    if severity:
        clauses.append(Event.severity == severity.lower())
    if since_minutes:
        since = datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
        clauses.append(Event.timestamp >= since)

    if clauses:
        stmt = stmt.where(and_(*clauses))
    return stmt.order_by(Event.timestamp.desc()).offset(offset).limit(min(limit, 500))


def search_events(
    db: Session,
    q: str = "",
    *,
    source_type: str | None = None,
    severity: str | None = None,
    since_minutes: int | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[int, list[Event]]:
    base = build_search_query(
        q,
        source_type=source_type,
        severity=severity,
        since_minutes=since_minutes,
        limit=limit,
        offset=offset,
    )
    count_stmt = select(func.count()).select_from(Event)
    field_filters, free_terms = parse_query(q)
    clauses = []
    for field, value in field_filters:
        col = FIELD_MAP.get(field)
        if col is None:
            continue
        if field == "message":
            clauses.append(col.ilike(f"%{value}%"))
        else:
            clauses.append(func.lower(cast(col, String)) == value.lower())
    for term in free_terms:
        like = f"%{term}%"
        clauses.append(
            or_(
                Event.message.ilike(like),
                Event.raw.ilike(like),
                Event.user.ilike(like),
                Event.host.ilike(like),
                Event.src_ip.ilike(like),
                Event.dst_ip.ilike(like),
                Event.action.ilike(like),
            )
        )
    if source_type:
        clauses.append(Event.source_type == source_type)
    if severity:
        clauses.append(Event.severity == severity.lower())
    if since_minutes:
        since = datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
        clauses.append(Event.timestamp >= since)
    if clauses:
        count_stmt = count_stmt.where(and_(*clauses))

    total = db.scalar(count_stmt) or 0
    events = list(db.scalars(base).all())
    return int(total), events
