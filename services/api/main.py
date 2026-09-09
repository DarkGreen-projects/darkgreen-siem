from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import SessionLocal, get_db, init_db
from .ingest import ingest_many, ingest_payload, list_sources
from .models import Alert, Event
from .rules_engine import load_rules, run_rules
from .schemas import (
    AlertOut,
    EventOut,
    IngestRequest,
    IngestResponse,
    RuleOut,
    SearchResponse,
    SourceOut,
    StatsOut,
)
from .search import search_events
from .seed import seed_samples
from .syslog_server import start_syslog_server

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("darkgreen-siem")
settings = get_settings()


def _handle_syslog(message: str, host: str) -> None:
    db = SessionLocal()
    try:
        # strip RFC3164 priority if present
        text = message
        if text.startswith("<") and ">" in text[:5]:
            text = text.split(">", 1)[1]
        ingest_payload(db, text, source_type="firewall", ingest_channel="syslog")
        db.commit()
    except Exception:
        logger.exception("Syslog ingest failed from %s", host)
        db.rollback()
    finally:
        db.close()


async def _rules_loop(stop: asyncio.Event) -> None:
    while not stop.is_set():
        db = SessionLocal()
        try:
            created = run_rules(db, settings.rules_dir)
            if created:
                logger.info("Created %s alert(s)", len(created))
        except Exception:
            logger.exception("Rule engine error")
            db.rollback()
        finally:
            db.close()
        try:
            await asyncio.wait_for(stop.wait(), timeout=settings.rule_interval_sec)
        except asyncio.TimeoutError:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    db = SessionLocal()
    try:
        if settings.seed_on_start:
            seed_samples(db, settings.samples_dir)
            run_rules(db, settings.rules_dir)
    finally:
        db.close()

    stop = asyncio.Event()
    transport = await start_syslog_server(
        settings.syslog_host, settings.syslog_port, _handle_syslog
    )
    rules_task = asyncio.create_task(_rules_loop(stop))
    logger.info("DarkGreen SIEM API ready")
    try:
        yield
    finally:
        stop.set()
        rules_task.cancel()
        transport.close()


app = FastAPI(
    title="DarkGreen SIEM",
    description="Multi-source demo SIEM — ingest, normalize, search, detect",
    version="0.1.0",
    lifespan=lifespan,
)

origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "darkgreen-siem"}


@app.post("/api/ingest", response_model=IngestResponse)
def api_ingest(body: IngestRequest, db: Session = Depends(get_db)) -> IngestResponse:
    items: list[tuple[Any, str | None, str]] = []
    for ev in body.events:
        items.append((ev.payload, ev.source_type, ev.ingest_channel or "http"))
    if body.raw is not None:
        items.append((body.raw, body.source_type, body.ingest_channel or "http"))
    if not items:
        raise HTTPException(status_code=400, detail="No events provided")
    ids = ingest_many(db, items)
    return IngestResponse(inserted=len(ids), ids=ids)


@app.get("/api/events/search", response_model=SearchResponse)
def api_search(
    q: str = Query("", description="field:value AND free-text"),
    source_type: str | None = None,
    severity: str | None = None,
    since_minutes: int | None = Query(None, ge=1, le=10080),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> SearchResponse:
    total, events = search_events(
        db,
        q,
        source_type=source_type,
        severity=severity,
        since_minutes=since_minutes,
        limit=limit,
        offset=offset,
    )
    return SearchResponse(total=total, events=[EventOut.model_validate(e) for e in events])


@app.get("/api/events/{event_id}", response_model=EventOut)
def api_event(event_id: int, db: Session = Depends(get_db)) -> EventOut:
    event = db.get(Event, event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return EventOut.model_validate(event)


@app.get("/api/stats", response_model=StatsOut)
def api_stats(db: Session = Depends(get_db)) -> StatsOut:
    total_events = db.scalar(select(func.count()).select_from(Event)) or 0
    total_alerts = db.scalar(select(func.count()).select_from(Alert)) or 0
    open_alerts = (
        db.scalar(select(func.count()).select_from(Alert).where(Alert.status == "open")) or 0
    )

    since = datetime.now(timezone.utc) - timedelta(minutes=1)
    last_min = (
        db.scalar(select(func.count()).select_from(Event).where(Event.timestamp >= since)) or 0
    )
    eps = float(last_min) / 60.0

    by_source = {
        str(k): int(v)
        for k, v in db.execute(
            select(Event.source_type, func.count()).group_by(Event.source_type)
        ).all()
    }
    by_sev = {
        str(k): int(v)
        for k, v in db.execute(
            select(Event.severity, func.count()).group_by(Event.severity)
        ).all()
    }
    by_channel = {
        str(k): int(v)
        for k, v in db.execute(
            select(Event.ingest_channel, func.count()).group_by(Event.ingest_channel)
        ).all()
    }

    # 12 buckets of 5 minutes
    timeline: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)
    for i in range(11, -1, -1):
        start = now - timedelta(minutes=5 * (i + 1))
        end = now - timedelta(minutes=5 * i)
        count = (
            db.scalar(
                select(func.count())
                .select_from(Event)
                .where(and_(Event.timestamp >= start, Event.timestamp < end))
            )
            or 0
        )
        timeline.append({"bucket": start.isoformat(), "count": int(count)})

    recent = list(
        db.scalars(select(Alert).order_by(Alert.created_at.desc()).limit(8)).all()
    )
    return StatsOut(
        total_events=int(total_events),
        total_alerts=int(total_alerts),
        open_alerts=int(open_alerts),
        eps_approx=round(eps, 2),
        by_source_type=by_source,
        by_severity=by_sev,
        by_channel=by_channel,
        timeline=timeline,
        recent_alerts=[AlertOut.model_validate(a) for a in recent],
    )


@app.get("/api/sources", response_model=list[SourceOut])
def api_sources(db: Session = Depends(get_db)) -> list[SourceOut]:
    return [
        SourceOut(channel=s.channel, count=int(s.count or 0), last_event_at=s.last_event_at)
        for s in list_sources(db)
    ]


@app.get("/api/rules", response_model=list[RuleOut])
def api_rules() -> list[RuleOut]:
    out: list[RuleOut] = []
    for rule in load_rules(settings.rules_dir):
        out.append(
            RuleOut(
                id=rule.get("id") or "unknown",
                name=rule.get("name") or rule.get("id") or "unnamed",
                description=rule.get("description") or "",
                severity=rule.get("severity") or "medium",
                type=rule.get("type") or "match",
                enabled=bool(rule.get("enabled", True)),
                definition={k: v for k, v in rule.items() if not str(k).startswith("_")},
            )
        )
    return out


@app.get("/api/alerts", response_model=list[AlertOut])
def api_alerts(
    status: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> list[AlertOut]:
    stmt = select(Alert).order_by(Alert.created_at.desc()).limit(limit)
    if status:
        stmt = stmt.where(Alert.status == status)
    return [AlertOut.model_validate(a) for a in db.scalars(stmt).all()]


@app.post("/api/alerts/{alert_id}/ack", response_model=AlertOut)
def api_ack_alert(alert_id: int, db: Session = Depends(get_db)) -> AlertOut:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = "acked"
    alert.acked_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(alert)
    return AlertOut.model_validate(alert)


@app.post("/api/rules/run", response_model=list[AlertOut])
def api_run_rules(db: Session = Depends(get_db)) -> list[AlertOut]:
    created = run_rules(db, settings.rules_dir)
    return [AlertOut.model_validate(a) for a in created]
