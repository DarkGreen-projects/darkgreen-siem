from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import SessionLocal, get_db, init_db
from .ingest import ingest_many, ingest_payload, list_sources
from .models import Alert, AlertComment, Event
from .rules_engine import (
    RuleConflictError,
    RuleValidationError,
    delete_rule,
    load_rules,
    run_rules,
    save_rule,
    set_rule_enabled,
)
from .schemas import (
    ALERT_STATUSES,
    AlertOut,
    AlertSearchHit,
    CommentCreate,
    CommentOut,
    EventOut,
    IngestRequest,
    IngestResponse,
    RuleCreate,
    RuleEnabledUpdate,
    RuleOut,
    SearchResponse,
    SourceHealthOut,
    SourceOut,
    StatsOut,
    StatusUpdate,
)
from .alert_search import search_alerts_by_text
from .search import search_events
from .seed import seed_samples
from .stats_helpers import (
    KNOWN_SOURCES,
    build_bucket_bounds,
    health_status,
    normalize_range,
    resolve_threat_brief,
    threat_brief_lookup,
)
from .syslog_server import start_syslog_server

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("darkgreen-siem")
settings = get_settings()


def _rule_briefs() -> dict[str, str]:
    return threat_brief_lookup(load_rules(settings.rules_dir))


def _load_comments(db: Session, alert_id: int) -> list[AlertComment]:
    return list(
        db.scalars(
            select(AlertComment)
            .where(AlertComment.alert_id == alert_id)
            .order_by(AlertComment.created_at.asc())
        ).all()
    )


def alert_to_out(
    alert: Alert,
    briefs: dict[str, str] | None = None,
    *,
    db: Session | None = None,
    comments: list[AlertComment] | None = None,
    include_comments: bool = True,
) -> AlertOut:
    briefs = briefs if briefs is not None else _rule_briefs()
    evidence = dict(alert.evidence or {})
    brief = resolve_threat_brief(alert.rule_id, evidence, briefs)
    comment_rows: list[AlertComment] = []
    if include_comments:
        if comments is not None:
            comment_rows = comments
        elif db is not None:
            comment_rows = _load_comments(db, alert.id)
    return AlertOut(
        id=alert.id,
        rule_id=alert.rule_id,
        rule_name=alert.rule_name,
        severity=alert.severity,
        title=alert.title,
        description=alert.description,
        status=alert.status,
        evidence=evidence,
        threat_brief=brief,
        comments=[CommentOut.model_validate(c) for c in comment_rows],
        created_at=alert.created_at,
        acked_at=alert.acked_at,
    )


def apply_alert_status(alert: Alert, status: str) -> None:
    status = status.strip().lower()
    if status not in ALERT_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Allowed: {', '.join(sorted(ALERT_STATUSES))}",
        )
    alert.status = status
    if status == "acked":
        alert.acked_at = datetime.now(timezone.utc)


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
    briefs = _rule_briefs()
    total, events = search_events(
        db,
        q,
        source_type=source_type,
        severity=severity,
        since_minutes=since_minutes,
        limit=limit,
        offset=offset,
    )
    alert_hits: list[AlertSearchHit] = []
    for alert, matched in search_alerts_by_text(db, q, limit=25):
        base = alert_to_out(alert, briefs, db=db)
        alert_hits.append(
            AlertSearchHit(**base.model_dump(), matched_comment=matched)
        )
    return SearchResponse(
        total=total,
        events=[EventOut.model_validate(e) for e in events],
        alerts=alert_hits,
    )


@app.get("/api/events/{event_id}", response_model=EventOut)
def api_event(event_id: int, db: Session = Depends(get_db)) -> EventOut:
    event = db.get(Event, event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return EventOut.model_validate(event)


@app.get("/api/stats", response_model=StatsOut)
def api_stats(
    range: str = Query("1h", description="1h | 1d | 7d | 30d | 1y"),
    db: Session = Depends(get_db),
) -> StatsOut:
    range_key = normalize_range(range)
    briefs = _rule_briefs()

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

    now = datetime.now(timezone.utc)
    timeline: list[dict[str, Any]] = []
    for start, end in build_bucket_bounds(range_key, now):
        rows = db.execute(
            select(Event.source_type, func.count())
            .where(and_(Event.timestamp >= start, Event.timestamp < end))
            .group_by(Event.source_type)
        ).all()
        by_src = {str(k): int(v) for k, v in rows}
        timeline.append(
            {
                "bucket": start.isoformat(),
                "count": sum(by_src.values()),
                "by_source": by_src,
            }
        )

    last_by_source = {
        str(k): v
        for k, v in db.execute(
            select(Event.source_type, func.max(Event.timestamp)).group_by(Event.source_type)
        ).all()
    }
    known = list(KNOWN_SOURCES)
    for extra in by_source:
        if extra not in known:
            known.append(extra)

    source_health: list[SourceHealthOut] = []
    for st in known:
        last_at = last_by_source.get(st)
        if last_at is None:
            silent = None
        else:
            if last_at.tzinfo is None:
                last_at = last_at.replace(tzinfo=timezone.utc)
            silent = int((now - last_at).total_seconds())
        source_health.append(
            SourceHealthOut(
                source_type=st,
                last_event_at=last_at,
                silent_for_seconds=silent,
                status=health_status(silent),
            )
        )

    recent = list(
        db.scalars(select(Alert).order_by(Alert.created_at.desc()).limit(8)).all()
    )
    return StatsOut(
        range=range_key,
        total_events=int(total_events),
        total_alerts=int(total_alerts),
        open_alerts=int(open_alerts),
        eps_approx=round(eps, 2),
        by_source_type=by_source,
        by_severity=by_sev,
        by_channel=by_channel,
        timeline=timeline,
        source_health=source_health,
        recent_alerts=[alert_to_out(a, briefs, db=db) for a in recent],
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
        brief = (rule.get("threat_brief") or "").strip() or None
        out.append(
            RuleOut(
                id=rule.get("id") or "unknown",
                name=rule.get("name") or rule.get("id") or "unnamed",
                description=rule.get("description") or "",
                threat_brief=brief,
                severity=rule.get("severity") or "medium",
                type=rule.get("type") or "match",
                enabled=bool(rule.get("enabled", True)),
                definition={k: v for k, v in rule.items() if not str(k).startswith("_")},
            )
        )
    return out


def _rule_to_out(rule: dict[str, Any]) -> RuleOut:
    brief = (rule.get("threat_brief") or "").strip() or None
    return RuleOut(
        id=rule.get("id") or "unknown",
        name=rule.get("name") or rule.get("id") or "unnamed",
        description=rule.get("description") or "",
        threat_brief=brief,
        severity=rule.get("severity") or "medium",
        type=rule.get("type") or "match",
        enabled=bool(rule.get("enabled", True)),
        definition={k: v for k, v in rule.items() if not str(k).startswith("_")},
    )


@app.post("/api/rules", response_model=RuleOut, status_code=201)
def api_create_rule(body: RuleCreate) -> RuleOut:
    payload = body.model_dump()
    overwrite = bool(payload.pop("overwrite", False))
    try:
        saved = save_rule(settings.rules_dir, payload, overwrite=overwrite)
    except RuleValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuleConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to write rule: {exc}") from exc
    return _rule_to_out(saved)


@app.put("/api/rules/{rule_id}", response_model=RuleOut)
def api_update_rule(rule_id: str, body: RuleCreate) -> RuleOut:
    payload = body.model_dump()
    payload.pop("overwrite", None)
    if payload.get("id", "").strip().lower() != rule_id.strip().lower():
        raise HTTPException(status_code=400, detail="Path id must match body id")
    try:
        saved = save_rule(settings.rules_dir, payload, overwrite=True)
    except RuleValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to write rule: {exc}") from exc
    return _rule_to_out(saved)


@app.delete("/api/rules/{rule_id}", status_code=204)
def api_delete_rule(rule_id: str) -> Response:
    try:
        delete_rule(settings.rules_dir, rule_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to delete rule: {exc}") from exc
    return Response(status_code=204)


@app.patch("/api/rules/{rule_id}/enabled", response_model=RuleOut)
def api_set_rule_enabled(rule_id: str, body: RuleEnabledUpdate) -> RuleOut:
    try:
        saved = set_rule_enabled(settings.rules_dir, rule_id, body.enabled)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuleValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to update rule: {exc}") from exc
    return _rule_to_out(saved)


@app.get("/api/alerts", response_model=list[AlertOut])
def api_alerts(
    status: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> list[AlertOut]:
    briefs = _rule_briefs()
    stmt = select(Alert).order_by(Alert.created_at.desc()).limit(limit)
    if status:
        stmt = stmt.where(Alert.status == status)
    return [alert_to_out(a, briefs, db=db) for a in db.scalars(stmt).all()]


@app.get("/api/alerts/{alert_id}", response_model=AlertOut)
def api_get_alert(alert_id: int, db: Session = Depends(get_db)) -> AlertOut:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert_to_out(alert, db=db)


@app.patch("/api/alerts/{alert_id}/status", response_model=AlertOut)
def api_set_alert_status(
    alert_id: int, body: StatusUpdate, db: Session = Depends(get_db)
) -> AlertOut:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    apply_alert_status(alert, body.status)
    db.commit()
    db.refresh(alert)
    return alert_to_out(alert, db=db)


@app.post("/api/alerts/{alert_id}/ack", response_model=AlertOut)
def api_ack_alert(alert_id: int, db: Session = Depends(get_db)) -> AlertOut:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    apply_alert_status(alert, "acked")
    db.commit()
    db.refresh(alert)
    return alert_to_out(alert, db=db)


@app.post("/api/alerts/{alert_id}/comments", response_model=CommentOut)
def api_add_comment(
    alert_id: int, body: CommentCreate, db: Session = Depends(get_db)
) -> CommentOut:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    text = (body.body or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="Comment body is required")
    comment = AlertComment(
        alert_id=alert_id,
        author=(body.author or "analyst").strip() or "analyst",
        body=text,
    )
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return CommentOut.model_validate(comment)


@app.post("/api/rules/run", response_model=list[AlertOut])
def api_run_rules(db: Session = Depends(get_db)) -> list[AlertOut]:
    created = run_rules(db, settings.rules_dir)
    briefs = _rule_briefs()
    return [alert_to_out(a, briefs, db=db) for a in created]
