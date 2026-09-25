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

from .auth import (
    AuthPrincipal,
    LoginRequest,
    LoginResponse,
    MeResponse,
    authenticate_user,
    bootstrap_auth,
    issue_user_token,
    require_auth,
    require_perm,
)
from .config import get_settings
from .db import SessionLocal, get_db, init_db
from .ingest import ingest_many, ingest_payload, list_sources
from .models import Alert, AlertAudit, AlertComment, Event, Tenant
from .rules_engine import (
    RuleConflictError,
    RuleValidationError,
    delete_rule,
    load_rules,
    run_rules,
    save_rule,
    set_rule_enabled,
    validate_rule_id,
)
from .input_limits import (
    ALLOWED_SOURCE_TYPES,
    MAX_INGEST_BATCH,
    MAX_RAW_BYTES,
    MAX_SEARCH_Q,
)
from .rule_validate import ALLOWED_SEVERITIES
from .schemas import (
    ALERT_STATUSES,
    AlertOut,
    AlertSearchHit,
    AuditOut,
    CommentCreate,
    CommentOut,
    EventOut,
    IngestRequest,
    IngestResponse,
    PurgeResult,
    RuleCreate,
    RuleEnabledUpdate,
    RuleOut,
    SearchResponse,
    SetupOut,
    SetupUpdate,
    SourceHealthOut,
    SourceOut,
    StatsOut,
    StatusUpdate,
    MultiEnrichOut,
    VtEnrichOut,
)
from .alert_export import alerts_to_csv
from .alert_search import search_alerts_by_text
from .lab_settings import (
    enrichment_keys_public,
    get_lab_state,
    load_lab_settings_from_db,
    update_lab_state,
)
from .maintenance import evaluate_silence_alerts, purge_all_tenants, purge_old_events
from .enrich_providers import enrich_multi
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
from .syslog_detect import detect_syslog_source
from .syslog_server import start_syslog_server
from .vt_enrich import enrich_vt


def _configure_logging() -> None:
    import gzip
    import os
    from logging.handlers import RotatingFileHandler

    root = logging.getLogger()
    if getattr(root, "_dg_configured", False):
        return
    root.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    if not any(isinstance(h, logging.StreamHandler) for h in root.handlers):
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        root.addHandler(sh)

    log_dir = os.environ.get("LOG_DIR", "logs")
    try:
        os.makedirs(log_dir, exist_ok=True)
        path = os.path.join(log_dir, "api.log")

        def _namer(name: str) -> str:
            return name + ".gz"

        def _rotator(source: str, dest: str) -> None:
            with open(source, "rb") as sf, gzip.open(dest, "wb") as df:
                df.writelines(sf)
            os.remove(source)

        fh = RotatingFileHandler(path, maxBytes=2_000_000, backupCount=5, encoding="utf-8")
        fh.rotator = _rotator  # type: ignore[method-assign]
        fh.namer = _namer  # type: ignore[method-assign]
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except OSError:
        pass
    root._dg_configured = True  # type: ignore[attr-defined]


_configure_logging()
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


def _load_audit(db: Session, alert_id: int, *, limit: int = 20) -> list[AlertAudit]:
    return list(
        db.scalars(
            select(AlertAudit)
            .where(AlertAudit.alert_id == alert_id)
            .order_by(AlertAudit.created_at.desc())
            .limit(limit)
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
    audit_rows: list[AlertAudit] = []
    if db is not None:
        audit_rows = _load_audit(db, alert.id)
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
        audit=[AuditOut.model_validate(a) for a in audit_rows],
        created_at=alert.created_at,
        acked_at=alert.acked_at,
    )


def apply_alert_status(
    db: Session,
    alert: Alert,
    status: str,
    *,
    actor: str = "analyst",
) -> None:
    status = status.strip().lower()
    if status not in ALERT_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Allowed: {', '.join(sorted(ALERT_STATUSES))}",
        )
    from_status = alert.status or "open"
    if from_status != status:
        db.add(
            AlertAudit(
                tenant_id=getattr(alert, "tenant_id", None) or "lab",
                alert_id=alert.id,
                actor=(actor or "analyst").strip() or "analyst",
                from_status=from_status,
                to_status=status,
            )
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
        source_type = detect_syslog_source(text)
        ingest_payload(
            db,
            text,
            source_type=source_type,
            ingest_channel="syslog",
            tenant_id=settings.default_tenant_id,
        )
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
            load_lab_settings_from_db(db)
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


async def _maintenance_loop(stop: asyncio.Event) -> None:
    while not stop.is_set():
        db = SessionLocal()
        try:
            load_lab_settings_from_db(db)
            purge_all_tenants(db)
            evaluate_silence_alerts(db)
        except Exception:
            logger.exception("Maintenance loop error")
            db.rollback()
        finally:
            db.close()
        interval = get_lab_state().purge_interval_sec
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    db = SessionLocal()
    try:
        bootstrap_auth(db, settings)
        load_lab_settings_from_db(db)
        if settings.seed_on_start:
            seed_samples(db, settings.samples_dir)
            if settings.run_background_jobs:
                run_rules(db, settings.rules_dir)
    finally:
        db.close()

    stop = asyncio.Event()
    transport = await start_syslog_server(
        settings.syslog_host, settings.syslog_port, _handle_syslog
    )
    rules_task = None
    maintenance_task = None
    if settings.run_background_jobs:
        rules_task = asyncio.create_task(_rules_loop(stop))
        maintenance_task = asyncio.create_task(_maintenance_loop(stop))
    logger.info(
        "DarkGreen SIEM API ready (background_jobs=%s)",
        settings.run_background_jobs,
    )
    try:
        yield
    finally:
        stop.set()
        if rules_task:
            rules_task.cancel()
        if maintenance_task:
            maintenance_task.cancel()
        transport.close()


app = FastAPI(
    title="DarkGreen SIEM",
    description="Multi-source demo SIEM — ingest, normalize, search, detect",
    version="0.1.0",
    lifespan=lifespan,
    dependencies=[Depends(require_auth)],
)

origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins or ["http://localhost:8080", "http://127.0.0.1:8080"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "darkgreen-siem"}


@app.post("/api/auth/login", response_model=LoginResponse)
def api_login(body: LoginRequest, db: Session = Depends(get_db)) -> LoginResponse:
    username = body.username.strip()
    if not settings.auth_enabled:
        token, exp = issue_user_token(
            settings,
            username or "anonymous",
            role="admin",
            tenant_id=settings.default_tenant_id,
        )
        return LoginResponse(
            token=token,
            expires_at=exp,
            username=username or "anonymous",
            role="admin",
            tenant_id=settings.default_tenant_id,
        )
    user = authenticate_user(db, settings, username, body.password)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token, exp = issue_user_token(
        settings, user.username, role=user.role, tenant_id=user.tenant_id
    )
    return LoginResponse(
        token=token,
        expires_at=exp,
        username=user.username,
        role=user.role,
        tenant_id=user.tenant_id,
    )


@app.get("/api/auth/me", response_model=MeResponse)
def api_me(
    principal: AuthPrincipal = Depends(require_auth),
    db: Session = Depends(get_db),
) -> MeResponse:
    tname = None
    if principal.tenant_id:
        t = db.get(Tenant, principal.tenant_id)
        tname = t.name if t else principal.tenant_id
    return MeResponse(
        username=principal.username,
        kind=principal.kind,
        role=principal.role,
        tenant_id=principal.tenant_id,
        tenant_name=tname,
    )


@app.post("/api/ingest", response_model=IngestResponse)
def api_ingest(
    body: IngestRequest,
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("ingest")),
) -> IngestResponse:
    items: list[tuple[Any, str | None, str]] = []
    for ev in body.events:
        items.append((ev.payload, ev.source_type, ev.ingest_channel or "http"))
    if body.raw is not None:
        items.append((body.raw, body.source_type, body.ingest_channel or "http"))
    if not items:
        raise HTTPException(status_code=400, detail="No events provided")
    if len(items) > MAX_INGEST_BATCH:
        raise HTTPException(
            status_code=400, detail=f"Too many events (max {MAX_INGEST_BATCH})"
        )
    for payload, _, _ in items:
        raw_size = len(payload) if isinstance(payload, (str, bytes)) else len(str(payload))
        if raw_size > MAX_RAW_BYTES:
            raise HTTPException(
                status_code=400, detail=f"Event payload too large (max {MAX_RAW_BYTES} bytes)"
            )
    ids = ingest_many(db, items, tenant_id=principal.tenant_id)
    return IngestResponse(inserted=len(ids), ids=ids)


@app.get("/api/events/search", response_model=SearchResponse)
def api_search(
    q: str = Query("", max_length=MAX_SEARCH_Q, description="field:value AND free-text"),
    source_type: str | None = None,
    severity: str | None = None,
    since_minutes: int | None = Query(None, ge=1, le=10080),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("search")),
) -> SearchResponse:
    if source_type and source_type not in ALLOWED_SOURCE_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"source_type must be one of: {', '.join(sorted(ALLOWED_SOURCE_TYPES))}",
        )
    if severity and severity.lower() not in ALLOWED_SEVERITIES:
        raise HTTPException(
            status_code=400,
            detail=f"severity must be one of: {', '.join(sorted(ALLOWED_SEVERITIES))}",
        )
    briefs = _rule_briefs()
    tid = principal.tenant_id
    total, events = search_events(
        db,
        q,
        source_type=source_type,
        severity=severity,
        since_minutes=since_minutes,
        limit=limit,
        offset=offset,
        tenant_id=tid,
    )
    alert_hits: list[AlertSearchHit] = []
    for alert, matched in search_alerts_by_text(db, q, limit=25, tenant_id=tid):
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
def api_event(
    event_id: int,
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("search")),
) -> EventOut:
    event = db.get(Event, event_id)
    if not event or event.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="Event not found")
    return EventOut.model_validate(event)


@app.get("/api/stats", response_model=StatsOut)
def api_stats(
    range: str = Query("1h", description="1h | 1d | 7d | 30d | 1y"),
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("search")),
) -> StatsOut:
    range_key = normalize_range(range)
    briefs = _rule_briefs()
    tid = principal.tenant_id
    te = Event.tenant_id == tid
    ta = Alert.tenant_id == tid

    total_events = db.scalar(select(func.count()).select_from(Event).where(te)) or 0
    total_alerts = db.scalar(select(func.count()).select_from(Alert).where(ta)) or 0
    open_alerts = (
        db.scalar(
            select(func.count())
            .select_from(Alert)
            .where(and_(ta, Alert.status == "open"))
        )
        or 0
    )

    since = datetime.now(timezone.utc) - timedelta(minutes=1)
    last_min = (
        db.scalar(
            select(func.count())
            .select_from(Event)
            .where(and_(te, Event.timestamp >= since))
        )
        or 0
    )
    eps = float(last_min) / 60.0

    by_source = {
        str(k): int(v)
        for k, v in db.execute(
            select(Event.source_type, func.count()).where(te).group_by(Event.source_type)
        ).all()
    }
    by_sev = {
        str(k): int(v)
        for k, v in db.execute(
            select(Event.severity, func.count()).where(te).group_by(Event.severity)
        ).all()
    }
    by_channel = {
        str(k): int(v)
        for k, v in db.execute(
            select(Event.ingest_channel, func.count())
            .where(te)
            .group_by(Event.ingest_channel)
        ).all()
    }
    by_alert_status = {
        str(k): int(v)
        for k, v in db.execute(
            select(Alert.status, func.count()).where(ta).group_by(Alert.status)
        ).all()
    }
    for st in ALERT_STATUSES:
        by_alert_status.setdefault(st, 0)

    now = datetime.now(timezone.utc)
    timeline: list[dict[str, Any]] = []
    for start, end in build_bucket_bounds(range_key, now):
        rows = db.execute(
            select(Event.source_type, func.count())
            .where(and_(te, Event.timestamp >= start, Event.timestamp < end))
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
            select(Event.source_type, func.max(Event.timestamp))
            .where(te)
            .group_by(Event.source_type)
        ).all()
    }
    known = list(KNOWN_SOURCES)
    for extra in by_source:
        if extra not in known:
            known.append(extra)

    source_health: list[SourceHealthOut] = []
    lab = get_lab_state()
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
                status=health_status(
                    silent,
                    stale_minutes=lab.health_stale_minutes,
                    silent_minutes=lab.health_silent_minutes,
                ),
            )
        )

    recent = list(
        db.scalars(
            select(Alert)
            .where(ta)
            .order_by(Alert.created_at.desc())
            .limit(8)
        ).all()
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
        by_alert_status=by_alert_status,
        timeline=timeline,
        source_health=source_health,
        recent_alerts=[alert_to_out(a, briefs, db=db) for a in recent],
    )


@app.get("/api/sources", response_model=list[SourceOut])
def api_sources(
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("search")),
) -> list[SourceOut]:
    return [
        SourceOut(channel=s.channel, count=int(s.count or 0), last_event_at=s.last_event_at)
        for s in list_sources(db, tenant_id=principal.tenant_id)
    ]


@app.get("/api/rules", response_model=list[RuleOut])
def api_rules(principal: AuthPrincipal = Depends(require_perm("search"))) -> list[RuleOut]:
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
def api_create_rule(
    body: RuleCreate,
    principal: AuthPrincipal = Depends(require_perm("rules_write")),
) -> RuleOut:
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
def api_update_rule(
    rule_id: str,
    body: RuleCreate,
    principal: AuthPrincipal = Depends(require_perm("rules_write")),
) -> RuleOut:
    try:
        rid = validate_rule_id(rule_id)
    except RuleValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    payload = body.model_dump()
    payload.pop("overwrite", None)
    if payload.get("id", "").strip().lower() != rid:
        raise HTTPException(status_code=400, detail="Path id must match body id")
    try:
        saved = save_rule(settings.rules_dir, payload, overwrite=True)
    except RuleValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to write rule: {exc}") from exc
    return _rule_to_out(saved)


@app.delete("/api/rules/{rule_id}", status_code=204)
def api_delete_rule(
    rule_id: str,
    principal: AuthPrincipal = Depends(require_perm("rules_write")),
) -> Response:
    try:
        rid = validate_rule_id(rule_id)
    except RuleValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        delete_rule(settings.rules_dir, rid)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to delete rule: {exc}") from exc
    return Response(status_code=204)


@app.patch("/api/rules/{rule_id}/enabled", response_model=RuleOut)
def api_set_rule_enabled(
    rule_id: str,
    body: RuleEnabledUpdate,
    principal: AuthPrincipal = Depends(require_perm("rules_write")),
) -> RuleOut:
    try:
        rid = validate_rule_id(rule_id)
    except RuleValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        saved = set_rule_enabled(settings.rules_dir, rid, body.enabled)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuleValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to update rule: {exc}") from exc
    return _rule_to_out(saved)


@app.get("/api/setup", response_model=SetupOut)
def api_get_setup(
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("setup")),
) -> SetupOut:
    load_lab_settings_from_db(db)
    s = get_lab_state()
    keys = enrichment_keys_public(s)
    return SetupOut(
        retention_days=s.retention_days,
        health_stale_minutes=s.health_stale_minutes,
        health_silent_minutes=s.health_silent_minutes,
        silence_alerts_enabled=s.silence_alerts_enabled,
        purge_interval_sec=s.purge_interval_sec,
        last_purge_at=s.last_purge_at,
        last_purge_deleted=s.last_purge_deleted,
        **keys,
    )


@app.patch("/api/setup", response_model=SetupOut)
def api_patch_setup(
    body: SetupUpdate,
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("setup")),
) -> SetupOut:
    try:
        update_lab_state(
            retention_days=body.retention_days,
            health_stale_minutes=body.health_stale_minutes,
            health_silent_minutes=body.health_silent_minutes,
            silence_alerts_enabled=body.silence_alerts_enabled,
            vt_api_key=body.vt_api_key,
            abuseipdb_api_key=body.abuseipdb_api_key,
            otx_api_key=body.otx_api_key,
            db=db,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return api_get_setup(db=db, principal=principal)


@app.post("/api/admin/purge", response_model=PurgeResult)
def api_purge(
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("purge")),
) -> PurgeResult:
    load_lab_settings_from_db(db)
    result = purge_old_events(db, tenant_id=principal.tenant_id)
    return PurgeResult(
        deleted=int(result["deleted"]),
        cutoff=result.get("cutoff"),
        skipped=bool(result.get("skipped")),
    )


@app.get("/api/alerts", response_model=list[AlertOut])
def api_alerts(
    status: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("search")),
) -> list[AlertOut]:
    if status and status not in ALERT_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"status must be one of: {', '.join(sorted(ALERT_STATUSES))}",
        )
    briefs = _rule_briefs()
    stmt = (
        select(Alert)
        .where(Alert.tenant_id == principal.tenant_id)
        .order_by(Alert.created_at.desc())
        .limit(limit)
    )
    if status:
        stmt = stmt.where(Alert.status == status)
    return [alert_to_out(a, briefs, db=db) for a in db.scalars(stmt).all()]


@app.get("/api/alerts/export.csv")
def api_alerts_export_csv(
    status: str | None = None,
    limit: int = Query(500, ge=1, le=500),
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("search")),
) -> Response:
    if status and status not in ALERT_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"status must be one of: {', '.join(sorted(ALERT_STATUSES))}",
        )
    stmt = (
        select(Alert)
        .where(Alert.tenant_id == principal.tenant_id)
        .order_by(Alert.created_at.desc())
        .limit(limit)
    )
    if status:
        stmt = stmt.where(Alert.status == status)
    alerts = list(db.scalars(stmt).all())
    csv_body = alerts_to_csv(alerts)
    filename = f"darkgreen-alerts{('-' + status) if status else ''}.csv"
    return Response(
        content=csv_body,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/alerts/{alert_id}", response_model=AlertOut)
def api_get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("search")),
) -> AlertOut:
    alert = db.get(Alert, alert_id)
    if not alert or alert.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert_to_out(alert, db=db)


@app.get("/api/enrich/vt", response_model=VtEnrichOut)
def api_enrich_vt(
    type: str = Query(..., description="ip | domain | url"),
    value: str = Query(..., min_length=1, max_length=512),
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("enrich")),
) -> VtEnrichOut:
    result = enrich_vt(
        db, settings, ioc_type=type, value=value, tenant_id=principal.tenant_id
    )
    return VtEnrichOut(**result)


@app.get("/api/enrich", response_model=MultiEnrichOut)
def api_enrich_multi(
    type: str = Query(..., description="ip | domain | url"),
    value: str = Query(..., min_length=1, max_length=512),
    providers: str = Query("vt,abuseipdb,otx"),
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("enrich")),
) -> MultiEnrichOut:
    plist = [p.strip() for p in providers.split(",") if p.strip()]
    load_lab_settings_from_db(db)
    result = enrich_multi(
        db, ioc_type=type, value=value, providers=plist, tenant_id=principal.tenant_id
    )
    return MultiEnrichOut(**result)


@app.patch("/api/alerts/{alert_id}/status", response_model=AlertOut)
def api_set_alert_status(
    alert_id: int,
    body: StatusUpdate,
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("alerts_write")),
) -> AlertOut:
    alert = db.get(Alert, alert_id)
    if not alert or alert.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="Alert not found")
    apply_alert_status(db, alert, body.status, actor=principal.username)
    db.commit()
    db.refresh(alert)
    return alert_to_out(alert, db=db)


@app.post("/api/alerts/{alert_id}/ack", response_model=AlertOut)
def api_ack_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("alerts_write")),
) -> AlertOut:
    alert = db.get(Alert, alert_id)
    if not alert or alert.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="Alert not found")
    apply_alert_status(db, alert, "acked", actor=principal.username)
    db.commit()
    db.refresh(alert)
    return alert_to_out(alert, db=db)


@app.post("/api/alerts/{alert_id}/comments", response_model=CommentOut)
def api_add_comment(
    alert_id: int,
    body: CommentCreate,
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("alerts_write")),
) -> CommentOut:
    alert = db.get(Alert, alert_id)
    if not alert or alert.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="Alert not found")
    text = (body.body or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="Comment body is required")
    comment = AlertComment(
        tenant_id=alert.tenant_id,
        alert_id=alert_id,
        author=(body.author or principal.username or "analyst").strip() or "analyst",
        body=text,
    )
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return CommentOut.model_validate(comment)


@app.post("/api/rules/run", response_model=list[AlertOut])
def api_run_rules(
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("rules_write")),
) -> list[AlertOut]:
    created = run_rules(db, settings.rules_dir)
    briefs = _rule_briefs()
    return [
        alert_to_out(a, briefs, db=db)
        for a in created
        if a.tenant_id == principal.tenant_id
    ]
