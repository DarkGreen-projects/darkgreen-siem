from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import json

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
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
from .config import enforce_startup_secrets, get_settings
from .db import SessionLocal, get_db, init_db
from .ingest import ingest_many, ingest_payload, list_sources
from .models import Alert, AlertAudit, AlertComment, Event, Tenant
from .rules_engine import (
    RuleConflictError,
    RuleValidationError,
    delete_rule,
    dry_run_rules,
    event_from_normalized,
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
    escape_like,
)
from .rate_limit import enforce_ingest_rate, enforce_login_rate
from .rule_validate import ALLOWED_SEVERITIES
from .schemas import (
    ALERT_STATUSES,
    AlertOut,
    AlertSearchHit,
    AuditOut,
    CommentCreate,
    CommentOut,
    DryRunRequest,
    DryRunResponse,
    DryRunHit,
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
    SimilarAlertOut,
    SourceHealthOut,
    SourceOut,
    StatsOut,
    StatusUpdate,
    TriageBriefOut,
    CopilotSuggestOut,
    AlertLinksOut,
    MemoryStatsOut,
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
from .sla import alert_matches_sla_filter, compute_alert_sla
from .maintenance import evaluate_silence_alerts, purge_all_tenants, purge_old_events
from .enrich_providers import enrich_multi
from .search import search_events
from .seed import seed_samples
from .stats_helpers import (
    KNOWN_SOURCES,
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
    include_audit: bool = True,
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
    if include_audit and db is not None:
        audit_rows = _load_audit(db, alert.id)
    lab = get_lab_state()
    sla = compute_alert_sla(
        alert,
        ack_map=lab.sla_ack_minutes,
        close_map=lab.sla_close_minutes,
    )
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
        mitre=getattr(alert, "mitre", None) or evidence.get("mitre"),
        created_at=alert.created_at,
        acked_at=alert.acked_at,
        closed_at=getattr(alert, "closed_at", None),
        disposition=getattr(alert, "disposition", None),
        closure_note=getattr(alert, "closure_note", None),
        closed_by=getattr(alert, "closed_by", None),
        risk_score=getattr(alert, "risk_score", None),
        noise_hint=getattr(alert, "noise_hint", None),
        **sla,
    )


def apply_alert_status(
    db: Session,
    alert: Alert,
    status: str,
    *,
    actor: str = "analyst",
    disposition: str | None = None,
    closure_note: str | None = None,
) -> None:
    from .schemas import ALERT_DISPOSITIONS

    status = status.strip().lower()
    if status not in ALERT_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Allowed: {', '.join(sorted(ALERT_STATUSES))}",
        )
    note_text: str | None = None
    if status == "closed":
        disp = (disposition or "").strip().lower()
        if disp not in ALERT_DISPOSITIONS:
            raise HTTPException(
                status_code=400,
                detail=(
                    "disposition required when closing: "
                    + ", ".join(sorted(ALERT_DISPOSITIONS))
                ),
            )
        note = (closure_note or "").strip()
        if len(note) < 10:
            raise HTTPException(
                status_code=400,
                detail="closure_note required when closing (min 10 characters)",
            )
        alert.disposition = disp
        alert.closure_note = note
        alert.closed_by = (actor or "analyst").strip() or "analyst"
        note_text = f"{disp}: {note[:200]}"
    from_status = alert.status or "open"
    if from_status != status:
        db.add(
            AlertAudit(
                tenant_id=getattr(alert, "tenant_id", None) or "lab",
                alert_id=alert.id,
                actor=(actor or "analyst").strip() or "analyst",
                from_status=from_status,
                to_status=status,
                note=note_text,
            )
        )
    alert.status = status
    now = datetime.now(timezone.utc)
    if from_status == "open" and status != "open" and alert.acked_at is None:
        alert.acked_at = now
    if status == "closed" and getattr(alert, "closed_at", None) is None:
        alert.closed_at = now
    if status == "closed":
        try:
            from .rag_memory import upsert_alert_memory

            upsert_alert_memory(db, alert)
        except Exception:
            logger.exception("alert_memory upsert failed for alert %s", alert.id)


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
    enforce_startup_secrets(settings)
    init_db()
    db = SessionLocal()
    try:
        bootstrap_auth(db, settings)
        load_lab_settings_from_db(db)
        try:
            from .rag_memory import backfill_alert_memory

            n_mem = backfill_alert_memory(db, tenant_id=settings.default_tenant_id)
            if n_mem:
                db.commit()
                logger.info("Alert memory backfill: %s rows", n_mem)
        except Exception:
            logger.exception("Alert memory backfill skipped")
            db.rollback()
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


_openapi_kwargs: dict[str, Any] = {}
if getattr(settings, "disable_openapi", False):
    _openapi_kwargs = {"docs_url": None, "redoc_url": None, "openapi_url": None}

app = FastAPI(
    title="DarkGreen SIEM",
    description="Multi-source demo SIEM - ingest, normalize, search, detect",
    version="0.1.0",
    lifespan=lifespan,
    dependencies=[Depends(require_auth)],
    **_openapi_kwargs,
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        path = request.url.path
        if path.startswith("/api/") or path == "/health":
            response.headers.setdefault("Cache-Control", "no-store")
        return response


origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins or ["http://localhost:8080", "http://127.0.0.1:8080"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)
app.add_middleware(SecurityHeadersMiddleware)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "darkgreen-siem"}


@app.post("/api/auth/login", response_model=LoginResponse)
def api_login(
    body: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> LoginResponse:
    enforce_login_rate(request)
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


def _payload_byte_size(payload: Any) -> int:
    if isinstance(payload, bytes):
        return len(payload)
    if isinstance(payload, str):
        return len(payload.encode("utf-8", errors="replace"))
    try:
        return len(json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8"))
    except Exception:
        return len(repr(payload).encode("utf-8", errors="replace"))


@app.post("/api/ingest", response_model=IngestResponse)
def api_ingest(
    body: IngestRequest,
    request: Request,
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("ingest")),
) -> IngestResponse:
    enforce_ingest_rate(request, identity=principal.username or "ingest")
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
        raw_size = _payload_byte_size(payload)
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
    status: str | None = Query(
        None, description="Filter alert hits by status (open|acked|in_progress|closed)"
    ),
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
    status_norm = (status or "").strip().lower() or None
    if status_norm and status_norm not in ALERT_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"status must be one of: {', '.join(sorted(ALERT_STATUSES))}",
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
    for alert, matched in search_alerts_by_text(
        db, q, limit=25, tenant_id=tid, status=status_norm
    ):
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
    from .stats_helpers import build_timeline

    timeline = build_timeline(db, tenant_id=tid, range_key=range_key, now=now)

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
        recent_alerts=[
            alert_to_out(
                a, briefs, db=db, include_comments=False, include_audit=False
            )
            for a in recent
        ],
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
    return [_rule_to_out(rule) for rule in load_rules(settings.rules_dir)]


def _rule_to_out(rule: dict[str, Any]) -> RuleOut:
    brief = (rule.get("threat_brief") or "").strip() or None
    mitre = rule.get("mitre")
    if isinstance(mitre, list):
        mitre = ",".join(str(x) for x in mitre) if mitre else None
    elif mitre is not None:
        mitre = str(mitre).strip() or None
    return RuleOut(
        id=rule.get("id") or "unknown",
        name=rule.get("name") or rule.get("id") or "unnamed",
        description=rule.get("description") or "",
        threat_brief=brief,
        mitre=mitre,
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
    except OSError:
        logger.exception("Failed to write rule")
        raise HTTPException(status_code=500, detail="Failed to write rule") from None
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
    except OSError:
        logger.exception("Failed to write rule")
        raise HTTPException(status_code=500, detail="Failed to write rule") from None
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
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Rule not found") from None
    except OSError:
        logger.exception("Failed to delete rule")
        raise HTTPException(status_code=500, detail="Failed to delete rule") from None
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
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Rule not found") from None
    except RuleValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError:
        logger.exception("Failed to update rule")
        raise HTTPException(status_code=500, detail="Failed to update rule") from None
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
            notify_webhook_url=body.notify_webhook_url,
            notify_format=body.notify_format,
            notify_min_severity=body.notify_min_severity,
            sla_ack_minutes=body.sla_ack_minutes,
            sla_close_minutes=body.sla_close_minutes,
            triage_scoring_enabled=body.triage_scoring_enabled,
            triage_prior_days=body.triage_prior_days,
            rag_enabled=body.rag_enabled,
            rag_top_k=body.rag_top_k,
            llm_enabled=body.llm_enabled,
            llm_api_url=body.llm_api_url,
            llm_api_key=body.llm_api_key,
            llm_model=body.llm_model,
            graph_enabled=body.graph_enabled,
            graph_window_minutes=body.graph_window_minutes,
            graph_min_history=body.graph_min_history,
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
    mitre: str | None = Query(None, max_length=64),
    sla: str | None = Query(None, max_length=16),
    disposition: str | None = Query(None, max_length=32),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("search")),
) -> list[AlertOut]:
    from .schemas import ALERT_DISPOSITIONS

    if status and status not in ALERT_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"status must be one of: {', '.join(sorted(ALERT_STATUSES))}",
        )
    sla_wanted = (sla or "").strip().lower() or None
    if sla_wanted and sla_wanted not in {"breached", "at_risk", "met", "ok", "na"}:
        raise HTTPException(
            status_code=400,
            detail="sla must be one of: breached, at_risk, met, ok, na",
        )
    disp = (disposition or "").strip().lower() or None
    if disp and disp not in ALERT_DISPOSITIONS:
        raise HTTPException(
            status_code=400,
            detail=f"disposition must be one of: {', '.join(sorted(ALERT_DISPOSITIONS))}",
        )
    briefs = _rule_briefs()
    fetch_limit = min(200, limit * 4) if sla_wanted else limit
    stmt = (
        select(Alert)
        .where(Alert.tenant_id == principal.tenant_id)
        .order_by(Alert.created_at.desc())
        .limit(fetch_limit)
    )
    if status:
        stmt = stmt.where(Alert.status == status)
    if mitre and mitre.strip():
        safe_mitre = escape_like(mitre.strip())
        stmt = stmt.where(Alert.mitre.ilike(f"%{safe_mitre}%", escape="\\"))
    if disp:
        stmt = stmt.where(Alert.disposition == disp)
    out = [
        alert_to_out(a, briefs, db=db, include_comments=False, include_audit=False)
        for a in db.scalars(stmt).all()
    ]
    if sla_wanted:
        out = [
            a
            for a in out
            if alert_matches_sla_filter(
                {
                    "sla_ack_status": a.sla_ack_status,
                    "sla_close_status": a.sla_close_status,
                },
                sla_wanted,
            )
        ][:limit]
    return out


@app.get("/api/alerts/queue", response_model=list[AlertOut])
def api_alerts_queue(
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("search")),
) -> list[AlertOut]:
    from .triage_brief import queue_sort_key

    briefs = _rule_briefs()
    stmt = (
        select(Alert)
        .where(
            and_(
                Alert.tenant_id == principal.tenant_id,
                Alert.status.in_(["open", "in_progress"]),
            )
        )
        .order_by(Alert.created_at.asc())
        .limit(min(200, limit * 3))
    )
    outs = [
        alert_to_out(a, briefs, db=db, include_comments=False, include_audit=False)
        for a in db.scalars(stmt).all()
    ]
    outs.sort(key=queue_sort_key)
    return outs[:limit]


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


@app.get("/api/alerts/{alert_id}/similar", response_model=list[SimilarAlertOut])
def api_alert_similar(
    alert_id: int,
    days: int = Query(30, ge=1, le=365),
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("search")),
) -> list[SimilarAlertOut]:
    from .triage_score import find_similar_alerts

    alert = db.get(Alert, alert_id)
    if not alert or alert.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="Alert not found")
    rows = find_similar_alerts(db, alert, days=days, limit=limit)
    return [
        SimilarAlertOut(
            id=r.id,
            rule_id=r.rule_id,
            title=r.title,
            severity=r.severity,
            status=r.status,
            disposition=getattr(r, "disposition", None),
            created_at=r.created_at,
            closed_at=getattr(r, "closed_at", None),
            noise_hint=getattr(r, "noise_hint", None),
            risk_score=getattr(r, "risk_score", None),
        )
        for r in rows
    ]


@app.get("/api/alerts/{alert_id}/brief", response_model=TriageBriefOut)
def api_alert_brief(
    alert_id: int,
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("search")),
) -> TriageBriefOut:
    from .triage_brief import build_alert_brief

    alert = db.get(Alert, alert_id)
    if not alert or alert.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="Alert not found")
    lab = get_lab_state()
    data = build_alert_brief(
        alert,
        db=db,
        ack_map=lab.sla_ack_minutes,
        close_map=lab.sla_close_minutes,
        prior_days=int(lab.triage_prior_days or 30),
    )
    return TriageBriefOut(**data)


@app.get("/api/alerts/{alert_id}/links", response_model=AlertLinksOut)
def api_alert_links(
    alert_id: int,
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("search")),
) -> AlertLinksOut:
    from .alert_graph import links_payload

    alert = db.get(Alert, alert_id)
    if not alert or alert.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="Alert not found")
    return AlertLinksOut(**links_payload(db, alert))


@app.post("/api/alerts/{alert_id}/copilot-suggest", response_model=CopilotSuggestOut)
def api_alert_copilot_suggest(
    alert_id: int,
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("alerts_write")),
) -> CopilotSuggestOut:
    from .copilot import suggest_closure
    from .triage_brief import build_alert_brief

    alert = db.get(Alert, alert_id)
    if not alert or alert.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="Alert not found")
    lab = get_lab_state()
    brief = build_alert_brief(
        alert,
        db=db,
        ack_map=lab.sla_ack_minutes,
        close_map=lab.sla_close_minutes,
        prior_days=int(lab.triage_prior_days or 30),
    )
    suggestion = suggest_closure(brief)
    return CopilotSuggestOut(**suggestion, brief=TriageBriefOut(**brief))


@app.get("/api/memory/stats", response_model=MemoryStatsOut)
def api_memory_stats(
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("search")),
) -> MemoryStatsOut:
    from .rag_memory import memory_stats

    lab = get_lab_state()
    stats = memory_stats(db, tenant_id=principal.tenant_id)
    return MemoryStatsOut(
        **stats,
        rag_enabled=bool(getattr(lab, "rag_enabled", True)),
        rag_top_k=int(getattr(lab, "rag_top_k", 5) or 5),
    )


@app.get("/api/memory/export")
def api_memory_export(
    limit: int = Query(500, ge=1, le=2000),
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("setup")),
) -> dict[str, Any]:
    from .rag_memory import export_memory

    return export_memory(db, tenant_id=principal.tenant_id, limit=limit)


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
    apply_alert_status(
        db,
        alert,
        body.status,
        actor=principal.username,
        disposition=body.disposition,
        closure_note=body.closure_note,
    )
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
        author=(principal.username or "analyst").strip() or "analyst",
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


@app.post("/api/rules/dry-run", response_model=DryRunResponse)
def api_rules_dry_run(
    body: DryRunRequest,
    db: Session = Depends(get_db),
    principal: AuthPrincipal = Depends(require_perm("rules_write")),
) -> DryRunResponse:
    if not body.events:
        raise HTTPException(status_code=400, detail="events required")
    try:
        hits, n_norm = dry_run_rules(
            db,
            settings.rules_dir,
            body.events,
            rule_ids=body.rule_ids,
            tenant_id=principal.tenant_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return DryRunResponse(
        matched=[
            DryRunHit(
                rule_id=h.get("rule_id") or "",
                rule_name=h.get("rule_name") or "",
                would_create=bool(h.get("would_create")),
                evidence=h.get("evidence") or {},
                mitre=h.get("mitre"),
                severity=h.get("severity") or "medium",
                title=h.get("title") or "",
            )
            for h in hits
        ],
        events_normalized=n_norm,
    )


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _zip_tool_dir(subdir: str, zip_name: str) -> Response:
    import io
    import zipfile

    root = _repo_root() / "tools" / subdir
    if not root.is_dir():
        raise HTTPException(status_code=404, detail=f"tool pack not found: {subdir}")
    buf = io.BytesIO()
    skip_parts = {"generated", "bin", "obj", ".git"}
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in root.rglob("*"):
            if not path.is_file() or path.name == ".agent-last.json":
                continue
            if any(p in skip_parts for p in path.parts):
                continue
            if path.name == ".gitkeep":
                continue
            zf.write(path, arcname=str(path.relative_to(root.parent)))
    data = buf.getvalue()
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{zip_name}"'},
    )


@app.get("/api/tools/connect-installer.zip")
def api_download_connect_installer(
    principal: AuthPrincipal = Depends(require_perm("search")),
) -> Response:
    return _zip_tool_dir("connect-installer", "darkgreen-connect-installer.zip")


@app.get("/api/tools/connect-wizard.zip")
def api_download_connect_wizard(
    principal: AuthPrincipal = Depends(require_perm("search")),
) -> Response:
    # Alias legacy → installer pack
    return _zip_tool_dir("connect-installer", "darkgreen-connect-installer.zip")


@app.get("/api/tools/windows-agent.zip")
def api_download_windows_agent(
    principal: AuthPrincipal = Depends(require_perm("search")),
) -> Response:
    return _zip_tool_dir("windows-agent", "darkgreen-windows-agent.zip")
