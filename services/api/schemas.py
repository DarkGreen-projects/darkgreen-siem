from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from .input_limits import (
    ALLOWED_INGEST_CHANNELS,
    ALLOWED_SOURCE_TYPES,
    MAX_COMMENT_AUTHOR,
    MAX_COMMENT_BODY,
    MAX_INGEST_BATCH,
    MAX_RULE_NAME,
    MAX_RULE_TEXT,
    MAX_THRESHOLD,
    MAX_WINDOW_MINUTES,
)
from .rule_validate import ALLOWED_SEVERITIES, ALLOWED_TYPES

AUTHOR_RE = re.compile(r"^[\w .@-]{1,64}$")

AlertStatusLiteral = Literal["open", "acked", "in_progress", "closed"]
AlertDispositionLiteral = Literal[
    "true_positive",
    "false_positive",
    "benign",
    "duplicate",
    "tuning_needed",
]
ALERT_DISPOSITIONS = frozenset(
    {"true_positive", "false_positive", "benign", "duplicate", "tuning_needed"}
)


class IngestItem(BaseModel):
    source_type: str | None = None
    payload: Any
    ingest_channel: str = "http"

    @field_validator("ingest_channel")
    @classmethod
    def channel_ok(cls, v: str) -> str:
        ch = (v or "http").strip().lower()
        if ch not in ALLOWED_INGEST_CHANNELS:
            raise ValueError(f"ingest_channel must be one of: {', '.join(sorted(ALLOWED_INGEST_CHANNELS))}")
        return ch

    @field_validator("source_type")
    @classmethod
    def source_ok(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        st = v.strip().lower()
        if st not in ALLOWED_SOURCE_TYPES:
            raise ValueError(f"source_type must be one of: {', '.join(sorted(ALLOWED_SOURCE_TYPES))}")
        return st


class IngestRequest(BaseModel):
    events: list[IngestItem] = Field(default_factory=list, max_length=MAX_INGEST_BATCH)
    raw: Any | None = None
    source_type: str | None = None
    ingest_channel: str = "http"

    @field_validator("ingest_channel")
    @classmethod
    def channel_ok(cls, v: str) -> str:
        ch = (v or "http").strip().lower()
        if ch not in ALLOWED_INGEST_CHANNELS:
            raise ValueError(f"ingest_channel must be one of: {', '.join(sorted(ALLOWED_INGEST_CHANNELS))}")
        return ch

    @field_validator("source_type")
    @classmethod
    def source_ok(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        st = v.strip().lower()
        if st not in ALLOWED_SOURCE_TYPES:
            raise ValueError(f"source_type must be one of: {', '.join(sorted(ALLOWED_SOURCE_TYPES))}")
        return st


class IngestResponse(BaseModel):
    inserted: int
    ids: list[int]


class EventOut(BaseModel):
    id: int
    timestamp: datetime
    source_type: str
    vendor: str | None = None
    device: str | None = None
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    action: str | None = None
    severity: str
    message: str
    raw: str
    labels: dict[str, Any] = Field(default_factory=dict)
    ingest_channel: str
    event_id: str | None = None
    channel: str | None = None
    provider: str | None = None

    class Config:
        from_attributes = True

    @field_validator("raw", mode="before")
    @classmethod
    def _decompress_raw(cls, v: Any) -> str:
        from .raw_compress import decompress_raw

        return decompress_raw(str(v) if v is not None else "")


class SearchResponse(BaseModel):
    total: int
    events: list[EventOut]
    alerts: list["AlertSearchHit"] = Field(default_factory=list)


class CommentOut(BaseModel):
    id: int
    alert_id: int
    author: str
    body: str
    created_at: datetime

    class Config:
        from_attributes = True


class CommentCreate(BaseModel):
    body: str = Field(min_length=1, max_length=MAX_COMMENT_BODY)
    author: str = Field(default="analyst", max_length=MAX_COMMENT_AUTHOR)

    @field_validator("body")
    @classmethod
    def strip_body(cls, v: str) -> str:
        body = v.strip()
        if not body:
            raise ValueError("body is required")
        # Soft-strip HTML tags for stored comments
        return re.sub(r"<[^>]+>", "", body)

    @field_validator("author")
    @classmethod
    def author_ok(cls, v: str) -> str:
        author = (v or "analyst").strip() or "analyst"
        if not AUTHOR_RE.match(author):
            raise ValueError("author contains invalid characters")
        return author


class StatusUpdate(BaseModel):
    status: AlertStatusLiteral
    disposition: AlertDispositionLiteral | None = None
    closure_note: str | None = Field(default=None, max_length=4000)


ALERT_STATUSES = frozenset({"open", "acked", "in_progress", "closed"})


class AlertOut(BaseModel):
    id: int
    rule_id: str
    rule_name: str
    severity: str
    title: str
    description: str
    status: str
    mitre: str | None = None
    evidence: dict[str, Any]
    threat_brief: str | None = None
    comments: list[CommentOut] = Field(default_factory=list)
    audit: list["AuditOut"] = Field(default_factory=list)
    created_at: datetime
    acked_at: datetime | None = None
    closed_at: datetime | None = None
    disposition: str | None = None
    closure_note: str | None = None
    closed_by: str | None = None
    risk_score: int | None = None
    noise_hint: str | None = None
    cluster_size: int | None = None
    campaign_id: int | None = None
    fingerprint_hash: str | None = None
    sla_ack_status: str | None = None
    sla_ack_target_minutes: int | None = None
    sla_ack_due_at: datetime | None = None
    sla_ack_elapsed_minutes: int | None = None
    sla_ack_remaining_minutes: int | None = None
    sla_close_status: str | None = None
    sla_close_target_minutes: int | None = None
    sla_close_due_at: datetime | None = None
    sla_close_elapsed_minutes: int | None = None
    sla_close_remaining_minutes: int | None = None

    class Config:
        from_attributes = True


class AuditOut(BaseModel):
    id: int
    alert_id: int
    actor: str
    from_status: str
    to_status: str
    note: str | None = None
    created_at: datetime

    class Config:
        from_attributes = True


class SimilarAlertOut(BaseModel):
    id: int
    rule_id: str
    title: str
    severity: str
    status: str
    disposition: str | None = None
    created_at: datetime
    closed_at: datetime | None = None
    noise_hint: str | None = None
    risk_score: int | None = None


class MemoryCaseOut(BaseModel):
    alert_id: int
    rule_id: str = ""
    title: str = ""
    disposition: str | None = None
    note_excerpt: str = ""
    entity_key: str | None = None
    mitre: str | None = None
    score: float = 0.0
    closed_at: str | None = None


class ConnectedAlertOut(BaseModel):
    id: int
    title: str = ""
    rule_id: str | None = None
    severity: str | None = None
    status: str | None = None
    disposition: str | None = None
    mitre: str | None = None
    relation: str
    score: int = 0
    direction: str = "out"
    shared_keys: list[str] = Field(default_factory=list)


class AlertLinksOut(BaseModel):
    alert_id: int
    connected: list[ConnectedAlertOut] = Field(default_factory=list)
    count: int = 0


class TriageBriefOut(BaseModel):
    alert_id: int
    summary: str
    entities: dict[str, Any] = Field(default_factory=dict)
    pivot_query: str | None = None
    similar_count: int = 0
    similar_fp: int = 0
    similar_tp: int = 0
    sla: dict[str, Any] = Field(default_factory=dict)
    noise_hint: str | None = None
    risk_score: int | None = None
    mitre: str | None = None
    threat_brief: str | None = None
    playbook: str | None = None
    asset_context: dict[str, Any] | None = None
    cases: list[MemoryCaseOut] = Field(default_factory=list)
    connected: list[ConnectedAlertOut] = Field(default_factory=list)
    fingerprint: dict[str, Any] = Field(default_factory=dict)


class CopilotSuggestOut(BaseModel):
    available: bool = False
    suggested_disposition: str | None = None
    suggested_note: str | None = None
    rationale: str | None = None
    message: str | None = None
    source: str | None = None
    citations: list[int] = Field(default_factory=list)
    cases: list[MemoryCaseOut] = Field(default_factory=list)
    related_alert_ids: list[int] = Field(default_factory=list)
    relation_hint: str | None = None
    brief: TriageBriefOut | None = None
    priority: str | None = None
    noise_action: str | None = None
    llm_skipped: str | None = None
    llm_redacted: bool | None = None


class MemoryStatsOut(BaseModel):
    tenant_id: str
    total: int = 0
    by_disposition: dict[str, int] = Field(default_factory=dict)
    last_closed_at: str | None = None
    rag_enabled: bool = True
    rag_top_k: int = 5
    llm_called: int = 0
    llm_skipped: int = 0


class CopilotFeedbackIn(BaseModel):
    useful: bool = True


class BulkCloseIn(BaseModel):
    alert_ids: list[int] | None = None
    noise_hint: str | None = Field(default=None, max_length=32)
    disposition: str = Field(default="false_positive", max_length=32)
    closure_note: str = Field(
        default="Noise training batch: false positive lab noise for RAG priors.",
        min_length=10,
        max_length=4000,
    )
    limit: int = Field(default=50, ge=1, le=200)


class BulkCloseOut(BaseModel):
    closed: int = 0
    ids: list[int] = Field(default_factory=list)


class RotateSealedIn(BaseModel):
    old_secret: str = Field(..., min_length=8, max_length=512)
    new_secret: str = Field(..., min_length=8, max_length=512)


class RotateSealedOut(BaseModel):
    resealed: int = 0
    message: str | None = None


class VtEnrichOut(BaseModel):
    available: bool
    cached: bool = False
    ioc_type: str | None = None
    value: str | None = None
    verdict: str | None = None
    malicious_count: int = 0
    stats: dict[str, Any] = Field(default_factory=dict)
    fetched_at: str | None = None
    message: str | None = None
    error: str | None = None


class AlertSearchHit(AlertOut):
    matched_comment: str | None = None


class RuleOut(BaseModel):
    id: str
    name: str
    description: str = ""
    threat_brief: str | None = None
    mitre: str | None = None
    severity: str = "medium"
    type: str
    enabled: bool = True
    definition: dict[str, Any] = Field(default_factory=dict)


class RuleCreate(BaseModel):
    id: str = Field(min_length=2, max_length=63)
    name: str = Field(min_length=1, max_length=MAX_RULE_NAME)
    title: str | None = Field(default=None, max_length=MAX_RULE_NAME)
    description: str = Field(default="", max_length=MAX_RULE_TEXT)
    threat_brief: str = Field(default="", max_length=MAX_RULE_TEXT)
    mitre: str | list[str] | None = None
    type: str = "match"
    severity: str = "medium"
    enabled: bool = True
    window_minutes: int = Field(default=10, ge=1, le=MAX_WINDOW_MINUTES)
    cooldown_minutes: int = Field(default=15, ge=1, le=MAX_WINDOW_MINUTES)
    match: dict[str, Any] = Field(default_factory=dict)
    threshold: int | None = Field(default=None, ge=1, le=MAX_THRESHOLD)
    group_by: str | None = None
    join_on: str | None = None
    steps: list[dict[str, Any]] | None = None
    overwrite: bool = False

    @field_validator("type")
    @classmethod
    def type_ok(cls, v: str) -> str:
        t = v.strip().lower()
        if t not in ALLOWED_TYPES:
            raise ValueError("type must be match, threshold, or correlation")
        return t

    @field_validator("severity")
    @classmethod
    def sev_ok(cls, v: str) -> str:
        s = v.strip().lower()
        if s not in ALLOWED_SEVERITIES:
            raise ValueError(f"severity must be one of: {', '.join(sorted(ALLOWED_SEVERITIES))}")
        return s


class DryRunRequest(BaseModel):
    events: list[Any] = Field(default_factory=list, max_length=100)
    rule_ids: list[str] | None = None


class DryRunHit(BaseModel):
    rule_id: str
    rule_name: str = ""
    severity: str = "medium"
    title: str = ""
    mitre: str | None = None
    would_create: bool = True
    evidence: dict[str, Any] = Field(default_factory=dict)


class DryRunResponse(BaseModel):
    matched: list[DryRunHit] = Field(default_factory=list)
    events_normalized: int = 0


class RuleEnabledUpdate(BaseModel):
    enabled: bool


class SourceOut(BaseModel):
    channel: str
    count: int
    last_event_at: datetime | None = None


class SourceHealthOut(BaseModel):
    source_type: str
    last_event_at: datetime | None = None
    silent_for_seconds: int | None = None
    status: str


class StatsOut(BaseModel):
    range: str = "1h"
    total_events: int
    total_alerts: int
    open_alerts: int
    eps_approx: float
    by_source_type: dict[str, int]
    by_severity: dict[str, int]
    by_channel: dict[str, int]
    by_alert_status: dict[str, int] = Field(default_factory=dict)
    timeline: list[dict[str, Any]]
    source_health: list[SourceHealthOut] = Field(default_factory=list)
    recent_alerts: list[AlertOut]


class SetupOut(BaseModel):
    retention_days: int
    health_stale_minutes: int
    health_silent_minutes: int
    silence_alerts_enabled: bool
    purge_interval_sec: int
    last_purge_at: datetime | None = None
    last_purge_deleted: int = 0
    vt_configured: bool = False
    vt_api_key_masked: str | None = None
    abuseipdb_configured: bool = False
    abuseipdb_api_key_masked: str | None = None
    otx_configured: bool = False
    otx_api_key_masked: str | None = None
    notify_webhook_configured: bool = False
    notify_webhook_url_masked: str | None = None
    notify_format: str = "slack"
    notify_min_severity: str = "high"
    sla_ack_minutes: dict[str, int] = Field(default_factory=dict)
    sla_close_minutes: dict[str, int] = Field(default_factory=dict)
    triage_scoring_enabled: bool = True
    triage_prior_days: int = 30
    rag_enabled: bool = True
    rag_top_k: int = 5
    llm_enabled: bool = False
    llm_configured: bool = False
    llm_api_key_masked: str | None = None
    llm_api_url: str = "https://api.openai.com/v1/chat/completions"
    llm_model: str = "gpt-4o-mini"
    graph_enabled: bool = True
    graph_window_minutes: int = 120
    graph_min_history: int = 15
    graph_peer_limit: int = 40
    suppress_noise_in_queue: bool = False
    llm_effort: str = "low"
    notify_min_risk_score: int | None = None


class SetupUpdate(BaseModel):
    retention_days: int | None = Field(default=None, ge=0, le=3650)
    health_stale_minutes: int | None = Field(default=None, ge=1, le=10080)
    health_silent_minutes: int | None = Field(default=None, ge=1, le=10080)
    silence_alerts_enabled: bool | None = None
    vt_api_key: str | None = Field(default=None, max_length=256)
    abuseipdb_api_key: str | None = Field(default=None, max_length=256)
    otx_api_key: str | None = Field(default=None, max_length=256)
    notify_webhook_url: str | None = Field(default=None, max_length=2048)
    notify_format: str | None = Field(default=None, max_length=16)
    notify_min_severity: str | None = Field(default=None, max_length=16)
    sla_ack_minutes: dict[str, int] | None = None
    sla_close_minutes: dict[str, int] | None = None
    triage_scoring_enabled: bool | None = None
    triage_prior_days: int | None = Field(default=None, ge=1, le=365)
    rag_enabled: bool | None = None
    rag_top_k: int | None = Field(default=None, ge=1, le=10)
    llm_enabled: bool | None = None
    llm_api_url: str | None = Field(default=None, max_length=2048)
    llm_api_key: str | None = Field(default=None, max_length=512)
    llm_model: str | None = Field(default=None, max_length=128)
    graph_enabled: bool | None = None
    graph_window_minutes: int | None = Field(default=None, ge=5, le=10080)
    graph_min_history: int | None = Field(default=None, ge=0, le=10000)
    graph_peer_limit: int | None = Field(default=None, ge=10, le=80)
    suppress_noise_in_queue: bool | None = None
    llm_effort: str | None = Field(default=None, max_length=16)
    notify_min_risk_score: int | None = Field(default=None, ge=0, le=100)


class ProviderEnrichOut(BaseModel):
    provider: str
    available: bool
    cached: bool = False
    ioc_type: str | None = None
    value: str | None = None
    verdict: str | None = None
    malicious_count: int = 0
    stats: dict[str, Any] = Field(default_factory=dict)
    fetched_at: str | None = None
    message: str | None = None
    error: str | None = None


class MultiEnrichOut(BaseModel):
    ioc_type: str
    value: str
    results: list[ProviderEnrichOut] = Field(default_factory=list)


class PurgeResult(BaseModel):
    deleted: int
    cutoff: str | None = None
    skipped: bool = False


SearchResponse.model_rebuild()
AlertOut.model_rebuild()
