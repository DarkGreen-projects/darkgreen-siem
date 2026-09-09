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

    class Config:
        from_attributes = True


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


ALERT_STATUSES = frozenset({"open", "acked", "in_progress", "closed"})


class AlertOut(BaseModel):
    id: int
    rule_id: str
    rule_name: str
    severity: str
    title: str
    description: str
    status: str
    evidence: dict[str, Any]
    threat_brief: str | None = None
    comments: list[CommentOut] = Field(default_factory=list)
    created_at: datetime
    acked_at: datetime | None = None

    class Config:
        from_attributes = True


class AlertSearchHit(AlertOut):
    matched_comment: str | None = None


class RuleOut(BaseModel):
    id: str
    name: str
    description: str = ""
    threat_brief: str | None = None
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
    type: str = "match"
    severity: str = "medium"
    enabled: bool = True
    window_minutes: int = Field(default=10, ge=1, le=MAX_WINDOW_MINUTES)
    cooldown_minutes: int = Field(default=15, ge=1, le=MAX_WINDOW_MINUTES)
    match: dict[str, Any] = Field(default_factory=dict)
    threshold: int | None = Field(default=None, ge=1, le=MAX_THRESHOLD)
    group_by: str | None = None
    overwrite: bool = False

    @field_validator("type")
    @classmethod
    def type_ok(cls, v: str) -> str:
        t = v.strip().lower()
        if t not in ALLOWED_TYPES:
            raise ValueError("type must be match or threshold")
        return t

    @field_validator("severity")
    @classmethod
    def sev_ok(cls, v: str) -> str:
        s = v.strip().lower()
        if s not in ALLOWED_SEVERITIES:
            raise ValueError(f"severity must be one of: {', '.join(sorted(ALLOWED_SEVERITIES))}")
        return s


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
    timeline: list[dict[str, Any]]
    source_health: list[SourceHealthOut] = Field(default_factory=list)
    recent_alerts: list[AlertOut]


SearchResponse.model_rebuild()
