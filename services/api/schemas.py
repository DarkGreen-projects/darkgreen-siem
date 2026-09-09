from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class IngestItem(BaseModel):
    source_type: str | None = None
    payload: Any
    ingest_channel: str = "http"


class IngestRequest(BaseModel):
    events: list[IngestItem] = Field(default_factory=list)
    # convenience: single raw string or object
    raw: Any | None = None
    source_type: str | None = None
    ingest_channel: str = "http"


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


class AlertOut(BaseModel):
    id: int
    rule_id: str
    rule_name: str
    severity: str
    title: str
    description: str
    status: str
    evidence: dict[str, Any]
    created_at: datetime
    acked_at: datetime | None = None

    class Config:
        from_attributes = True


class RuleOut(BaseModel):
    id: str
    name: str
    description: str = ""
    severity: str = "medium"
    type: str
    enabled: bool = True
    definition: dict[str, Any] = Field(default_factory=dict)


class SourceOut(BaseModel):
    channel: str
    count: int
    last_event_at: datetime | None = None


class StatsOut(BaseModel):
    total_events: int
    total_alerts: int
    open_alerts: int
    eps_approx: float
    by_source_type: dict[str, int]
    by_severity: dict[str, int]
    by_channel: dict[str, int]
    timeline: list[dict[str, Any]]
    recent_alerts: list[AlertOut]
