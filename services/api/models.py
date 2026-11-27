from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("username", name="uq_users_username"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), index=True)
    password_hash: Mapped[str] = mapped_column(String(256), default="")
    role: Mapped[str] = mapped_column(String(32), default="viewer", index=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="lab", index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class LabSetting(Base):
    """Persisted lab overrides (shared across API replicas)."""

    __tablename__ = "lab_settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="lab", index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source_type: Mapped[str] = mapped_column(String(64), index=True)
    vendor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    device: Mapped[str | None] = mapped_column(String(128), nullable=True)
    host: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)
    user: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)
    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    action: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    severity: Mapped[str] = mapped_column(String(32), default="info", index=True)
    message: Mapped[str] = mapped_column(Text, default="")
    raw: Mapped[str] = mapped_column(Text, default="")
    labels: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    ingest_channel: Mapped[str] = mapped_column(String(32), default="http", index=True)
    event_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    channel: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    provider: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_tenant_status_created", "tenant_id", "status", "created_at"),
        Index("ix_alerts_tenant_rule_status", "tenant_id", "rule_id", "status"),
        Index("ix_alerts_tenant_noise_hint", "tenant_id", "noise_hint"),
        Index("ix_alerts_tenant_fingerprint", "tenant_id", "fingerprint_hash"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="lab", index=True)
    rule_id: Mapped[str] = mapped_column(String(128), index=True)
    rule_name: Mapped[str] = mapped_column(String(256))
    severity: Mapped[str] = mapped_column(String(32), default="medium")
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    mitre: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    acked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disposition: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    closure_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    closed_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    noise_hint: Mapped[str | None] = mapped_column(String(32), nullable=True)
    fingerprint_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)


class AlertComment(Base):
    __tablename__ = "alert_comments"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="lab", index=True)
    alert_id: Mapped[int] = mapped_column(BigInteger, index=True)
    author: Mapped[str] = mapped_column(String(128), default="analyst")
    body: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class IngestStat(Base):
    __tablename__ = "ingest_stats"

    tenant_id: Mapped[str] = mapped_column(String(64), primary_key=True, default="lab")
    channel: Mapped[str] = mapped_column(String(32), primary_key=True)
    count: Mapped[int] = mapped_column(BigInteger, default=0)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AlertAudit(Base):
    __tablename__ = "alert_audits"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="lab", index=True)
    alert_id: Mapped[int] = mapped_column(BigInteger, index=True)
    actor: Mapped[str] = mapped_column(String(128), default="analyst")
    from_status: Mapped[str] = mapped_column(String(32), default="")
    to_status: Mapped[str] = mapped_column(String(32), default="")
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class IocVerdict(Base):
    __tablename__ = "ioc_verdicts"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="lab", index=True)
    provider: Mapped[str] = mapped_column(String(32), default="vt", index=True)
    ioc_type: Mapped[str] = mapped_column(String(32), index=True)
    value: Mapped[str] = mapped_column(String(512), index=True)
    verdict: Mapped[str] = mapped_column(String(32), default="unknown")
    malicious_count: Mapped[int] = mapped_column(BigInteger, default=0)
    stats_json: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class AlertMemory(Base):
    """Closed-alert memory for portable Alert Memory RAG (FTS + structured boosts)."""

    __tablename__ = "alert_memory"

    alert_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="lab", index=True)
    rule_id: Mapped[str] = mapped_column(String(128), index=True)
    entity_key: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)
    disposition: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    mitre: Mapped[str | None] = mapped_column(String(256), nullable=True)
    title: Mapped[str] = mapped_column(String(512), default="")
    note_excerpt: Mapped[str] = mapped_column(Text, default="")
    memory_text: Mapped[str] = mapped_column(Text, default="")
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )


class AlertLink(Base):
    """Directed edge between alerts (entity / temporal / MITRE / IOC)."""

    __tablename__ = "alert_links"
    __table_args__ = (
        UniqueConstraint(
            "src_alert_id",
            "dst_alert_id",
            "relation",
            name="uq_alert_links_src_dst_rel",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="lab", index=True)
    src_alert_id: Mapped[int] = mapped_column(BigInteger, index=True)
    dst_alert_id: Mapped[int] = mapped_column(BigInteger, index=True)
    relation: Mapped[str] = mapped_column(String(32), index=True)
    score: Mapped[int] = mapped_column(Integer, default=0)
    shared_keys: Mapped[list[Any]] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class RateBucket(Base):
    """Fixed-window rate counter shared across API workers via Postgres."""

    __tablename__ = "rate_buckets"

    bucket_key: Mapped[str] = mapped_column(String(256), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="lab", index=True)
    window_id: Mapped[int] = mapped_column(BigInteger, default=0)
    count: Mapped[int] = mapped_column(Integer, default=0)


class CopilotAudit(Base):
    """Suggest-only Copilot provenance (never auto-disposes)."""

    __tablename__ = "copilot_audits"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="lab", index=True)
    alert_id: Mapped[int] = mapped_column(BigInteger, index=True)
    actor: Mapped[str] = mapped_column(String(128), default="analyst")
    action: Mapped[str] = mapped_column(String(32), default="copilot_suggest", index=True)
    source: Mapped[str | None] = mapped_column(String(32), nullable=True)
    suggested_disposition: Mapped[str | None] = mapped_column(String(32), nullable=True)
    llm_skipped: Mapped[str | None] = mapped_column(String(64), nullable=True)
    priority: Mapped[str | None] = mapped_column(String(8), nullable=True)
    noise_action: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class CopilotFeedback(Base):
    """Analyst thumbs on Copilot suggestions (RAG boost)."""

    __tablename__ = "copilot_feedback"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="lab", index=True)
    alert_id: Mapped[int] = mapped_column(BigInteger, index=True)
    actor: Mapped[str] = mapped_column(String(128), default="analyst")
    useful: Mapped[bool] = mapped_column(Boolean, default=True)
    rule_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
