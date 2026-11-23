from __future__ import annotations

from collections.abc import Generator
from functools import lru_cache

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .config import get_settings
from .models import Base

_ALTERS = (
    "ALTER TABLE events ADD COLUMN IF NOT EXISTS event_id VARCHAR(64)",
    "ALTER TABLE events ADD COLUMN IF NOT EXISTS channel VARCHAR(128)",
    "ALTER TABLE events ADD COLUMN IF NOT EXISTS provider VARCHAR(128)",
    "ALTER TABLE ioc_verdicts ADD COLUMN IF NOT EXISTS provider VARCHAR(32) DEFAULT 'vt'",
    "ALTER TABLE events ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64) DEFAULT 'lab'",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64) DEFAULT 'lab'",
    "ALTER TABLE alert_comments ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64) DEFAULT 'lab'",
    "ALTER TABLE alert_audits ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64) DEFAULT 'lab'",
    "ALTER TABLE ioc_verdicts ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64) DEFAULT 'lab'",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre VARCHAR(256)",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS closed_at TIMESTAMPTZ",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS disposition VARCHAR(32)",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS closure_note TEXT",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS closed_by VARCHAR(128)",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS risk_score INTEGER",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS noise_hint VARCHAR(32)",
    "ALTER TABLE alert_audits ADD COLUMN IF NOT EXISTS note TEXT",
    "CREATE INDEX IF NOT EXISTS ix_events_tenant_ts ON events (tenant_id, timestamp)",
    """
    CREATE TABLE IF NOT EXISTS alert_memory (
        alert_id BIGINT PRIMARY KEY,
        tenant_id VARCHAR(64) NOT NULL DEFAULT 'lab',
        rule_id VARCHAR(128) NOT NULL DEFAULT '',
        entity_key VARCHAR(256),
        disposition VARCHAR(32),
        mitre VARCHAR(256),
        title VARCHAR(512) DEFAULT '',
        note_excerpt TEXT DEFAULT '',
        memory_text TEXT DEFAULT '',
        closed_at TIMESTAMPTZ
    )
    """,
    "ALTER TABLE alert_memory ADD COLUMN IF NOT EXISTS tsv tsvector",
    "CREATE INDEX IF NOT EXISTS ix_alert_memory_tenant_closed ON alert_memory (tenant_id, closed_at)",
    "CREATE INDEX IF NOT EXISTS ix_alert_memory_tsv ON alert_memory USING GIN (tsv)",
    """
    CREATE TABLE IF NOT EXISTS alert_links (
        id BIGSERIAL PRIMARY KEY,
        tenant_id VARCHAR(64) NOT NULL DEFAULT 'lab',
        src_alert_id BIGINT NOT NULL,
        dst_alert_id BIGINT NOT NULL,
        relation VARCHAR(32) NOT NULL,
        score INTEGER DEFAULT 0,
        shared_keys JSONB DEFAULT '[]'::jsonb,
        created_at TIMESTAMPTZ DEFAULT NOW()
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_alert_links_src_dst_rel ON alert_links (src_alert_id, dst_alert_id, relation)",
    "CREATE INDEX IF NOT EXISTS ix_alert_links_tenant ON alert_links (tenant_id, created_at)",
)


@lru_cache
def get_engine() -> Engine:
    settings = get_settings()
    return create_engine(settings.database_url, pool_pre_ping=True)


@lru_cache
def _session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), autoflush=False, autocommit=False)


def SessionLocal() -> Session:
    return _session_factory()()


def init_db() -> None:
    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        for stmt in _ALTERS:
            try:
                conn.execute(text(stmt))
            except Exception:
                pass


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
