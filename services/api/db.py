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
    "CREATE INDEX IF NOT EXISTS ix_events_tenant_ts ON events (tenant_id, timestamp)",
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
