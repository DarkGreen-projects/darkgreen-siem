from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from .config import get_settings
from .models import Base

settings = get_settings()
engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

_ALTERS = (
    "ALTER TABLE events ADD COLUMN IF NOT EXISTS event_id VARCHAR(64)",
    "ALTER TABLE events ADD COLUMN IF NOT EXISTS channel VARCHAR(128)",
    "ALTER TABLE events ADD COLUMN IF NOT EXISTS provider VARCHAR(128)",
)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        for stmt in _ALTERS:
            try:
                conn.execute(text(stmt))
            except Exception:
                # SQLite / older engines may not support IF NOT EXISTS the same way
                pass


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
