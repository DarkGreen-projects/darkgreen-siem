from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from services.normalizers import normalize_event

from .ingest import insert_normalized
from .models import Event

logger = logging.getLogger("seed")


def seed_samples(db: Session, samples_dir: str | Path) -> int:
    existing = db.scalar(select(Event.id).limit(1))
    if existing is not None:
        logger.info("Events already present — skip seed")
        return 0

    root = Path(samples_dir)
    if not root.exists():
        logger.warning("Samples dir missing: %s", root)
        return 0

    now = datetime.now(timezone.utc)
    count = 0
    mapping = [
        ("firewall-syslog.txt", "firewall", "seed"),
        ("windows-events.json", "windows", "seed"),
        ("cloud-auth.json", "cloud_auth", "seed"),
        ("siem-export.json", "siem_export", "seed"),
    ]
    for filename, source_type, channel in mapping:
        path = root / filename
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        payloads: list = []
        if filename.endswith(".json"):
            data = json.loads(text)
            payloads = data if isinstance(data, list) else [data]
        else:
            payloads = [
                line.strip()
                for line in text.splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]

        for idx, item in enumerate(payloads):
            normalized = normalize_event(
                item, source_type=source_type, ingest_channel=channel
            )
            # Spread seed events over the last ~8 minutes so threshold rules fire
            normalized.timestamp = now - timedelta(seconds=30 * (len(payloads) - idx))
            insert_normalized(db, normalized.to_row())
            count += 1
    db.commit()
    logger.info("Seeded %s events", count)
    return count
