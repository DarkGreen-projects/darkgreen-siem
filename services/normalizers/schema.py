from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class NormalizedEvent(BaseModel):
    timestamp: datetime = Field(default_factory=utc_now)
    source_type: str = "unknown"
    vendor: str | None = None
    device: str | None = None
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    action: str | None = None
    severity: str = "info"
    message: str = ""
    raw: str = ""
    labels: dict[str, Any] = Field(default_factory=dict)
    ingest_channel: str = "http"

    def to_row(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "source_type": self.source_type,
            "vendor": self.vendor,
            "device": self.device,
            "host": self.host,
            "user": self.user,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "action": self.action,
            "severity": self.severity.lower() if self.severity else "info",
            "message": self.message,
            "raw": self.raw,
            "labels": self.labels,
            "ingest_channel": self.ingest_channel,
        }
