from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _sanitize_ip(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


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

    @field_validator("src_ip", "dst_ip", mode="before")
    @classmethod
    def ip_ok(cls, v: Any) -> str | None:
        return _sanitize_ip(v if v is None else str(v))

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
            "message": (self.message or "")[:2048],
            "raw": (self.raw or "")[:65536],
            "labels": self.labels,
            "ingest_channel": self.ingest_channel,
        }
