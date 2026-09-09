"""ECS-lite event schema and multi-source normalizers."""

from __future__ import annotations

from .schema import NormalizedEvent
from .dispatch import normalize_event, detect_source_type

__all__ = ["NormalizedEvent", "normalize_event", "detect_source_type"]
