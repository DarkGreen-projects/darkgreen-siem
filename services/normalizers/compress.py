"""Compress / decompress event raw payloads (stdlib zlib)."""

from __future__ import annotations

import base64
import zlib

RAW_PREFIX = "ZLIB1:"
COMPRESS_THRESHOLD = 512


def compress_raw(text: str, *, threshold: int = COMPRESS_THRESHOLD) -> str:
    if not text:
        return ""
    if text.startswith(RAW_PREFIX):
        return text
    raw_bytes = text.encode("utf-8")
    if len(raw_bytes) < threshold:
        return text
    packed = zlib.compress(raw_bytes, level=6)
    return RAW_PREFIX + base64.urlsafe_b64encode(packed).decode("ascii")


def decompress_raw(stored: str | None) -> str:
    if not stored:
        return ""
    if not stored.startswith(RAW_PREFIX):
        return stored
    try:
        packed = base64.urlsafe_b64decode(stored[len(RAW_PREFIX) :].encode("ascii"))
        return zlib.decompress(packed).decode("utf-8", errors="replace")
    except Exception:
        return stored


def is_compressed(stored: str | None) -> bool:
    return bool(stored and stored.startswith(RAW_PREFIX))
