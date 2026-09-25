"""Detect source_type for syslog UDP payloads."""

from __future__ import annotations


def detect_syslog_source(text: str) -> str:
    stripped = (text or "").strip()
    if stripped.startswith("{") and (
        "EventID" in stripped or '"Channel"' in stripped or '"channel"' in stripped
    ):
        return "windows"
    lower = stripped.lower()
    if (
        "logid=" in lower
        or "devid=" in lower
        or "srcip=" in lower
        or ("type=" in lower and "subtype=" in lower)
    ):
        return "firewall"
    return "firewall"
