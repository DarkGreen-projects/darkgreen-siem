from __future__ import annotations

import json
from typing import Any

from .parsers import (
    normalize_cloud_auth,
    normalize_firewall_syslog,
    normalize_generic,
    normalize_siem_export,
    normalize_windows_event,
)
from .schema import NormalizedEvent


def detect_source_type(payload: Any, hint: str | None = None) -> str:
    if hint:
        return hint.lower().strip()
    if isinstance(payload, str):
        lower = payload.lower()
        if "srcip=" in lower or "dstip=" in lower or "devname=" in lower:
            return "firewall"
        if payload.strip().startswith("{"):
            try:
                return detect_source_type(json.loads(payload))
            except json.JSONDecodeError:
                return "syslog"
        return "syslog"
    if not isinstance(payload, dict):
        return "unknown"
    keys = {k.lower() for k in payload.keys()}
    if {"eventid", "computer"} & keys or "targetusername" in keys:
        return "windows"
    if {"userprincipalname", "clientip"} & keys or payload.get("vendor") in {"EntraID", "Okta"}:
        return "cloud_auth"
    if {"alertid", "detectiontime", "severity"} & keys or payload.get("Product"):
        return "siem_export"
    if payload.get("source_type"):
        return str(payload["source_type"]).lower()
    return "unknown"


def normalize_event(
    payload: Any,
    *,
    source_type: str | None = None,
    ingest_channel: str = "http",
) -> NormalizedEvent:
    raw_str: str
    data: Any = payload
    if isinstance(payload, (bytes, bytearray)):
        raw_str = payload.decode("utf-8", errors="replace")
        data = raw_str
    elif isinstance(payload, str):
        raw_str = payload
        stripped = payload.strip()
        if stripped.startswith("{"):
            try:
                data = json.loads(stripped)
            except json.JSONDecodeError:
                data = payload
        else:
            data = payload
    else:
        raw_str = json.dumps(payload, default=str)

    st = detect_source_type(data, source_type)

    if st == "firewall" or (st == "syslog" and isinstance(data, str)):
        if isinstance(data, dict):
            # rebuild syslog-like line if needed
            line = data.get("raw") or data.get("message") or raw_str
            return normalize_firewall_syslog(str(line), ingest_channel=ingest_channel)
        return normalize_firewall_syslog(str(data), ingest_channel=ingest_channel)

    if st == "windows":
        if isinstance(data, dict):
            return normalize_windows_event(data, ingest_channel=ingest_channel, raw=raw_str)
        return normalize_generic(data, ingest_channel=ingest_channel, source_type="windows")

    if st == "cloud_auth":
        if isinstance(data, dict):
            return normalize_cloud_auth(data, ingest_channel=ingest_channel, raw=raw_str)
        return normalize_generic(data, ingest_channel=ingest_channel, source_type="cloud_auth")

    if st == "siem_export":
        if isinstance(data, dict):
            return normalize_siem_export(data, ingest_channel=ingest_channel, raw=raw_str)
        return normalize_generic(data, ingest_channel=ingest_channel, source_type="siem_export")

    if isinstance(data, dict):
        return normalize_generic(data, ingest_channel=ingest_channel, source_type=st)
    return normalize_generic(str(data), ingest_channel=ingest_channel, source_type=st)
