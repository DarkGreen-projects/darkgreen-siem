from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from .schema import NormalizedEvent


SEVERITY_MAP = {
    "0": "critical",
    "1": "critical",
    "2": "high",
    "3": "high",
    "4": "medium",
    "5": "medium",
    "6": "low",
    "7": "info",
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "warning": "medium",
    "error": "high",
    "informational": "info",
}


def parse_ts(value: Any) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        # seconds or ms
        ts = float(value)
        if ts > 1e12:
            ts /= 1000.0
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def sev(value: Any, default: str = "info") -> str:
    if value is None:
        return default
    key = str(value).strip().lower()
    return SEVERITY_MAP.get(key, default)


_KV_RE = re.compile(r'(\w+)=(".*?"|\S+)')


def parse_kv_syslog(message: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, raw in _KV_RE.findall(message):
        out[key] = raw.strip('"')
    return out


def normalize_firewall_syslog(
    raw: str, *, ingest_channel: str = "syslog", meta: dict[str, Any] | None = None
) -> NormalizedEvent:
    meta = meta or {}
    kv = parse_kv_syslog(raw)
    action = (kv.get("action") or kv.get("status") or "unknown").lower()
    severity = "high" if action in {"deny", "blocked", "drop"} else "info"
    if "severity" in kv:
        severity = sev(kv["severity"], severity)
    host = kv.get("devname") or kv.get("hostname") or meta.get("host")
    msg = kv.get("msg") or raw
    return NormalizedEvent(
        timestamp=parse_ts(kv.get("eventtime") or kv.get("time") or meta.get("timestamp")),
        source_type="firewall",
        vendor=kv.get("vendor") or "Fortinet",
        device=kv.get("devname") or "fortigate-demo",
        host=host,
        user=kv.get("user") or kv.get("unauthuser"),
        src_ip=kv.get("srcip") or kv.get("src"),
        dst_ip=kv.get("dstip") or kv.get("dst"),
        action=action,
        severity=severity,
        message=msg if len(msg) < 500 else msg[:497] + "...",
        raw=raw,
        labels={
            "srcport": kv.get("srcport"),
            "dstport": kv.get("dstport"),
            "proto": kv.get("proto") or kv.get("service"),
            "policyid": kv.get("policyid"),
        },
        ingest_channel=ingest_channel,
    )


def normalize_windows_event(
    payload: dict[str, Any], *, ingest_channel: str = "http", raw: str | None = None
) -> NormalizedEvent:
    event_id = str(payload.get("EventID") or payload.get("event_id") or "")
    action = (payload.get("Action") or payload.get("action") or "").lower()
    if not action:
        if event_id in {"4625", "4771"}:
            action = "login_failed"
        elif event_id in {"4624"}:
            action = "login_success"
        elif event_id in {"4688"}:
            action = "process_create"
        else:
            action = "windows_event"
    severity = "high" if action == "login_failed" else sev(payload.get("Level") or payload.get("severity"), "info")
    message = payload.get("Message") or payload.get("message") or f"Windows Event {event_id}"
    return NormalizedEvent(
        timestamp=parse_ts(payload.get("TimeCreated") or payload.get("timestamp")),
        source_type="windows",
        vendor="Microsoft",
        device=payload.get("Computer") or payload.get("host") or "win-dc01",
        host=payload.get("Computer") or payload.get("host"),
        user=payload.get("TargetUserName") or payload.get("user"),
        src_ip=payload.get("IpAddress") or payload.get("src_ip"),
        dst_ip=payload.get("dst_ip"),
        action=action,
        severity=severity,
        message=str(message),
        raw=raw or json.dumps(payload, default=str),
        labels={
            "event_id": event_id,
            "logon_type": str(payload.get("LogonType") or ""),
            "process": payload.get("NewProcessName") or payload.get("process"),
        },
        ingest_channel=ingest_channel,
    )


def normalize_cloud_auth(
    payload: dict[str, Any], *, ingest_channel: str = "http", raw: str | None = None
) -> NormalizedEvent:
    result = str(payload.get("result") or payload.get("status") or "").lower()
    action = (payload.get("action") or "").lower()
    if not action:
        action = "login_failed" if result in {"failure", "failed", "denied"} else "login_success"
    severity = "high" if "fail" in action or result in {"failure", "failed"} else "info"
    return NormalizedEvent(
        timestamp=parse_ts(payload.get("time") or payload.get("timestamp") or payload.get("@timestamp")),
        source_type="cloud_auth",
        vendor=payload.get("vendor") or payload.get("app") or "EntraID",
        device=payload.get("app") or "cloud-idp",
        host=payload.get("resource") or payload.get("app"),
        user=payload.get("user") or payload.get("userPrincipalName") or payload.get("actor"),
        src_ip=payload.get("ip") or payload.get("clientIp") or payload.get("src_ip"),
        dst_ip=None,
        action=action,
        severity=sev(payload.get("severity"), severity),
        message=payload.get("message")
        or f"Cloud auth {action} for {payload.get('user') or 'unknown'}",
        raw=raw or json.dumps(payload, default=str),
        labels={
            "app": payload.get("app"),
            "mfa": str(payload.get("mfa") or ""),
            "geo": payload.get("geo") or payload.get("country"),
        },
        ingest_channel=ingest_channel,
    )


def normalize_siem_export(
    payload: dict[str, Any], *, ingest_channel: str = "http", raw: str | None = None
) -> NormalizedEvent:
    # Cynet / generic SIEM export shape
    action = (
        payload.get("action")
        or payload.get("Activity")
        or payload.get("event_type")
        or "alert"
    )
    action = str(action).lower().replace(" ", "_")
    severity = sev(
        payload.get("severity") or payload.get("Severity") or payload.get("risk"),
        "medium",
    )
    message = (
        payload.get("message")
        or payload.get("Description")
        or payload.get("title")
        or payload.get("AlertName")
        or "SIEM export event"
    )
    return NormalizedEvent(
        timestamp=parse_ts(
            payload.get("timestamp")
            or payload.get("DetectionTime")
            or payload.get("Created")
            or payload.get("time")
        ),
        source_type="siem_export",
        vendor=payload.get("vendor") or payload.get("Product") or "Cynet",
        device=payload.get("device") or payload.get("Sensor") or payload.get("host"),
        host=payload.get("host") or payload.get("Hostname") or payload.get("device"),
        user=payload.get("user") or payload.get("User") or payload.get("Account"),
        src_ip=payload.get("src_ip") or payload.get("SourceIP") or payload.get("ip"),
        dst_ip=payload.get("dst_ip") or payload.get("DestinationIP"),
        action=action,
        severity=severity,
        message=str(message),
        raw=raw or json.dumps(payload, default=str),
        labels={
            "alert_id": str(payload.get("AlertId") or payload.get("id") or ""),
            "technique": payload.get("mitre") or payload.get("technique"),
            "category": payload.get("category") or payload.get("Category"),
        },
        ingest_channel=ingest_channel,
    )


def normalize_generic(
    payload: dict[str, Any] | str, *, ingest_channel: str = "http", source_type: str = "unknown"
) -> NormalizedEvent:
    if isinstance(payload, str):
        return NormalizedEvent(
            source_type=source_type,
            message=payload[:500],
            raw=payload,
            ingest_channel=ingest_channel,
        )
    return NormalizedEvent(
        timestamp=parse_ts(payload.get("timestamp")),
        source_type=source_type or payload.get("source_type") or "unknown",
        vendor=payload.get("vendor"),
        device=payload.get("device"),
        host=payload.get("host"),
        user=payload.get("user"),
        src_ip=payload.get("src_ip"),
        dst_ip=payload.get("dst_ip"),
        action=str(payload.get("action") or "unknown").lower(),
        severity=sev(payload.get("severity"), "info"),
        message=str(payload.get("message") or payload),
        raw=json.dumps(payload, default=str),
        labels=dict(payload.get("labels") or {}),
        ingest_channel=ingest_channel,
    )
