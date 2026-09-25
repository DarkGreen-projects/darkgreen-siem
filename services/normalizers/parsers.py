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
    # FortiGate level names
    "alert": "critical",
    "emergency": "critical",
    "notice": "low",
    "information": "info",
}

_DENY_ACTIONS = frozenset({"deny", "drop", "blocked", "block", "timeout", "reset", "client-rst", "server-rst"})
_ALLOW_ACTIONS = frozenset({"accept", "pass", "allow", "close", "close-by-client", "close-by-server"})
_UTM_SUBTYPES = frozenset({"virus", "ips", "webfilter", "app-ctrl", "app_ctrl", "botnet", "dlp", "emailfilter", "waf"})

_SYSLOG_HEADER_RE = re.compile(
    r"^(?:"
    r"<\d+>"  # PRI
    r"(?:1\s+)?"  # optional VERSION
    r")?"
    r"(?:"
    r"(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"  # BSD timestamp
    r"|(?:\d{4}-\d{2}-\d{2}T[\d:.+-]+Z?)"  # RFC3339
    r")?\s*"
    r"(?:[^\s=]+\s+)?"  # hostname (no = to avoid eating KV)
    r"(?:CEF:\d+\|[^\|]*\|[^\|]*\|[^\|]*\|[^\|]*\|[^\|]*\|[^\|]*\|)?"  # CEF prefix
    r"(.*)$",
    re.DOTALL,
)


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


def strip_syslog_header(raw: str) -> str:
    """Drop PRI / BSD or RFC3339 timestamp / hostname / CEF prefix; keep KV body."""
    text = (raw or "").strip()
    if "logid=" in text or "srcip=" in text or "devid=" in text:
        # Prefer finding first Forti-ish key rather than fragile full-header match
        for marker in ("date=", "logid=", "devname=", "devid=", "type=", "srcip="):
            idx = text.find(marker)
            if idx > 0:
                return text[idx:]
            if idx == 0:
                return text
    m = _SYSLOG_HEADER_RE.match(text)
    if m and m.group(1):
        return m.group(1).strip()
    return text


def _forti_action(kv: dict[str, str]) -> str:
    raw_action = (kv.get("action") or kv.get("status") or "").strip().lower()
    subtype = (kv.get("subtype") or "").strip().lower().replace("_", "-")
    log_type = (kv.get("type") or "").strip().lower()

    if log_type == "utm" or subtype in _UTM_SUBTYPES:
        if subtype:
            return subtype.replace("-", "_")
        if raw_action in _DENY_ACTIONS:
            return "deny"
        if raw_action:
            return raw_action.replace("-", "_")
        return "utm"
    if raw_action in _DENY_ACTIONS:
        return "deny"
    if raw_action in _ALLOW_ACTIONS:
        return "allow"
    if raw_action:
        return raw_action.replace("-", "_")
    if subtype:
        return subtype.replace("-", "_")
    return "unknown"


def _forti_severity(kv: dict[str, str], action: str) -> str:
    if "level" in kv:
        return sev(kv["level"], "info")
    if "severity" in kv:
        return sev(kv["severity"], "info")
    if action in {"deny"} or action in {s.replace("-", "_") for s in _UTM_SUBTYPES}:
        if action == "deny":
            return "high"
        return "high"
    if action == "allow":
        return "info"
    return "info"


def _forti_timestamp(kv: dict[str, str], meta: dict[str, Any]) -> datetime:
    if kv.get("eventtime"):
        # Forti often sends epoch microseconds as string
        et = kv["eventtime"]
        try:
            n = int(et)
            if n > 1e14:  # nanoseconds-ish
                n //= 1000
            if n > 1e12:  # microseconds
                return datetime.fromtimestamp(n / 1_000_000.0, tz=timezone.utc)
            if n > 1e10:  # milliseconds
                return datetime.fromtimestamp(n / 1000.0, tz=timezone.utc)
            return datetime.fromtimestamp(n, tz=timezone.utc)
        except ValueError:
            return parse_ts(et)
    if kv.get("date") and kv.get("time"):
        return parse_ts(f"{kv['date']}T{kv['time']}")
    return parse_ts(kv.get("time") or meta.get("timestamp"))


def _label_clean(labels: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in labels.items() if v is not None and str(v).strip() != ""}


def normalize_firewall_syslog(
    raw: str, *, ingest_channel: str = "syslog", meta: dict[str, Any] | None = None
) -> NormalizedEvent:
    meta = meta or {}
    body = strip_syslog_header(raw)
    kv = parse_kv_syslog(body)
    action = _forti_action(kv)
    severity = _forti_severity(kv, action)
    host = kv.get("devname") or kv.get("hostname") or meta.get("host")
    msg = kv.get("msg") or kv.get("attack") or body or raw
    msg_s = msg if len(msg) < 500 else msg[:497] + "..."
    labels = _label_clean(
        {
            "logid": kv.get("logid"),
            "type": kv.get("type"),
            "subtype": kv.get("subtype"),
            "devid": kv.get("devid"),
            "vd": kv.get("vd"),
            "srcport": kv.get("srcport"),
            "dstport": kv.get("dstport"),
            "srcintf": kv.get("srcintf"),
            "dstintf": kv.get("dstintf"),
            "proto": kv.get("proto") or kv.get("service"),
            "app": kv.get("app") or kv.get("appact") or kv.get("appcat"),
            "policyid": kv.get("policyid"),
            "policyname": kv.get("policyname") or kv.get("poluuid"),
            "url": kv.get("url") or kv.get("hostname"),
            "filename": kv.get("filename"),
            "attack": kv.get("attack") or kv.get("attackid"),
            "sessionid": kv.get("sessionid"),
            "level": kv.get("level"),
        }
    )
    return NormalizedEvent(
        timestamp=_forti_timestamp(kv, meta),
        source_type="firewall",
        vendor=kv.get("vendor") or "Fortinet",
        device=kv.get("devname") or "fortigate-demo",
        host=host,
        user=kv.get("user") or kv.get("unauthuser"),
        src_ip=kv.get("srcip") or kv.get("src"),
        dst_ip=kv.get("dstip") or kv.get("dst"),
        action=action,
        severity=severity,
        message=msg_s,
        raw=raw,
        labels=labels,
        ingest_channel=ingest_channel,
    )


def normalize_windows_event(
    payload: dict[str, Any], *, ingest_channel: str = "http", raw: str | None = None
) -> NormalizedEvent:
    event_id = str(payload.get("EventID") or payload.get("event_id") or "").strip()

    channel_raw = payload.get("Channel") or payload.get("channel")
    if channel_raw is None and isinstance(payload.get("Log"), dict):
        channel_raw = payload["Log"].get("Channel")
    if isinstance(channel_raw, dict):
        channel_raw = channel_raw.get("Name") or channel_raw.get("name")
    channel_s = str(channel_raw).strip() if channel_raw else "Security"

    provider_raw = payload.get("ProviderName") or payload.get("provider")
    if provider_raw is None:
        provider_raw = payload.get("Provider")
    if isinstance(provider_raw, dict):
        provider_raw = provider_raw.get("Name") or provider_raw.get("#text") or provider_raw.get("name")
    provider_s = (
        str(provider_raw).strip() if provider_raw else "Microsoft-Windows-Security-Auditing"
    )

    action = (payload.get("Action") or payload.get("action") or "").lower()
    if not action:
        if event_id in {"4625", "4771"}:
            action = "login_failed"
        elif event_id in {"4624"}:
            action = "login_success"
        elif event_id in {"4688"}:
            action = "process_create"
        elif event_id in {"1102"}:
            action = "audit_cleared"
        else:
            action = "windows_event"
    if action == "login_failed":
        severity = "high"
    elif action == "audit_cleared":
        severity = "critical"
    else:
        severity = sev(payload.get("Level") or payload.get("severity"), "info")
    message = payload.get("Message") or payload.get("message") or f"Windows Event {event_id}"
    return NormalizedEvent(
        timestamp=parse_ts(payload.get("TimeCreated") or payload.get("timestamp")),
        source_type="windows",
        vendor="Microsoft",
        device=payload.get("Computer") or payload.get("host") or "win-dc01",
        host=payload.get("Computer") or payload.get("host"),
        user=payload.get("TargetUserName") or payload.get("user") or payload.get("SubjectUserName"),
        src_ip=payload.get("IpAddress") or payload.get("src_ip"),
        dst_ip=payload.get("dst_ip"),
        action=action,
        severity=severity,
        message=str(message),
        raw=raw or json.dumps(payload, default=str),
        labels={
            "event_id": event_id,
            "channel": channel_s,
            "provider": provider_s,
            "logon_type": str(payload.get("LogonType") or ""),
            "process": payload.get("NewProcessName") or payload.get("process"),
        },
        ingest_channel=ingest_channel,
        event_id=event_id or None,
        channel=channel_s,
        provider=provider_s,
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
