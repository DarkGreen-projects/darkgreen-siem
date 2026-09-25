"""Mutable lab settings (env defaults + DB-backed overrides for HA)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock

from sqlalchemy.orm import Session

from .config import Settings, get_settings
from .sla import (
    DEFAULT_SLA_ACK_MINUTES,
    DEFAULT_SLA_CLOSE_MINUTES,
    default_sla_ack,
    default_sla_close,
    normalize_sla_map,
)

CLEAR_TOKEN = "CLEAR"

_KEY_MAP = {
    "retention_days": "retention_days",
    "health_stale_minutes": "health_stale_minutes",
    "health_silent_minutes": "health_silent_minutes",
    "silence_alerts_enabled": "silence_alerts_enabled",
    "vt_api_key": "vt_api_key",
    "abuseipdb_api_key": "abuseipdb_api_key",
    "otx_api_key": "otx_api_key",
}


def mask_secret(value: str | None) -> str | None:
    raw = (value or "").strip()
    if not raw:
        return None
    if len(raw) <= 4:
        return "****"
    return f"****{raw[-4:]}"


@dataclass
class LabState:
    retention_days: int = 7
    health_stale_minutes: int = 5
    health_silent_minutes: int = 30
    silence_alerts_enabled: bool = True
    purge_interval_sec: int = 300
    last_purge_at: datetime | None = None
    last_purge_deleted: int = 0
    vt_api_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""
    notify_webhook_url: str = ""
    notify_format: str = "slack"
    notify_min_severity: str = "high"
    sla_ack_minutes: dict[str, int] = field(default_factory=default_sla_ack)
    sla_close_minutes: dict[str, int] = field(default_factory=default_sla_close)
    _vt_cleared: bool = False
    _abuse_cleared: bool = False
    _otx_cleared: bool = False
    _notify_cleared: bool = False


_lock = Lock()
_state: LabState | None = None


def _from_settings(s: Settings) -> LabState:
    ack = default_sla_ack()
    close = default_sla_close()
    try:
        if getattr(s, "sla_ack_minutes", None):
            ack = normalize_sla_map(s.sla_ack_minutes, defaults=DEFAULT_SLA_ACK_MINUTES)
    except ValueError:
        pass
    try:
        if getattr(s, "sla_close_minutes", None):
            close = normalize_sla_map(s.sla_close_minutes, defaults=DEFAULT_SLA_CLOSE_MINUTES)
    except ValueError:
        pass
    return LabState(
        retention_days=max(0, int(s.retention_days)),
        health_stale_minutes=max(1, int(s.health_stale_minutes)),
        health_silent_minutes=max(1, int(s.health_silent_minutes)),
        silence_alerts_enabled=bool(s.silence_alerts_enabled),
        purge_interval_sec=max(30, int(s.purge_interval_sec)),
        vt_api_key=(s.vt_api_key or "").strip(),
        abuseipdb_api_key=(getattr(s, "abuseipdb_api_key", "") or "").strip(),
        otx_api_key=(getattr(s, "otx_api_key", "") or "").strip(),
        notify_webhook_url=(getattr(s, "notify_webhook_url", "") or "").strip(),
        notify_format=(getattr(s, "notify_format", "slack") or "slack").strip().lower(),
        notify_min_severity=(getattr(s, "notify_min_severity", "high") or "high")
        .strip()
        .lower(),
        sla_ack_minutes=ack,
        sla_close_minutes=close,
    )


def get_lab_state() -> LabState:
    global _state
    with _lock:
        if _state is None:
            _state = _from_settings(get_settings())
        return _state


def reset_lab_state_for_tests(s: Settings | None = None) -> LabState:
    global _state
    with _lock:
        _state = _from_settings(s or get_settings())
        return _state


def load_lab_settings_from_db(db: Session) -> LabState:
    """Merge LabSetting rows into in-memory state (called at startup / after PATCH)."""
    from .models import LabSetting
    from sqlalchemy import select

    state = get_lab_state()
    rows = {r.key: r.value for r in db.scalars(select(LabSetting)).all()}
    with _lock:
        if "retention_days" in rows:
            try:
                state.retention_days = max(0, int(rows["retention_days"]))
            except ValueError:
                pass
        if "health_stale_minutes" in rows:
            try:
                state.health_stale_minutes = max(1, int(rows["health_stale_minutes"]))
            except ValueError:
                pass
        if "health_silent_minutes" in rows:
            try:
                state.health_silent_minutes = max(1, int(rows["health_silent_minutes"]))
            except ValueError:
                pass
        if "silence_alerts_enabled" in rows:
            state.silence_alerts_enabled = rows["silence_alerts_enabled"].lower() in {
                "1",
                "true",
                "yes",
            }
        if "vt_api_key" in rows:
            state.vt_api_key = rows["vt_api_key"]
            state._vt_cleared = rows["vt_api_key"] == ""
        if "abuseipdb_api_key" in rows:
            state.abuseipdb_api_key = rows["abuseipdb_api_key"]
            state._abuse_cleared = rows["abuseipdb_api_key"] == ""
        if "otx_api_key" in rows:
            state.otx_api_key = rows["otx_api_key"]
            state._otx_cleared = rows["otx_api_key"] == ""
        if "notify_webhook_url" in rows:
            state.notify_webhook_url = rows["notify_webhook_url"]
            state._notify_cleared = rows["notify_webhook_url"] == ""
        if "notify_format" in rows and rows["notify_format"]:
            state.notify_format = rows["notify_format"].strip().lower()
        if "notify_min_severity" in rows and rows["notify_min_severity"]:
            state.notify_min_severity = rows["notify_min_severity"].strip().lower()
        if "sla_ack_minutes" in rows and rows["sla_ack_minutes"]:
            try:
                state.sla_ack_minutes = normalize_sla_map(
                    rows["sla_ack_minutes"], defaults=DEFAULT_SLA_ACK_MINUTES
                )
            except ValueError:
                pass
        if "sla_close_minutes" in rows and rows["sla_close_minutes"]:
            try:
                state.sla_close_minutes = normalize_sla_map(
                    rows["sla_close_minutes"], defaults=DEFAULT_SLA_CLOSE_MINUTES
                )
            except ValueError:
                pass
        return state


def _persist_key(db: Session, key: str, value: str) -> None:
    from .models import LabSetting

    row = db.get(LabSetting, key)
    if row is None:
        db.add(LabSetting(key=key, value=value))
    else:
        row.value = value


def persist_lab_state(db: Session, state: LabState | None = None) -> None:
    s = state or get_lab_state()
    with _lock:
        _persist_key(db, "retention_days", str(s.retention_days))
        _persist_key(db, "health_stale_minutes", str(s.health_stale_minutes))
        _persist_key(db, "health_silent_minutes", str(s.health_silent_minutes))
        _persist_key(
            db, "silence_alerts_enabled", "true" if s.silence_alerts_enabled else "false"
        )
        _persist_key(db, "vt_api_key", s.vt_api_key or "")
        _persist_key(db, "abuseipdb_api_key", s.abuseipdb_api_key or "")
        _persist_key(db, "otx_api_key", s.otx_api_key or "")
        _persist_key(db, "notify_webhook_url", s.notify_webhook_url or "")
        _persist_key(db, "notify_format", s.notify_format or "slack")
        _persist_key(db, "notify_min_severity", s.notify_min_severity or "high")
        _persist_key(db, "sla_ack_minutes", json.dumps(s.sla_ack_minutes or default_sla_ack()))
        _persist_key(
            db, "sla_close_minutes", json.dumps(s.sla_close_minutes or default_sla_close())
        )
        db.commit()


def _apply_key(current: str, incoming: str | None, *, cleared_attr: str, state: LabState) -> str:
    if incoming is None:
        return current
    text = incoming.strip()
    if text == "":
        return current
    if text.upper() == CLEAR_TOKEN:
        setattr(state, cleared_attr, True)
        return ""
    setattr(state, cleared_attr, False)
    return text


def update_lab_state(
    *,
    retention_days: int | None = None,
    health_stale_minutes: int | None = None,
    health_silent_minutes: int | None = None,
    silence_alerts_enabled: bool | None = None,
    vt_api_key: str | None = None,
    abuseipdb_api_key: str | None = None,
    otx_api_key: str | None = None,
    notify_webhook_url: str | None = None,
    notify_format: str | None = None,
    notify_min_severity: str | None = None,
    sla_ack_minutes: dict[str, int] | None = None,
    sla_close_minutes: dict[str, int] | None = None,
    db: Session | None = None,
) -> LabState:
    state = get_lab_state()
    with _lock:
        if retention_days is not None:
            if retention_days < 0 or retention_days > 3650:
                raise ValueError("retention_days must be 0..3650 (0 disables purge)")
            state.retention_days = retention_days
        if health_stale_minutes is not None:
            if health_stale_minutes < 1 or health_stale_minutes > 10080:
                raise ValueError("health_stale_minutes must be 1..10080")
            state.health_stale_minutes = health_stale_minutes
        if health_silent_minutes is not None:
            if health_silent_minutes < 1 or health_silent_minutes > 10080:
                raise ValueError("health_silent_minutes must be 1..10080")
            state.health_silent_minutes = health_silent_minutes
        if silence_alerts_enabled is not None:
            state.silence_alerts_enabled = silence_alerts_enabled
        if state.health_silent_minutes < state.health_stale_minutes:
            raise ValueError("health_silent_minutes must be >= health_stale_minutes")

        state.vt_api_key = _apply_key(
            state.vt_api_key, vt_api_key, cleared_attr="_vt_cleared", state=state
        )
        state.abuseipdb_api_key = _apply_key(
            state.abuseipdb_api_key,
            abuseipdb_api_key,
            cleared_attr="_abuse_cleared",
            state=state,
        )
        state.otx_api_key = _apply_key(
            state.otx_api_key, otx_api_key, cleared_attr="_otx_cleared", state=state
        )
        state.notify_webhook_url = _apply_key(
            state.notify_webhook_url,
            notify_webhook_url,
            cleared_attr="_notify_cleared",
            state=state,
        )
        if notify_format is not None and notify_format.strip():
            fmt = notify_format.strip().lower()
            if fmt not in {"slack", "teams"}:
                raise ValueError("notify_format must be slack or teams")
            state.notify_format = fmt
        if notify_min_severity is not None and notify_min_severity.strip():
            sev = notify_min_severity.strip().lower()
            if sev not in {"critical", "high", "medium", "low", "info"}:
                raise ValueError("notify_min_severity invalid")
            state.notify_min_severity = sev
        if sla_ack_minutes is not None:
            state.sla_ack_minutes = normalize_sla_map(
                sla_ack_minutes, defaults=state.sla_ack_minutes or DEFAULT_SLA_ACK_MINUTES
            )
        if sla_close_minutes is not None:
            state.sla_close_minutes = normalize_sla_map(
                sla_close_minutes,
                defaults=state.sla_close_minutes or DEFAULT_SLA_CLOSE_MINUTES,
            )
    if db is not None:
        persist_lab_state(db, state)
    return state


def record_purge(deleted: int, when: datetime) -> None:
    state = get_lab_state()
    with _lock:
        state.last_purge_at = when
        state.last_purge_deleted = int(deleted)


def enrichment_keys_public(state: LabState | None = None) -> dict:
    s = state or get_lab_state()
    return {
        "vt_configured": bool(s.vt_api_key),
        "vt_api_key_masked": mask_secret(s.vt_api_key),
        "abuseipdb_configured": bool(s.abuseipdb_api_key),
        "abuseipdb_api_key_masked": mask_secret(s.abuseipdb_api_key),
        "otx_configured": bool(s.otx_api_key),
        "otx_api_key_masked": mask_secret(s.otx_api_key),
        "notify_webhook_configured": bool(s.notify_webhook_url),
        "notify_webhook_url_masked": mask_secret(s.notify_webhook_url),
        "notify_format": s.notify_format or "slack",
        "notify_min_severity": s.notify_min_severity or "high",
        "sla_ack_minutes": dict(s.sla_ack_minutes or default_sla_ack()),
        "sla_close_minutes": dict(s.sla_close_minutes or default_sla_close()),
    }
