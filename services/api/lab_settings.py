"""Mutable lab settings (env defaults + DB-backed overrides for HA)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from threading import Lock

from sqlalchemy.orm import Session

from .config import Settings, get_settings

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
    _vt_cleared: bool = False
    _abuse_cleared: bool = False
    _otx_cleared: bool = False


_lock = Lock()
_state: LabState | None = None


def _from_settings(s: Settings) -> LabState:
    return LabState(
        retention_days=max(0, int(s.retention_days)),
        health_stale_minutes=max(1, int(s.health_stale_minutes)),
        health_silent_minutes=max(1, int(s.health_silent_minutes)),
        silence_alerts_enabled=bool(s.silence_alerts_enabled),
        purge_interval_sec=max(30, int(s.purge_interval_sec)),
        vt_api_key=(s.vt_api_key or "").strip(),
        abuseipdb_api_key=(getattr(s, "abuseipdb_api_key", "") or "").strip(),
        otx_api_key=(getattr(s, "otx_api_key", "") or "").strip(),
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
    }
