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


def mask_secret(value: str | None, *, reveal_tail: bool = True) -> str | None:
    raw = (value or "").strip()
    if not raw:
        return None
    if not reveal_tail:
        return "****"
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
    triage_scoring_enabled: bool = True
    triage_prior_days: int = 30
    rag_enabled: bool = True
    rag_top_k: int = 5
    llm_enabled: bool = False
    llm_api_url: str = "https://api.openai.com/v1/chat/completions"
    llm_api_key: str = ""
    llm_model: str = "gpt-4o-mini"
    graph_enabled: bool = True
    graph_window_minutes: int = 120
    graph_min_history: int = 15
    graph_peer_limit: int = 40
    suppress_noise_in_queue: bool = False
    llm_effort: str = "low"
    notify_min_risk_score: int | None = None
    _vt_cleared: bool = False
    _abuse_cleared: bool = False
    _otx_cleared: bool = False
    _notify_cleared: bool = False
    _llm_cleared: bool = False


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
        triage_scoring_enabled=True,
        triage_prior_days=30,
        rag_enabled=True,
        rag_top_k=5,
        llm_enabled=bool(getattr(s, "llm_enabled", False)),
        llm_api_url=(
            getattr(s, "llm_api_url", None)
            or "https://api.openai.com/v1/chat/completions"
        ).strip(),
        llm_api_key=(getattr(s, "llm_api_key", "") or "").strip(),
        llm_model=(getattr(s, "llm_model", None) or "gpt-4o-mini").strip(),
        graph_enabled=True,
        graph_window_minutes=120,
        graph_min_history=15,
        graph_peer_limit=40,
        suppress_noise_in_queue=False,
        llm_effort="low",
        notify_min_risk_score=None,
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
        from .secret_crypto import unseal

        if "vt_api_key" in rows:
            state.vt_api_key = unseal(rows["vt_api_key"])
            state._vt_cleared = rows["vt_api_key"] == ""
        if "abuseipdb_api_key" in rows:
            state.abuseipdb_api_key = unseal(rows["abuseipdb_api_key"])
            state._abuse_cleared = rows["abuseipdb_api_key"] == ""
        if "otx_api_key" in rows:
            state.otx_api_key = unseal(rows["otx_api_key"])
            state._otx_cleared = rows["otx_api_key"] == ""
        if "notify_webhook_url" in rows:
            state.notify_webhook_url = unseal(rows["notify_webhook_url"])
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
        if "triage_scoring_enabled" in rows:
            state.triage_scoring_enabled = rows["triage_scoring_enabled"].lower() in {
                "1",
                "true",
                "yes",
            }
        if "triage_prior_days" in rows:
            try:
                state.triage_prior_days = max(1, min(365, int(rows["triage_prior_days"])))
            except ValueError:
                pass
        if "rag_enabled" in rows:
            state.rag_enabled = rows["rag_enabled"].lower() in {"1", "true", "yes"}
        if "rag_top_k" in rows:
            try:
                state.rag_top_k = max(1, min(10, int(rows["rag_top_k"])))
            except ValueError:
                pass
        if "llm_enabled" in rows:
            state.llm_enabled = rows["llm_enabled"].lower() in {"1", "true", "yes"}
        if "llm_api_url" in rows and rows["llm_api_url"]:
            state.llm_api_url = rows["llm_api_url"].strip()
        if "llm_api_key" in rows:
            state.llm_api_key = unseal(rows["llm_api_key"])
            state._llm_cleared = rows["llm_api_key"] == ""
        if "llm_model" in rows and rows["llm_model"]:
            state.llm_model = rows["llm_model"].strip()
        if "graph_enabled" in rows:
            state.graph_enabled = rows["graph_enabled"].lower() in {"1", "true", "yes"}
        if "graph_window_minutes" in rows:
            try:
                state.graph_window_minutes = max(5, min(10080, int(rows["graph_window_minutes"])))
            except ValueError:
                pass
        if "graph_min_history" in rows:
            try:
                state.graph_min_history = max(0, min(10000, int(rows["graph_min_history"])))
            except ValueError:
                pass
        if "graph_peer_limit" in rows:
            try:
                state.graph_peer_limit = max(10, min(80, int(rows["graph_peer_limit"])))
            except ValueError:
                pass
        if "suppress_noise_in_queue" in rows:
            state.suppress_noise_in_queue = rows["suppress_noise_in_queue"].lower() in {
                "1",
                "true",
                "yes",
            }
        if "llm_effort" in rows and rows["llm_effort"]:
            effort = rows["llm_effort"].strip().lower()
            if effort in {"low", "high"}:
                state.llm_effort = effort
        if "notify_min_risk_score" in rows:
            raw = (rows["notify_min_risk_score"] or "").strip()
            if raw == "":
                state.notify_min_risk_score = None
            else:
                try:
                    state.notify_min_risk_score = max(0, min(100, int(raw)))
                except ValueError:
                    pass
        return state


def _persist_key(db: Session, key: str, value: str) -> None:
    from .models import LabSetting
    from .secret_crypto import is_sensitive_key, seal

    stored = seal(value) if is_sensitive_key(key) and value else value
    row = db.get(LabSetting, key)
    if row is None:
        db.add(LabSetting(key=key, value=stored))
    else:
        row.value = stored


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
        _persist_key(
            db,
            "triage_scoring_enabled",
            "true" if s.triage_scoring_enabled else "false",
        )
        _persist_key(db, "triage_prior_days", str(int(s.triage_prior_days or 30)))
        _persist_key(db, "rag_enabled", "true" if s.rag_enabled else "false")
        _persist_key(db, "rag_top_k", str(int(s.rag_top_k or 5)))
        _persist_key(db, "llm_enabled", "true" if s.llm_enabled else "false")
        _persist_key(db, "llm_api_url", s.llm_api_url or "")
        _persist_key(db, "llm_api_key", s.llm_api_key or "")
        _persist_key(db, "llm_model", s.llm_model or "gpt-4o-mini")
        _persist_key(db, "graph_enabled", "true" if s.graph_enabled else "false")
        _persist_key(db, "graph_window_minutes", str(int(s.graph_window_minutes or 120)))
        _persist_key(db, "graph_min_history", str(int(s.graph_min_history or 15)))
        _persist_key(db, "graph_peer_limit", str(int(s.graph_peer_limit or 40)))
        _persist_key(
            db,
            "suppress_noise_in_queue",
            "true" if s.suppress_noise_in_queue else "false",
        )
        _persist_key(db, "llm_effort", (s.llm_effort or "low").strip().lower())
        _persist_key(
            db,
            "notify_min_risk_score",
            "" if s.notify_min_risk_score is None else str(int(s.notify_min_risk_score)),
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
    triage_scoring_enabled: bool | None = None,
    triage_prior_days: int | None = None,
    rag_enabled: bool | None = None,
    rag_top_k: int | None = None,
    llm_enabled: bool | None = None,
    llm_api_url: str | None = None,
    llm_api_key: str | None = None,
    llm_model: str | None = None,
    graph_enabled: bool | None = None,
    graph_window_minutes: int | None = None,
    graph_min_history: int | None = None,
    graph_peer_limit: int | None = None,
    suppress_noise_in_queue: bool | None = None,
    llm_effort: str | None = None,
    notify_min_risk_score: int | None = None,
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
        if notify_webhook_url is not None and notify_webhook_url.strip():
            text = notify_webhook_url.strip()
            if text.upper() != CLEAR_TOKEN:
                from .url_safety import validate_egress_url

                validate_egress_url(text, purpose="notify webhook")
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
        if triage_scoring_enabled is not None:
            state.triage_scoring_enabled = bool(triage_scoring_enabled)
        if triage_prior_days is not None:
            if triage_prior_days < 1 or triage_prior_days > 365:
                raise ValueError("triage_prior_days must be 1..365")
            state.triage_prior_days = triage_prior_days
        if rag_enabled is not None:
            state.rag_enabled = bool(rag_enabled)
        if rag_top_k is not None:
            if rag_top_k < 1 or rag_top_k > 10:
                raise ValueError("rag_top_k must be 1..10")
            state.rag_top_k = int(rag_top_k)
        if llm_enabled is not None:
            state.llm_enabled = bool(llm_enabled)
        if llm_api_url is not None and llm_api_url.strip():
            from .url_safety import validate_egress_url

            state.llm_api_url = validate_egress_url(
                llm_api_url.strip(), purpose="LLM"
            )
        state.llm_api_key = _apply_key(
            state.llm_api_key, llm_api_key, cleared_attr="_llm_cleared", state=state
        )
        if llm_model is not None and llm_model.strip():
            state.llm_model = llm_model.strip()[:128]
        if graph_enabled is not None:
            state.graph_enabled = bool(graph_enabled)
        if graph_window_minutes is not None:
            if graph_window_minutes < 5 or graph_window_minutes > 10080:
                raise ValueError("graph_window_minutes must be 5..10080")
            state.graph_window_minutes = int(graph_window_minutes)
        if graph_min_history is not None:
            if graph_min_history < 0 or graph_min_history > 10000:
                raise ValueError("graph_min_history must be 0..10000")
            state.graph_min_history = int(graph_min_history)
        if graph_peer_limit is not None:
            if graph_peer_limit < 10 or graph_peer_limit > 80:
                raise ValueError("graph_peer_limit must be 10..80")
            state.graph_peer_limit = int(graph_peer_limit)
        if suppress_noise_in_queue is not None:
            state.suppress_noise_in_queue = bool(suppress_noise_in_queue)
        if llm_effort is not None and llm_effort.strip():
            effort = llm_effort.strip().lower()
            if effort not in {"low", "high"}:
                raise ValueError("llm_effort must be low or high")
            state.llm_effort = effort
        if notify_min_risk_score is not None:
            if notify_min_risk_score < 0 or notify_min_risk_score > 100:
                raise ValueError("notify_min_risk_score must be 0..100")
            state.notify_min_risk_score = int(notify_min_risk_score)
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
        "vt_api_key_masked": mask_secret(s.vt_api_key, reveal_tail=False),
        "abuseipdb_configured": bool(s.abuseipdb_api_key),
        "abuseipdb_api_key_masked": mask_secret(s.abuseipdb_api_key, reveal_tail=False),
        "otx_configured": bool(s.otx_api_key),
        "otx_api_key_masked": mask_secret(s.otx_api_key, reveal_tail=False),
        "notify_webhook_configured": bool(s.notify_webhook_url),
        "notify_webhook_url_masked": mask_secret(s.notify_webhook_url, reveal_tail=False),
        "notify_format": s.notify_format or "slack",
        "notify_min_severity": s.notify_min_severity or "high",
        "sla_ack_minutes": dict(s.sla_ack_minutes or default_sla_ack()),
        "sla_close_minutes": dict(s.sla_close_minutes or default_sla_close()),
        "triage_scoring_enabled": bool(s.triage_scoring_enabled),
        "triage_prior_days": int(s.triage_prior_days or 30),
        "rag_enabled": bool(getattr(s, "rag_enabled", True)),
        "rag_top_k": int(getattr(s, "rag_top_k", 5) or 5),
        "llm_enabled": bool(s.llm_enabled),
        "llm_configured": bool(s.llm_api_key),
        "llm_api_key_masked": mask_secret(s.llm_api_key, reveal_tail=False),
        "llm_api_url": s.llm_api_url
        or "https://api.openai.com/v1/chat/completions",
        "llm_model": s.llm_model or "gpt-4o-mini",
        "graph_enabled": bool(getattr(s, "graph_enabled", True)),
        "graph_window_minutes": int(getattr(s, "graph_window_minutes", 120) or 120),
        "graph_min_history": int(getattr(s, "graph_min_history", 15) or 15),
        "graph_peer_limit": int(getattr(s, "graph_peer_limit", 40) or 40),
        "suppress_noise_in_queue": bool(getattr(s, "suppress_noise_in_queue", False)),
        "llm_effort": (getattr(s, "llm_effort", None) or "low"),
        "notify_min_risk_score": getattr(s, "notify_min_risk_score", None),
    }
