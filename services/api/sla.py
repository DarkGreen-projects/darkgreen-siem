"""Alert SLA computation (ack + close targets per severity)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

SLA_SEVERITIES = ("critical", "high", "medium", "low")

DEFAULT_SLA_ACK_MINUTES: dict[str, int] = {
    "critical": 15,
    "high": 30,
    "medium": 240,
    "low": 1440,
}

DEFAULT_SLA_CLOSE_MINUTES: dict[str, int] = {
    "critical": 120,
    "high": 480,
    "medium": 1440,
    "low": 10080,
}

AT_RISK_RATIO = 0.8
MAX_SLA_MINUTES = 10080 * 4  # 28 days


def default_sla_ack() -> dict[str, int]:
    return dict(DEFAULT_SLA_ACK_MINUTES)


def default_sla_close() -> dict[str, int]:
    return dict(DEFAULT_SLA_CLOSE_MINUTES)


def normalize_sla_map(
    raw: Any,
    *,
    defaults: dict[str, int] | None = None,
) -> dict[str, int]:
    base = dict(defaults or DEFAULT_SLA_ACK_MINUTES)
    if raw is None:
        return base
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return base
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid SLA JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("SLA map must be an object of severity -> minutes")
    out = dict(base)
    for sev in SLA_SEVERITIES:
        if sev not in raw:
            continue
        try:
            minutes = int(raw[sev])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"SLA minutes for {sev} must be an integer") from exc
        if minutes < 0 or minutes > MAX_SLA_MINUTES:
            raise ValueError(f"SLA minutes for {sev} must be 0..{MAX_SLA_MINUTES}")
        out[sev] = minutes
    return out


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _status_for(
    *,
    target_minutes: int,
    start: datetime,
    done_at: datetime | None,
    now: datetime,
) -> dict[str, Any]:
    if target_minutes <= 0:
        return {
            "target_minutes": 0,
            "due_at": None,
            "elapsed_minutes": 0,
            "remaining_minutes": None,
            "status": "na",
        }
    due = start + timedelta(minutes=target_minutes)
    end = done_at or now
    elapsed = max(0, int((end - start).total_seconds() // 60))
    remaining = int((due - now).total_seconds() // 60) if done_at is None else None

    if done_at is not None:
        status = "met" if done_at <= due else "breached"
        remaining = None
    elif now >= due:
        status = "breached"
    elif (now - start).total_seconds() >= target_minutes * 60 * AT_RISK_RATIO:
        status = "at_risk"
    else:
        status = "ok"

    return {
        "target_minutes": target_minutes,
        "due_at": due,
        "elapsed_minutes": elapsed,
        "remaining_minutes": remaining,
        "status": status,
    }


def compute_alert_sla(
    alert: Any,
    *,
    ack_map: dict[str, int] | None = None,
    close_map: dict[str, int] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return flat sla_* fields for AlertOut."""
    now = _aware(now) or datetime.now(timezone.utc)
    created = _aware(getattr(alert, "created_at", None)) or now
    sev = (getattr(alert, "severity", None) or "medium").strip().lower()
    if sev not in SLA_SEVERITIES:
        sev = "medium"
    ack_minutes = int(
        (ack_map or DEFAULT_SLA_ACK_MINUTES).get(sev, DEFAULT_SLA_ACK_MINUTES["medium"])
    )
    close_minutes = int(
        (close_map or DEFAULT_SLA_CLOSE_MINUTES).get(sev, DEFAULT_SLA_CLOSE_MINUTES["medium"])
    )

    status = (getattr(alert, "status", None) or "open").strip().lower()
    acked_at = _aware(getattr(alert, "acked_at", None))
    closed_at = _aware(getattr(alert, "closed_at", None))

    if status == "open":
        ack_done = None
    else:
        ack_done = acked_at or created

    if status == "closed":
        close_done = closed_at or now
    else:
        close_done = None

    ack = _status_for(
        target_minutes=ack_minutes, start=created, done_at=ack_done, now=now
    )
    close = _status_for(
        target_minutes=close_minutes, start=created, done_at=close_done, now=now
    )

    return {
        "sla_ack_status": ack["status"],
        "sla_ack_target_minutes": ack["target_minutes"],
        "sla_ack_due_at": ack["due_at"],
        "sla_ack_elapsed_minutes": ack["elapsed_minutes"],
        "sla_ack_remaining_minutes": ack["remaining_minutes"],
        "sla_close_status": close["status"],
        "sla_close_target_minutes": close["target_minutes"],
        "sla_close_due_at": close["due_at"],
        "sla_close_elapsed_minutes": close["elapsed_minutes"],
        "sla_close_remaining_minutes": close["remaining_minutes"],
    }


def alert_matches_sla_filter(sla_fields: dict[str, Any], wanted: str) -> bool:
    w = wanted.strip().lower()
    if w not in {"breached", "at_risk", "met", "ok", "na"}:
        return True
    return sla_fields.get("sla_ack_status") == w or sla_fields.get("sla_close_status") == w
