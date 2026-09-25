"""Outbound alert notifications (Slack / Teams webhooks)."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from .lab_settings import get_lab_state

logger = logging.getLogger("darkgreen-siem.notify")

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _meets_min_severity(severity: str, minimum: str) -> bool:
    return _SEV_RANK.get((severity or "").lower(), 0) >= _SEV_RANK.get(
        (minimum or "high").lower(), 3
    )


def _slack_payload(alert: Any) -> dict[str, Any]:
    mitre = getattr(alert, "mitre", None) or (alert.evidence or {}).get("mitre") or ""
    text = (
        f"*[{(alert.severity or '').upper()}]* {alert.title}\n"
        f"Rule `{alert.rule_id}` · status `{alert.status}`"
        + (f" · MITRE `{mitre}`" if mitre else "")
        + f"\n{alert.description or ''}"
    )
    return {"text": text}


def _teams_payload(alert: Any) -> dict[str, Any]:
    mitre = getattr(alert, "mitre", None) or (alert.evidence or {}).get("mitre") or ""
    facts = [
        {"name": "Severity", "value": alert.severity or ""},
        {"name": "Rule", "value": alert.rule_id or ""},
        {"name": "Status", "value": alert.status or ""},
    ]
    if mitre:
        facts.append({"name": "MITRE", "value": str(mitre)})
    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": alert.title or alert.rule_id,
        "themeColor": "D70000" if (alert.severity or "") == "critical" else "FF8C00",
        "title": alert.title or alert.rule_name,
        "sections": [
            {
                "activitySubtitle": alert.description or "",
                "facts": facts,
            }
        ],
    }


def notify_alert_opened(alert: Any) -> bool:
    """POST webhook for newly opened critical/high alerts. Soft-fail on errors."""
    state = get_lab_state()
    url = (getattr(state, "notify_webhook_url", None) or "").strip()
    if not url:
        return False
    if (alert.status or "open").lower() != "open":
        return False
    min_sev = getattr(state, "notify_min_severity", None) or "high"
    if not _meets_min_severity(alert.severity or "info", min_sev):
        return False
    fmt = (getattr(state, "notify_format", None) or "slack").strip().lower()
    payload = _teams_payload(alert) if fmt == "teams" else _slack_payload(alert)
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(url, json=payload)
            if resp.status_code >= 400:
                logger.warning("Notify webhook HTTP %s: %s", resp.status_code, resp.text[:200])
                return False
        return True
    except Exception as exc:
        logger.warning("Notify webhook failed: %s", exc)
        return False
