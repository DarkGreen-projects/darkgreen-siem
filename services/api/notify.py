"""Outbound alert notifications (Slack / Teams webhooks)."""

from __future__ import annotations

import logging
from typing import Any

from .lab_settings import get_lab_state

logger = logging.getLogger("darkgreen-siem.notify")

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _meets_min_severity(severity: str, minimum: str) -> bool:
    return _SEV_RANK.get((severity or "").lower(), 0) >= _SEV_RANK.get(
        (minimum or "high").lower(), 3
    )


def _slack_payload(alert: Any) -> dict[str, Any]:
    mitre = getattr(alert, "mitre", None) or (alert.evidence or {}).get("mitre") or ""
    risk = getattr(alert, "risk_score", None)
    noise = getattr(alert, "noise_hint", None)
    extra = ""
    if risk is not None or noise:
        extra = f" · risk={risk if risk is not None else 'n/a'} noise={noise or 'n/a'}"
    text = (
        f"*[{(alert.severity or '').upper()}]* {alert.title}\n"
        f"Rule `{alert.rule_id}` · status `{alert.status}`"
        + (f" · MITRE `{mitre}`" if mitre else "")
        + extra
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
    if getattr(alert, "risk_score", None) is not None:
        facts.append({"name": "Risk", "value": str(alert.risk_score)})
    if getattr(alert, "noise_hint", None):
        facts.append({"name": "Noise", "value": str(alert.noise_hint)})
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
    min_risk = getattr(state, "notify_min_risk_score", None)
    if min_risk is not None:
        risk = getattr(alert, "risk_score", None)
        if risk is None or int(risk) < int(min_risk):
            return False
    fmt = (getattr(state, "notify_format", None) or "slack").strip().lower()
    payload = _teams_payload(alert) if fmt == "teams" else _slack_payload(alert)
    try:
        from .url_safety import UnsafeUrlError, egress_post

        resp = egress_post(url, purpose="notify webhook", timeout=5.0, json=payload)
        if resp.status_code >= 400:
            logger.warning("Notify webhook HTTP %s", resp.status_code)
            return False
        return True
    except UnsafeUrlError:
        logger.warning("Notify webhook URL rejected")
        return False
    except Exception as exc:
        logger.warning("Notify webhook failed: %s", type(exc).__name__)
        return False
