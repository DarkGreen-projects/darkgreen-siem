"""VirusTotal enrichment (thin wrapper around enrich_providers)."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from .config import Settings
from .enrich_providers import _classify, enrich_ioc  # noqa: F401
from .lab_settings import get_lab_state


def enrich_vt(
    db: Session,
    settings: Settings,
    *,
    ioc_type: str,
    value: str,
    tenant_id: str = "lab",
) -> dict[str, Any]:
    state = get_lab_state()
    if not state.vt_api_key and (settings.vt_api_key or "").strip():
        state.vt_api_key = settings.vt_api_key.strip()
    result = enrich_ioc(
        db,
        provider="vt",
        ioc_type=ioc_type,
        value=value,
        state=state,
        tenant_id=tenant_id,
    )
    return {
        "available": result.get("available", False),
        "cached": result.get("cached", False),
        "ioc_type": result.get("ioc_type"),
        "value": result.get("value"),
        "verdict": result.get("verdict"),
        "malicious_count": result.get("malicious_count", 0),
        "stats": result.get("stats") or {},
        "fetched_at": result.get("fetched_at"),
        "message": result.get("message"),
        "error": result.get("error"),
    }
