"""Multi-provider IOC enrichment with local TTL cache."""

from __future__ import annotations

import base64
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from .lab_settings import LabState, get_lab_state
from .models import IocVerdict

logger = logging.getLogger("darkgreen-siem.enrich")

ALLOWED_IOC_TYPES = frozenset({"ip", "domain", "url"})
ALLOWED_PROVIDERS = frozenset({"vt", "abuseipdb", "otx"})
VERDICTS = frozenset({"malicious", "suspicious", "harmless", "undetected", "unknown"})


def classify_vt_stats(stats: dict[str, Any]) -> tuple[str, int]:
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    harmless = int(stats.get("harmless") or 0)
    undetected = int(stats.get("undetected") or 0)
    if malicious > 0:
        return "malicious", malicious
    if suspicious > 0:
        return "suspicious", malicious
    if harmless > 0:
        return "harmless", malicious
    if undetected > 0:
        return "undetected", malicious
    return "unknown", malicious


def _ttl_hours(state: LabState) -> int:
    from .config import get_settings

    return max(1, int(get_settings().vt_cache_ttl_hours))


def _cache_get(
    db: Session,
    provider: str,
    ioc_type: str,
    value: str,
    ttl_hours: int,
    *,
    tenant_id: str = "lab",
) -> IocVerdict | None:
    row = db.scalar(
        select(IocVerdict)
        .where(
            and_(
                IocVerdict.provider == provider,
                IocVerdict.ioc_type == ioc_type,
                IocVerdict.value == value,
                IocVerdict.tenant_id == tenant_id,
            )
        )
        .order_by(IocVerdict.fetched_at.desc())
        .limit(1)
    )
    if row is None:
        return None
    fetched = row.fetched_at
    if fetched.tzinfo is None:
        fetched = fetched.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - fetched > timedelta(hours=ttl_hours):
        return None
    return row


def _provider_key(state: LabState, provider: str) -> str:
    if provider == "vt":
        return (state.vt_api_key or "").strip()
    if provider == "abuseipdb":
        return (state.abuseipdb_api_key or "").strip()
    if provider == "otx":
        return (state.otx_api_key or "").strip()
    return ""


def _vt_url(ioc_type: str, value: str) -> str:
    if ioc_type == "ip":
        return f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
    if ioc_type == "domain":
        return f"https://www.virustotal.com/api/v3/domains/{value}"
    encoded = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")
    return f"https://www.virustotal.com/api/v3/urls/{encoded}"


def _fetch_vt(api_key: str, ioc_type: str, value: str) -> tuple[str, int, dict[str, Any]]:
    with httpx.Client(timeout=12.0) as client:
        resp = client.get(_vt_url(ioc_type, value), headers={"x-apikey": api_key})
    if resp.status_code == 404:
        return "undetected", 0, {}
    if resp.status_code >= 400:
        raise RuntimeError(f"VT HTTP {resp.status_code}")
    data = resp.json().get("data") or {}
    attrs = data.get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    verdict, mal = classify_vt_stats(stats if isinstance(stats, dict) else {})
    return verdict, mal, dict(stats) if isinstance(stats, dict) else {}


def _fetch_abuseipdb(api_key: str, ioc_type: str, value: str) -> tuple[str, int, dict[str, Any]]:
    if ioc_type != "ip":
        return "unknown", 0, {"skipped": "abuseipdb supports ip only"}
    with httpx.Client(timeout=12.0) as client:
        resp = client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": value, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
        )
    if resp.status_code >= 400:
        raise RuntimeError(f"AbuseIPDB HTTP {resp.status_code}")
    data = (resp.json().get("data") or {}) if resp.content else {}
    score = int(data.get("abuseConfidenceScore") or 0)
    if score >= 75:
        verdict = "malicious"
    elif score >= 25:
        verdict = "suspicious"
    else:
        verdict = "harmless"
    return verdict, score, {"abuseConfidenceScore": score, "totalReports": data.get("totalReports")}


def _fetch_otx(api_key: str, ioc_type: str, value: str) -> tuple[str, int, dict[str, Any]]:
    if ioc_type == "ip":
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{value}/general"
    elif ioc_type == "domain":
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{value}/general"
    else:
        return "unknown", 0, {"skipped": "otx supports ip/domain"}
    with httpx.Client(timeout=12.0) as client:
        resp = client.get(url, headers={"X-OTX-API-KEY": api_key})
    if resp.status_code == 404:
        return "undetected", 0, {}
    if resp.status_code >= 400:
        raise RuntimeError(f"OTX HTTP {resp.status_code}")
    data = resp.json() if resp.content else {}
    pulse = int((data.get("pulse_info") or {}).get("count") or 0)
    if pulse >= 3:
        verdict = "malicious"
    elif pulse >= 1:
        verdict = "suspicious"
    else:
        verdict = "harmless"
    return verdict, pulse, {"pulse_count": pulse}


def _fetch(provider: str, api_key: str, ioc_type: str, value: str) -> tuple[str, int, dict[str, Any]]:
    if provider == "vt":
        return _fetch_vt(api_key, ioc_type, value)
    if provider == "abuseipdb":
        return _fetch_abuseipdb(api_key, ioc_type, value)
    if provider == "otx":
        return _fetch_otx(api_key, ioc_type, value)
    raise RuntimeError(f"unknown provider {provider}")


def enrich_ioc(
    db: Session,
    *,
    provider: str,
    ioc_type: str,
    value: str,
    state: LabState | None = None,
    fetch: bool = True,
    tenant_id: str = "lab",
) -> dict[str, Any]:
    provider = (provider or "").strip().lower()
    ioc_type = (ioc_type or "").strip().lower()
    value = (value or "").strip()
    state = state or get_lab_state()
    tid = tenant_id or "lab"

    if provider not in ALLOWED_PROVIDERS:
        return {"provider": provider, "available": False, "error": "invalid provider"}
    if ioc_type not in ALLOWED_IOC_TYPES or not value:
        return {
            "provider": provider,
            "available": False,
            "error": "invalid ioc type or value",
        }

    api_key = _provider_key(state, provider)
    if not api_key:
        return {
            "provider": provider,
            "available": False,
            "cached": False,
            "ioc_type": ioc_type,
            "value": value,
            "message": f"{provider} API key not configured",
        }

    ttl = _ttl_hours(state)
    cached = _cache_get(db, provider, ioc_type, value, ttl, tenant_id=tid)
    if cached is not None:
        return {
            "provider": provider,
            "available": True,
            "cached": True,
            "ioc_type": ioc_type,
            "value": value,
            "verdict": cached.verdict,
            "malicious_count": int(cached.malicious_count or 0),
            "stats": cached.stats_json or {},
            "fetched_at": cached.fetched_at.isoformat() if cached.fetched_at else None,
        }

    if not fetch:
        return {
            "provider": provider,
            "available": True,
            "cached": False,
            "ioc_type": ioc_type,
            "value": value,
            "verdict": None,
            "message": "cache miss",
        }

    try:
        verdict, mal, stats = _fetch(provider, api_key, ioc_type, value)
    except Exception as exc:
        logger.warning("%s enrich failed: %s", provider, exc)
        return {
            "provider": provider,
            "available": True,
            "cached": False,
            "error": str(exc),
            "ioc_type": ioc_type,
            "value": value,
            "verdict": "unknown",
            "malicious_count": 0,
        }

    now = datetime.now(timezone.utc)
    row = IocVerdict(
        tenant_id=tid,
        provider=provider,
        ioc_type=ioc_type,
        value=value,
        verdict=verdict,
        malicious_count=mal,
        stats_json=stats,
        fetched_at=now,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {
        "provider": provider,
        "available": True,
        "cached": False,
        "ioc_type": ioc_type,
        "value": value,
        "verdict": row.verdict,
        "malicious_count": int(row.malicious_count or 0),
        "stats": row.stats_json or {},
        "fetched_at": row.fetched_at.isoformat() if row.fetched_at else None,
    }


def enrich_multi(
    db: Session,
    *,
    ioc_type: str,
    value: str,
    providers: list[str] | None = None,
    state: LabState | None = None,
    tenant_id: str = "lab",
) -> dict[str, Any]:
    state = state or get_lab_state()
    wanted = providers or ["vt", "abuseipdb", "otx"]
    results = []
    for p in wanted:
        p = p.strip().lower()
        if p not in ALLOWED_PROVIDERS:
            continue
        results.append(
            enrich_ioc(
                db,
                provider=p,
                ioc_type=ioc_type,
                value=value,
                state=state,
                tenant_id=tenant_id,
            )
        )
    return {"ioc_type": ioc_type, "value": value, "results": results}


def keys_matching_enrich(
    db: Session,
    keys: set[str],
    *,
    providers: list[str],
    verdicts: list[str],
    ioc_type: str = "ip",
    state: LabState | None = None,
    tenant_id: str = "lab",
) -> set[str]:
    """Return keys that have at least one matching enrich verdict (cache + optional fetch)."""
    state = state or get_lab_state()
    wanted_verdicts = {v.lower() for v in verdicts} or {"malicious", "suspicious"}
    matched: set[str] = set()
    for key in keys:
        for provider in providers:
            res = enrich_ioc(
                db,
                provider=provider,
                ioc_type=ioc_type,
                value=key,
                state=state,
                fetch=True,
                tenant_id=tenant_id,
            )
            if res.get("available") and (res.get("verdict") or "").lower() in wanted_verdicts:
                matched.add(key)
                break
    return matched


# Back-compat for older tests/imports
def _classify(stats: dict[str, Any]) -> tuple[str, int]:
    return classify_vt_stats(stats)
