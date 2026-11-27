"""Sliding-window rate limits with Postgres-backed fixed windows + memory fallback."""

from __future__ import annotations

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from .config import get_settings
from .input_limits import (
    INGEST_RATE_LIMIT,
    INGEST_RATE_WINDOW_SEC,
    LOGIN_RATE_LIMIT,
    LOGIN_RATE_WINDOW_SEC,
    MACHINE_INGEST_RATE_LIMIT,
    MACHINE_INGEST_RATE_WINDOW_SEC,
)
from .rate_buckets import allow_db, allow_memory, reset_memory_for_tests


def client_ip(request: Request) -> str:
    """
    Prefer nginx X-Real-IP, then peer address.
    Ignore X-Forwarded-For unless TRUST_X_FORWARDED_FOR=true (spoofable otherwise).
    """
    real_ip = (request.headers.get("x-real-ip") or "").strip()
    if real_ip:
        return real_ip.split(",")[0].strip()
    settings = get_settings()
    if getattr(settings, "trust_x_forwarded_for", False):
        forwarded = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
        if forwarded:
            return forwarded
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def enforce_login_rate(request: Request, db: Session | None = None) -> None:
    ip = client_ip(request)
    key = f"login:{ip}"
    ok = allow_db(
        db,
        key,
        limit=LOGIN_RATE_LIMIT,
        window_sec=LOGIN_RATE_WINDOW_SEC,
    )
    if not ok:
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts",
            headers={"Retry-After": str(int(LOGIN_RATE_WINDOW_SEC))},
        )


def enforce_ingest_rate(
    request: Request,
    *,
    identity: str,
    kind: str = "user",
    db: Session | None = None,
    tenant_id: str = "lab",
) -> None:
    ip = client_ip(request)
    if (kind or "").lower() == "machine":
        limit = MACHINE_INGEST_RATE_LIMIT
        window = MACHINE_INGEST_RATE_WINDOW_SEC
        key = f"ingest:machine:{identity}:{ip}"
    else:
        limit = INGEST_RATE_LIMIT
        window = INGEST_RATE_WINDOW_SEC
        key = f"ingest:{identity}:{ip}"
    ok = allow_db(db, key, limit=limit, window_sec=window, tenant_id=tenant_id)
    if not ok:
        raise HTTPException(
            status_code=429,
            detail="Ingest rate limit exceeded",
            headers={"Retry-After": str(int(window))},
        )


def enforce_copilot_llm_budget(
    *,
    tenant_id: str = "lab",
    db: Session | None = None,
    limit: int | None = None,
) -> bool:
    from .input_limits import COPILOT_LLM_BUDGET_PER_MIN

    cap = limit if limit is not None else COPILOT_LLM_BUDGET_PER_MIN
    return allow_db(
        db,
        f"copilot_llm:{tenant_id}",
        limit=cap,
        window_sec=60.0,
        tenant_id=tenant_id,
    )


def reset_limiters_for_tests() -> None:
    """Clear memory buckets (tests only)."""
    reset_memory_for_tests()
