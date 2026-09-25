"""Lab authentication: demo/DB login + Bearer tokens + machine API token + RBAC."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Annotated, Callable

from fastapi import Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings, get_settings
from .db import get_db
from .models import Tenant, User
from .rbac import ROLES, hash_password, role_allows, verify_password

TOKEN_TTL_SEC = 12 * 60 * 60  # 12 hours


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class LoginResponse(BaseModel):
    token: str
    expires_at: int
    username: str
    role: str = "viewer"
    tenant_id: str = "lab"


class MeResponse(BaseModel):
    username: str
    kind: str  # user | machine | disabled | public
    role: str = "viewer"
    tenant_id: str = "lab"
    tenant_name: str | None = None


@dataclass
class AuthPrincipal:
    username: str
    kind: str
    role: str = "viewer"
    tenant_id: str = "lab"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def issue_user_token(
    settings: Settings,
    username: str,
    *,
    role: str = "analyst",
    tenant_id: str = "lab",
    ttl: int = TOKEN_TTL_SEC,
) -> tuple[str, int]:
    exp = int(time.time()) + ttl
    # username|role|tenant_id|exp
    payload = f"{username}|{role}|{tenant_id}|{exp}".encode("utf-8")
    sig = hmac.new(settings.auth_secret.encode("utf-8"), payload, hashlib.sha256).digest()
    token = f"{_b64url(payload)}.{_b64url(sig)}"
    return token, exp


def verify_user_token(settings: Settings, token: str) -> tuple[str, str, str] | None:
    """Return (username, role, tenant_id) or None."""
    try:
        body_b64, sig_b64 = token.split(".", 1)
        payload = _b64url_decode(body_b64)
        expected = hmac.new(settings.auth_secret.encode("utf-8"), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64url_decode(sig_b64)):
            return None
        text = payload.decode("utf-8")
        parts = text.split("|")
        if len(parts) == 2:
            # legacy username|exp
            username, exp_s = parts
            role, tenant_id = "analyst", settings.default_tenant_id
        elif len(parts) == 4:
            username, role, tenant_id, exp_s = parts
        else:
            return None
        if int(exp_s) < int(time.time()):
            return None
        if not username:
            return None
        if role not in ROLES:
            role = "viewer"
        return username, role, tenant_id or settings.default_tenant_id
    except Exception:
        return None


def check_password(settings: Settings, username: str, password: str) -> bool:
    """Env fallback when DB users not used."""
    user_ok = hmac.compare_digest(username.encode("utf-8"), settings.demo_username.encode("utf-8"))
    pass_ok = hmac.compare_digest(password.encode("utf-8"), settings.demo_password.encode("utf-8"))
    return user_ok and pass_ok


def authenticate_user(db: Session, settings: Settings, username: str, password: str) -> User | None:
    row = db.scalar(select(User).where(User.username == username))
    if row is not None:
        if not row.active:
            return None
        if verify_password(password, row.password_hash):
            return row
        return None
    # Fallback env demo → ensure bootstrap-compatible login without DB row
    if check_password(settings, username, password):
        return User(
            username=settings.demo_username,
            password_hash="",
            role="admin",
            tenant_id=settings.default_tenant_id,
            active=True,
        )
    return None


def bootstrap_auth(db: Session, settings: Settings) -> None:
    """Ensure default tenant + demo admin + viewer exist."""
    tid = settings.default_tenant_id or "lab"
    if db.get(Tenant, tid) is None:
        db.add(Tenant(id=tid, name=settings.default_tenant_name or "Lab"))
        db.flush()
    demo = db.scalar(select(User).where(User.username == settings.demo_username))
    if demo is None:
        db.add(
            User(
                username=settings.demo_username,
                password_hash=hash_password(settings.demo_password),
                role="admin",
                tenant_id=tid,
                active=True,
            )
        )
    viewer = db.scalar(select(User).where(User.username == "viewer"))
    if viewer is None:
        db.add(
            User(
                username="viewer",
                password_hash=hash_password("viewer"),
                role="viewer",
                tenant_id=tid,
                active=True,
            )
        )
    db.commit()


PUBLIC_PATHS = frozenset(
    {
        "/health",
        "/api/auth/login",
        "/docs",
        "/openapi.json",
        "/redoc",
    }
)


def require_auth(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
) -> AuthPrincipal:
    if request.url.path in PUBLIC_PATHS:
        return AuthPrincipal(username="public", kind="public", role="viewer", tenant_id="lab")
    if not settings.auth_enabled:
        if not settings.allow_insecure_no_auth:
            raise HTTPException(
                status_code=503,
                detail="AUTH_ENABLED=false requires ALLOW_INSECURE_NO_AUTH=true",
            )
        return AuthPrincipal(
            username="anonymous",
            kind="disabled",
            role="admin",
            tenant_id=settings.default_tenant_id,
        )

    raw = (authorization or "").strip()
    if not raw.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = raw[7:].strip()
    if not token:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if settings.siem_api_token and secrets.compare_digest(token, settings.siem_api_token):
        return AuthPrincipal(
            username="machine",
            kind="machine",
            role="ingest",
            tenant_id=settings.default_tenant_id,
        )

    parsed = verify_user_token(settings, token)
    if parsed:
        username, role, tenant_id = parsed
        row = db.scalar(select(User).where(User.username == username))
        if row is None:
            # Env-fallback demo user only when matching DEMO_USERNAME and no users table yet
            # Reject deleted/unknown users so tokens cannot outlive the account.
            any_user = db.scalar(select(User.id).limit(1))
            if any_user is not None:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid or expired token",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            # Empty users table: allow token claims (bootstrap race)
            return AuthPrincipal(username=username, kind="user", role=role, tenant_id=tenant_id)
        if not row.active:
            raise HTTPException(status_code=401, detail="User disabled")
        return AuthPrincipal(
            username=row.username, kind="user", role=row.role, tenant_id=row.tenant_id
        )

    raise HTTPException(
        status_code=401,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_perm(perm: str) -> Callable:
    def _dep(principal: AuthPrincipal = Depends(require_auth)) -> AuthPrincipal:
        if principal.kind == "public":
            return principal
        if principal.kind == "disabled":
            return principal
        if not role_allows(principal.role, perm):
            raise HTTPException(status_code=403, detail=f"Missing permission: {perm}")
        return principal

    return _dep
