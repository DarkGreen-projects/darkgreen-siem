"""Lab authentication: demo login + Bearer tokens + machine API token."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from .config import Settings, get_settings

TOKEN_TTL_SEC = 12 * 60 * 60  # 12 hours


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class LoginResponse(BaseModel):
    token: str
    expires_at: int
    username: str


class MeResponse(BaseModel):
    username: str
    kind: str  # user | machine | disabled


@dataclass
class AuthPrincipal:
    username: str
    kind: str


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def issue_user_token(settings: Settings, username: str, *, ttl: int = TOKEN_TTL_SEC) -> tuple[str, int]:
    exp = int(time.time()) + ttl
    payload = f"{username}|{exp}".encode("utf-8")
    sig = hmac.new(settings.auth_secret.encode("utf-8"), payload, hashlib.sha256).digest()
    token = f"{_b64url(payload)}.{_b64url(sig)}"
    return token, exp


def verify_user_token(settings: Settings, token: str) -> str | None:
    try:
        body_b64, sig_b64 = token.split(".", 1)
        payload = _b64url_decode(body_b64)
        expected = hmac.new(settings.auth_secret.encode("utf-8"), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64url_decode(sig_b64)):
            return None
        text = payload.decode("utf-8")
        username, exp_s = text.rsplit("|", 1)
        if int(exp_s) < int(time.time()):
            return None
        if not username:
            return None
        return username
    except Exception:
        return None


def check_password(settings: Settings, username: str, password: str) -> bool:
    user_ok = hmac.compare_digest(username.encode("utf-8"), settings.demo_username.encode("utf-8"))
    pass_ok = hmac.compare_digest(password.encode("utf-8"), settings.demo_password.encode("utf-8"))
    return user_ok and pass_ok


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
) -> AuthPrincipal:
    if request.url.path in PUBLIC_PATHS:
        return AuthPrincipal(username="public", kind="public")
    if not settings.auth_enabled:
        return AuthPrincipal(username="anonymous", kind="disabled")

    raw = (authorization or "").strip()
    if not raw.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Authentication required", headers={"WWW-Authenticate": "Bearer"})
    token = raw[7:].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required", headers={"WWW-Authenticate": "Bearer"})

    if settings.siem_api_token and secrets.compare_digest(token, settings.siem_api_token):
        return AuthPrincipal(username="machine", kind="machine")

    username = verify_user_token(settings, token)
    if username:
        return AuthPrincipal(username=username, kind="user")

    raise HTTPException(status_code=401, detail="Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
