"""Encrypt sensitive lab_settings values at rest (Fernet from AUTH_SECRET)."""

from __future__ import annotations

import base64
import hashlib
import logging

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import get_settings

logger = logging.getLogger("darkgreen-siem.secrets")

ENC_PREFIX = "enc:"
_SENSITIVE_KEYS = frozenset(
    {
        "vt_api_key",
        "abuseipdb_api_key",
        "otx_api_key",
        "notify_webhook_url",
        "llm_api_key",
    }
)


def is_sensitive_key(key: str) -> bool:
    return key in _SENSITIVE_KEYS


def _fernet() -> Fernet:
    secret = (get_settings().auth_secret or "").encode("utf-8")
    key_material = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"darkgreen-siem-lab-settings-v1",
        info=b"lab-settings-fernet",
    ).derive(secret)
    return Fernet(base64.urlsafe_b64encode(key_material))


def seal(plaintext: str) -> str:
    text = plaintext or ""
    if not text:
        return ""
    if text.startswith(ENC_PREFIX):
        return text
    token = _fernet().encrypt(text.encode("utf-8")).decode("ascii")
    return f"{ENC_PREFIX}{token}"


def unseal(value: str) -> str:
    text = value or ""
    if not text:
        return ""
    if not text.startswith(ENC_PREFIX):
        return text
    raw = text[len(ENC_PREFIX) :]
    try:
        return _fernet().decrypt(raw.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError) as exc:
        logger.warning("Failed to decrypt lab setting: %s", type(exc).__name__)
        return ""


def fingerprint(value: str) -> str:
    """Stable non-reversible short id for logging (not for auth)."""
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
