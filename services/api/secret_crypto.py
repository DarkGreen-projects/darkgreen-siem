"""Encrypt sensitive lab_settings values at rest (Fernet from AUTH_SECRET)."""

from __future__ import annotations

import base64
import hashlib
import logging
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import select
from sqlalchemy.orm import Session

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


def _fernet_for(secret: str) -> Fernet:
    key_material = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"darkgreen-siem-lab-settings-v1",
        info=b"lab-settings-fernet",
    ).derive((secret or "").encode("utf-8"))
    return Fernet(base64.urlsafe_b64encode(key_material))


def _fernet() -> Fernet:
    return _fernet_for(get_settings().auth_secret or "")


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


def reseal_with_new_secret(
    db: Session, *, old_secret: str, new_secret: str
) -> int:
    """
    Re-encrypt sensitive LabSetting rows after AUTH_SECRET rotation.
    Returns number of keys resealed. Does not change process AUTH_SECRET.
    """
    from .models import LabSetting

    if not (old_secret or "").strip() or not (new_secret or "").strip():
        raise ValueError("old_secret and new_secret required")
    if old_secret == new_secret:
        return 0

    old_f = _fernet_for(old_secret)
    new_f = _fernet_for(new_secret)
    n = 0
    for row in db.scalars(select(LabSetting)).all():
        if not is_sensitive_key(row.key):
            continue
        val = row.value or ""
        if not val.startswith(ENC_PREFIX):
            continue
        raw = val[len(ENC_PREFIX) :]
        try:
            plain = old_f.decrypt(raw.encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError):
            logger.warning("Skipping reseal for key=%s (decrypt failed)", row.key)
            continue
        token = new_f.encrypt(plain.encode("utf-8")).decode("ascii")
        row.value = f"{ENC_PREFIX}{token}"
        n += 1
    return n
