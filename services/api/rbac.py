"""Password hashing and RBAC helpers (stdlib only)."""

from __future__ import annotations

import hashlib
import hmac
import secrets

ROLES = frozenset({"admin", "analyst", "viewer", "ingest"})

# permission -> roles that have it
PERMS: dict[str, frozenset[str]] = {
    "search": frozenset({"admin", "analyst", "viewer"}),
    "alerts_write": frozenset({"admin", "analyst"}),
    "rules_write": frozenset({"admin", "analyst"}),
    "enrich": frozenset({"admin", "analyst"}),
    "setup": frozenset({"admin"}),
    "purge": frozenset({"admin"}),
    "ingest": frozenset({"admin", "ingest"}),
}


def hash_password(password: str, *, iterations: int = 120_000) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations
    )
    return f"pbkdf2_sha256${iterations}${salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iter_s, salt, digest = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iter_s)
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations
        )
        return hmac.compare_digest(dk.hex(), digest)
    except Exception:
        return False


def role_allows(role: str, perm: str) -> bool:
    allowed = PERMS.get(perm)
    if not allowed:
        return False
    return (role or "").lower() in allowed
