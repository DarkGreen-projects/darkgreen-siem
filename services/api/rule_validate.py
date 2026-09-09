"""Pure rule validation helpers (no DB imports)."""

from __future__ import annotations

import re
from typing import Any

RULE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,62}$")
ALLOWED_GROUP_BY = frozenset({"user", "src_ip", "host", "action", "source_type"})
ALLOWED_TYPES = frozenset({"match", "threshold"})
ALLOWED_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})


class RuleValidationError(ValueError):
    pass


class RuleConflictError(FileExistsError):
    pass


def validate_rule_payload(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize and validate a rule dict for persistence. Raises RuleValidationError."""
    rule_id = str(data.get("id") or "").strip().lower()
    if not RULE_ID_RE.match(rule_id):
        raise RuleValidationError(
            "id must be a slug: start with a-z0-9, then a-z0-9_- (2-63 chars)"
        )

    name = str(data.get("name") or "").strip()
    if not name:
        raise RuleValidationError("name is required")

    rtype = str(data.get("type") or "match").strip().lower()
    if rtype not in ALLOWED_TYPES:
        raise RuleValidationError("type must be match or threshold")

    severity = str(data.get("severity") or "medium").strip().lower()
    if severity not in ALLOWED_SEVERITIES:
        raise RuleValidationError(
            f"severity must be one of: {', '.join(sorted(ALLOWED_SEVERITIES))}"
        )

    match = data.get("match") or data.get("filters") or {}
    if not isinstance(match, dict) or not match:
        raise RuleValidationError("match filters are required (non-empty object)")
    clean_match: dict[str, Any] = {}
    for key, value in match.items():
        k = str(key).strip()
        if not k:
            continue
        if isinstance(value, list):
            clean_match[k] = [str(v) for v in value if str(v).strip()]
        else:
            v = str(value).strip()
            if v:
                clean_match[k] = v
    if not clean_match:
        raise RuleValidationError("match filters are required (non-empty object)")

    out: dict[str, Any] = {
        "id": rule_id,
        "name": name,
        "title": str(data.get("title") or name).strip() or name,
        "description": str(data.get("description") or "").strip(),
        "threat_brief": str(data.get("threat_brief") or "").strip(),
        "type": rtype,
        "severity": severity,
        "enabled": bool(data.get("enabled", True)),
        "window_minutes": max(1, int(data.get("window_minutes") or 10)),
        "cooldown_minutes": max(1, int(data.get("cooldown_minutes") or 15)),
        "match": clean_match,
    }

    if rtype == "threshold":
        threshold = int(data.get("threshold") or 0)
        if threshold < 1:
            raise RuleValidationError("threshold must be >= 1")
        group_by = str(data.get("group_by") or "user").strip()
        if group_by not in ALLOWED_GROUP_BY:
            raise RuleValidationError(
                f"group_by must be one of: {', '.join(sorted(ALLOWED_GROUP_BY))}"
            )
        out["threshold"] = threshold
        out["group_by"] = group_by

    if not out["threat_brief"]:
        del out["threat_brief"]
    if not out["description"]:
        del out["description"]

    return out
