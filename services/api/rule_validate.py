"""Pure rule validation helpers (no DB imports)."""

from __future__ import annotations

import re
from typing import Any

from .input_limits import (
    ALLOWED_MATCH_KEYS,
    MAX_COOLDOWN_MINUTES,
    MAX_MATCH_KEYS,
    MAX_MATCH_VALUE_LEN,
    MAX_RULE_NAME,
    MAX_RULE_TEXT,
    MAX_THRESHOLD,
    MAX_WINDOW_MINUTES,
)

RULE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,62}$")
MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$", re.I)
ALLOWED_GROUP_BY = frozenset({"user", "src_ip", "host", "action", "source_type", "event_id"})
ALLOWED_TYPES = frozenset({"match", "threshold", "correlation"})
ALLOWED_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
ALLOWED_ENRICH_PROVIDERS = frozenset({"vt", "abuseipdb", "otx"})
ALLOWED_ENRICH_VERDICTS = frozenset(
    {"malicious", "suspicious", "harmless", "undetected", "unknown"}
)
MAX_CORRELATION_STEPS = 4


class RuleValidationError(ValueError):
    pass


class RuleConflictError(FileExistsError):
    pass


def _normalize_mitre_field(data: dict[str, Any]) -> str | None:
    raw = data.get("mitre")
    if raw is None or raw == "" or raw == []:
        return None
    if isinstance(raw, list):
        parts = [str(x).strip() for x in raw if str(x).strip()]
    else:
        parts = [p.strip() for p in str(raw).split(",") if p.strip()]
    cleaned: list[str] = []
    for p in parts[:8]:
        if not MITRE_RE.match(p):
            raise RuleValidationError(f"mitre technique invalid: {p} (expect Txxxx or Txxxx.xxx)")
        cleaned.append(p.upper() if p.startswith(("t", "T")) else p)
    return ",".join(cleaned) if cleaned else None


def validate_rule_id(rule_id: str) -> str:
    rid = str(rule_id or "").strip().lower()
    if not RULE_ID_RE.match(rid):
        raise RuleValidationError(
            "id must be a slug: start with a-z0-9, then a-z0-9_- (2-63 chars)"
        )
    return rid


def _clean_match(match: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(match, dict) or not match:
        raise RuleValidationError("match filters are required (non-empty object)")
    if len(match) > MAX_MATCH_KEYS:
        raise RuleValidationError(f"match may have at most {MAX_MATCH_KEYS} keys")

    clean_match: dict[str, Any] = {}
    for key, value in match.items():
        k = str(key).strip()
        if not k:
            continue
        if k not in ALLOWED_MATCH_KEYS:
            raise RuleValidationError(
                f"match key '{k}' not allowed; use: {', '.join(sorted(ALLOWED_MATCH_KEYS))}"
            )
        if isinstance(value, list):
            vals = [str(v).strip()[:MAX_MATCH_VALUE_LEN] for v in value if str(v).strip()]
            if vals:
                clean_match[k] = vals
        else:
            v = str(value).strip()[:MAX_MATCH_VALUE_LEN]
            if v:
                clean_match[k] = v
    if not clean_match:
        raise RuleValidationError("match filters are required (non-empty object)")
    return clean_match


def validate_rule_payload(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize and validate a rule dict for persistence. Raises RuleValidationError."""
    rule_id = validate_rule_id(str(data.get("id") or ""))

    name = str(data.get("name") or "").strip()
    if not name:
        raise RuleValidationError("name is required")
    if len(name) > MAX_RULE_NAME:
        raise RuleValidationError(f"name must be <= {MAX_RULE_NAME} chars")

    rtype = str(data.get("type") or "match").strip().lower()
    if rtype not in ALLOWED_TYPES:
        raise RuleValidationError("type must be match, threshold, or correlation")

    severity = str(data.get("severity") or "medium").strip().lower()
    if severity not in ALLOWED_SEVERITIES:
        raise RuleValidationError(
            f"severity must be one of: {', '.join(sorted(ALLOWED_SEVERITIES))}"
        )

    description = str(data.get("description") or "").strip()[:MAX_RULE_TEXT]
    threat_brief = str(data.get("threat_brief") or "").strip()[:MAX_RULE_TEXT]
    mitre = _normalize_mitre_field(data)
    window = max(1, min(MAX_WINDOW_MINUTES, int(data.get("window_minutes") or 10)))
    cooldown = max(1, min(MAX_COOLDOWN_MINUTES, int(data.get("cooldown_minutes") or 15)))

    out: dict[str, Any] = {
        "id": rule_id,
        "name": name,
        "title": str(data.get("title") or name).strip()[:MAX_RULE_NAME] or name,
        "description": description,
        "threat_brief": threat_brief,
        "type": rtype,
        "severity": severity,
        "enabled": bool(data.get("enabled", True)),
        "window_minutes": window,
        "cooldown_minutes": cooldown,
    }
    if mitre:
        out["mitre"] = mitre

    if rtype == "correlation":
        join_on = str(data.get("join_on") or "src_ip").strip()
        if join_on not in ALLOWED_GROUP_BY:
            raise RuleValidationError(
                f"join_on must be one of: {', '.join(sorted(ALLOWED_GROUP_BY))}"
            )
        steps_raw = data.get("steps")
        if not isinstance(steps_raw, list) or len(steps_raw) < 2:
            raise RuleValidationError("correlation requires at least 2 steps")
        if len(steps_raw) > MAX_CORRELATION_STEPS:
            raise RuleValidationError(f"correlation may have at most {MAX_CORRELATION_STEPS} steps")
        clean_steps: list[dict[str, Any]] = []
        for i, step in enumerate(steps_raw):
            if not isinstance(step, dict):
                raise RuleValidationError(f"steps[{i}] must be an object")
            if "enrich" in step and step.get("enrich") is not None:
                enrich = step.get("enrich") or {}
                if not isinstance(enrich, dict):
                    raise RuleValidationError(f"steps[{i}].enrich must be an object")
                providers_raw = enrich.get("providers") or ["vt"]
                if isinstance(providers_raw, str):
                    providers_raw = [providers_raw]
                providers = []
                for p in providers_raw:
                    pl = str(p).strip().lower()
                    if pl not in ALLOWED_ENRICH_PROVIDERS:
                        raise RuleValidationError(
                            f"steps[{i}].enrich.providers invalid; use: "
                            f"{', '.join(sorted(ALLOWED_ENRICH_PROVIDERS))}"
                        )
                    providers.append(pl)
                if not providers:
                    raise RuleValidationError(f"steps[{i}].enrich.providers required")
                verdicts_raw = enrich.get("verdicts") or ["malicious", "suspicious"]
                if isinstance(verdicts_raw, str):
                    verdicts_raw = [verdicts_raw]
                verdicts = []
                for v in verdicts_raw:
                    vl = str(v).strip().lower()
                    if vl not in ALLOWED_ENRICH_VERDICTS:
                        raise RuleValidationError(
                            f"steps[{i}].enrich.verdicts invalid; use: "
                            f"{', '.join(sorted(ALLOWED_ENRICH_VERDICTS))}"
                        )
                    verdicts.append(vl)
                ioc_type = str(enrich.get("ioc_type") or "ip").strip().lower()
                if ioc_type not in {"ip", "domain", "url"}:
                    raise RuleValidationError(f"steps[{i}].enrich.ioc_type must be ip|domain|url")
                clean_steps.append(
                    {
                        "enrich": {
                            "providers": providers,
                            "verdicts": verdicts,
                            "ioc_type": ioc_type,
                        }
                    }
                )
            else:
                step_match = _clean_match(step.get("match") or {})
                min_count = int(step.get("min_count") or 1)
                if min_count < 1 or min_count > MAX_THRESHOLD:
                    raise RuleValidationError(f"steps[{i}].min_count must be 1..{MAX_THRESHOLD}")
                clean_steps.append({"match": step_match, "min_count": min_count})
        out["join_on"] = join_on
        out["steps"] = clean_steps
        # Keep a synthetic match for list/UI compatibility (first match step)
        first_match = next((s.get("match") for s in clean_steps if s.get("match")), {})
        out["match"] = first_match or {"source_type": "windows"}
    else:
        match = data.get("match") or data.get("filters") or {}
        out["match"] = _clean_match(match if isinstance(match, dict) else {})

        if rtype == "threshold":
            threshold = int(data.get("threshold") or 0)
            if threshold < 1 or threshold > MAX_THRESHOLD:
                raise RuleValidationError(f"threshold must be 1..{MAX_THRESHOLD}")
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
