"""Normalize alert entity keys so join:/src_ip:/host:/user: align across rule types."""

from __future__ import annotations

from typing import Any


def _add(keys: list[str], seen: set[str], kind: str, value: Any) -> None:
    if value is None:
        return
    text = str(value).strip()
    if not text:
        return
    token = f"{kind}:{text}"
    if token not in seen:
        seen.add(token)
        keys.append(token)


def collect_entity_keys(evidence: dict[str, Any] | None) -> list[str]:
    """Return ordered unique entity keys derived from evidence/sample/join."""
    evidence = dict(evidence or {})
    keys: list[str] = []
    seen: set[str] = set()

    join_on = str(evidence.get("join_on") or "").strip()
    join_key = evidence.get("join_key")
    if join_key not in (None, ""):
        _add(keys, seen, "join", join_key)
        field = join_on if join_on in {"src_ip", "dst_ip", "host", "user"} else "src_ip"
        _add(keys, seen, field, join_key)

    if evidence.get("group_by") is not None and isinstance(evidence.get("sample"), dict):
        sample = evidence["sample"]
        if sample.get("key") is not None:
            gb = str(evidence["group_by"])
            _add(keys, seen, "group", f"{gb}={sample['key']}")
            if gb in {"src_ip", "dst_ip", "host", "user"}:
                _add(keys, seen, gb, sample["key"])

    sample = evidence.get("sample") if isinstance(evidence.get("sample"), dict) else {}
    for field in ("src_ip", "dst_ip", "host", "user"):
        _add(keys, seen, field, sample.get(field))

    labels = evidence.get("labels") if isinstance(evidence.get("labels"), dict) else {}
    for field in ("hash", "domain", "url"):
        _add(keys, seen, field, labels.get(field) if labels else None)

    # Preserve legacy primary if present and not already covered
    legacy = evidence.get("entity_key")
    if legacy and str(legacy) not in seen:
        keys.insert(0, str(legacy))
        seen.add(str(legacy))

    return keys


def primary_entity_key(evidence: dict[str, Any] | None, *, rule_id: str | None = None) -> str:
    """Stable primary key: prefer src_ip/host/user, else join, else group, else rule."""
    keys = collect_entity_keys(evidence)
    priority = ("src_ip:", "host:", "user:", "dst_ip:", "join:", "group:", "hash:", "domain:")
    for prefix in priority:
        for k in keys:
            if k.startswith(prefix):
                return k
    if keys:
        return keys[0]
    return f"rule:{rule_id or 'unknown'}"


def entity_keys_overlap(a: list[str] | None, b: list[str] | None) -> list[str]:
    sa = set(a or [])
    sb = set(b or [])
    return sorted(sa & sb)


def canonical_values(keys: list[str] | None) -> set[str]:
    """Strip kind prefix for loose IOC/IP matching across kinds."""
    out: set[str] = set()
    for k in keys or []:
        if ":" in k:
            out.add(k.split(":", 1)[1].lower())
        else:
            out.add(str(k).lower())
    return out


def apply_entity_normalization(evidence: dict[str, Any], *, rule_id: str | None = None) -> dict[str, Any]:
    """Mutate/return evidence with entity_key + entity_keys set."""
    ev = dict(evidence or {})
    keys = collect_entity_keys(ev)
    primary = primary_entity_key(ev, rule_id=rule_id)
    if primary not in keys:
        keys = [primary] + keys
    ev["entity_key"] = primary
    ev["entity_keys"] = keys
    return ev


def alert_entity_keys(alert: Any) -> list[str]:
    ev = dict(getattr(alert, "evidence", None) or {})
    keys = ev.get("entity_keys")
    if isinstance(keys, list) and keys:
        return [str(k) for k in keys]
    return collect_entity_keys(ev) or (
        [str(ev["entity_key"])] if ev.get("entity_key") else []
    )
