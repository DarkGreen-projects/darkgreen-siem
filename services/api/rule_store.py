"""YAML rule file persistence (no DB imports)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .rule_validate import validate_rule_payload


def load_rules(rules_dir: str | Path) -> list[dict[str, Any]]:
    root = Path(rules_dir)
    if not root.exists():
        return []
    rules: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.yml")) + sorted(root.glob("*.yaml")):
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if not isinstance(data, dict):
            continue
        data.setdefault("id", path.stem)
        data.setdefault("enabled", True)
        data["_path"] = str(path)
        rules.append(data)
    return rules


def get_rule(rules_dir: str | Path, rule_id: str) -> dict[str, Any] | None:
    rid = rule_id.strip().lower()
    for rule in load_rules(rules_dir):
        if str(rule.get("id") or "").lower() == rid:
            return rule
    return None


def save_rule(
    rules_dir: str | Path,
    data: dict[str, Any],
    *,
    overwrite: bool = False,
) -> dict[str, Any]:
    from .rule_validate import RuleConflictError

    rule = validate_rule_payload(data)
    root = Path(rules_dir)
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{rule['id']}.yml"
    if path.exists() and not overwrite:
        raise RuleConflictError(f"Rule already exists: {rule['id']}")
    with path.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(rule, fh, sort_keys=False, allow_unicode=True, default_flow_style=False)
    saved = dict(rule)
    saved["_path"] = str(path)
    return saved


def delete_rule(rules_dir: str | Path, rule_id: str) -> None:
    rid = rule_id.strip().lower()
    path = Path(rules_dir) / f"{rid}.yml"
    if not path.exists():
        alt = Path(rules_dir) / f"{rid}.yaml"
        if alt.exists():
            path = alt
        else:
            raise FileNotFoundError(f"Rule not found: {rid}")
    path.unlink()


def set_rule_enabled(rules_dir: str | Path, rule_id: str, enabled: bool) -> dict[str, Any]:
    existing = get_rule(rules_dir, rule_id)
    if existing is None:
        raise FileNotFoundError(f"Rule not found: {rule_id}")
    payload = {k: v for k, v in existing.items() if not str(k).startswith("_")}
    payload["enabled"] = bool(enabled)
    return save_rule(rules_dir, payload, overwrite=True)
