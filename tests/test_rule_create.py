"""Tests for rule payload validation and CRUD helpers."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.api.rule_store import delete_rule, save_rule, set_rule_enabled
from services.api.rule_validate import RuleValidationError, validate_rule_payload


def test_validate_rule_ok_match():
    rule = validate_rule_payload(
        {
            "id": "demo-deny",
            "name": "Demo deny",
            "type": "match",
            "severity": "medium",
            "match": {"source_type": "firewall", "action": "deny"},
        }
    )
    assert rule["id"] == "demo-deny"
    assert rule["type"] == "match"
    assert rule["match"]["action"] == "deny"


def test_validate_rule_list_match():
    rule = validate_rule_payload(
        {
            "id": "multi-src",
            "name": "Multi source",
            "type": "match",
            "match": {
                "source_type": ["firewall", "windows"],
                "action": ["deny", "malware_detected"],
            },
        }
    )
    assert rule["match"]["source_type"] == ["firewall", "windows"]
    assert rule["match"]["action"] == ["deny", "malware_detected"]


def test_validate_rule_ok_threshold():
    rule = validate_rule_payload(
        {
            "id": "burst-fails",
            "name": "Burst fails",
            "type": "threshold",
            "severity": "high",
            "threshold": 3,
            "group_by": "user",
            "match": {"action": "login_failed"},
        }
    )
    assert rule["threshold"] == 3
    assert rule["group_by"] == "user"


def test_validate_rule_rejects_bad_id():
    with pytest.raises(RuleValidationError, match="slug"):
        validate_rule_payload(
            {
                "id": "Bad ID!",
                "name": "x",
                "type": "match",
                "match": {"action": "deny"},
            }
        )


def test_validate_rule_requires_match():
    with pytest.raises(RuleValidationError, match="match"):
        validate_rule_payload({"id": "no-match", "name": "x", "type": "match", "match": {}})


def test_delete_rule_temp_dir(tmp_path: Path):
    save_rule(
        tmp_path,
        {
            "id": "temp-rule",
            "name": "Temp",
            "type": "match",
            "match": {"action": "deny"},
        },
    )
    path = tmp_path / "temp-rule.yml"
    assert path.exists()
    delete_rule(tmp_path, "temp-rule")
    assert not path.exists()
    with pytest.raises(FileNotFoundError):
        delete_rule(tmp_path, "temp-rule")


def test_set_rule_enabled_temp_dir(tmp_path: Path):
    save_rule(
        tmp_path,
        {
            "id": "toggle-me",
            "name": "Toggle",
            "type": "match",
            "enabled": True,
            "match": {"source_type": "firewall", "action": "deny"},
        },
    )
    updated = set_rule_enabled(tmp_path, "toggle-me", False)
    assert updated["enabled"] is False
    loaded = yaml.safe_load((tmp_path / "toggle-me.yml").read_text(encoding="utf-8"))
    assert loaded["enabled"] is False
