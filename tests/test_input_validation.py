"""Tests for input limits and stricter rule validation."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.api.input_limits import escape_like
from services.api.rule_validate import RuleValidationError, validate_rule_id, validate_rule_payload
from services.api.schemas import CommentCreate


def test_escape_like():
    assert escape_like("a%b_c\\d") == "a\\%b\\_c\\\\d"


def test_validate_rule_id_ok():
    assert validate_rule_id("my-rule") == "my-rule"


def test_validate_rule_id_bad():
    with pytest.raises(RuleValidationError):
        validate_rule_id("../etc/passwd")


def test_match_key_allowlist():
    with pytest.raises(RuleValidationError, match="not allowed"):
        validate_rule_payload(
            {
                "id": "bad-key",
                "name": "x",
                "type": "match",
                "match": {"evil_field": "1"},
            }
        )


def test_comment_body_max():
    with pytest.raises(ValidationError):
        CommentCreate(body="x" * 4001)


def test_comment_strips_html():
    c = CommentCreate(body="<script>alert(1)</script>note")
    assert "<script>" not in c.body
    assert "note" in c.body


def test_comment_author_invalid():
    with pytest.raises(ValidationError):
        CommentCreate(body="ok", author="bad<script>")
