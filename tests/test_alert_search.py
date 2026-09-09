"""Tests for alert text/comment search term extraction."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.api.query_parse import search_terms_from_query
from services.api.schemas import ALERT_STATUSES


def test_search_terms_free_text_and_fields():
    terms = search_terms_from_query("action:deny phishing")
    assert "deny" in terms
    assert "phishing" in terms


def test_search_terms_phrase():
    terms = search_terms_from_query("credential stuffing notes")
    assert "credential" in terms or "credential stuffing notes" in terms
    assert "stuffing" in terms or "notes" in terms


def test_alert_statuses():
    assert ALERT_STATUSES == frozenset({"open", "acked", "in_progress", "closed"})
