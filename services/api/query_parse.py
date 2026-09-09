"""Simple field:value AND query parser for demo SIEM search."""

from __future__ import annotations

import re

_TOKEN_RE = re.compile(
    r'(?P<field>[a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(?P<value>"[^"]+"|\S+)|(?P<free>"[^"]+"|\S+)'
)


def parse_query(q: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Return (field_filters, free_terms)."""
    field_filters: list[tuple[str, str]] = []
    free_terms: list[str] = []
    if not q or not q.strip():
        return field_filters, free_terms

    cleaned = re.sub(r"\bAND\b", " ", q, flags=re.IGNORECASE)
    for match in _TOKEN_RE.finditer(cleaned):
        if match.group("field"):
            field = match.group("field").lower()
            value = match.group("value").strip('"')
            field_filters.append((field, value))
        else:
            term = (match.group("free") or "").strip('"')
            if term.upper() == "AND":
                continue
            if term:
                free_terms.append(term)
    return field_filters, free_terms


def search_terms_from_query(q: str) -> list[str]:
    """Build text terms used to match alerts/comments (free-text + field values)."""
    if not q or not q.strip():
        return []
    field_filters, free_terms = parse_query(q)
    terms = list(free_terms)
    for _field, value in field_filters:
        if value and value not in terms:
            terms.append(value)
    cleaned = q.strip()
    if cleaned and cleaned not in terms and ":" not in cleaned:
        terms.append(cleaned)
    return terms
