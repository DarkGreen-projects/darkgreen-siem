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
