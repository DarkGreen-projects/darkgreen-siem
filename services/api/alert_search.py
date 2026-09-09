"""Alert comment search helpers."""

from __future__ import annotations

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .models import Alert, AlertComment
from .query_parse import search_terms_from_query


def search_alerts_by_text(
    db: Session, q: str, *, limit: int = 50
) -> list[tuple[Alert, str | None]]:
    """Return alerts matching title/description/comments, with matched comment snippet."""
    terms = search_terms_from_query(q)
    if not terms:
        return []

    clauses = []
    for term in terms:
        like = f"%{term}%"
        clauses.append(Alert.title.ilike(like))
        clauses.append(Alert.description.ilike(like))
        clauses.append(AlertComment.body.ilike(like))

    stmt = (
        select(Alert, AlertComment.body)
        .outerjoin(AlertComment, AlertComment.alert_id == Alert.id)
        .where(or_(*clauses))
        .order_by(Alert.created_at.desc())
        .limit(limit * 3)
    )
    rows = list(db.execute(stmt).all())

    # Deduplicate by alert id; prefer a matching comment snippet
    by_id: dict[int, tuple[Alert, str | None]] = {}
    for alert, comment_body in rows:
        existing = by_id.get(alert.id)
        snippet: str | None = None
        if comment_body:
            lower_body = comment_body.lower()
            if any(t.lower() in lower_body for t in terms):
                snippet = comment_body
            elif existing is None:
                # title/description hit; keep comment only if later match
                snippet = None
        if existing is None:
            by_id[alert.id] = (alert, snippet)
        elif snippet and not existing[1]:
            by_id[alert.id] = (alert, snippet)
        if len(by_id) >= limit:
            break
    return list(by_id.values())[:limit]
