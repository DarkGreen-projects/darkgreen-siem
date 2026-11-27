"""Portable Alert Memory RAG: index closed alerts and hybrid retrieve (FTS + boosts)."""

from __future__ import annotations

import logging
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, func, select, text
from sqlalchemy.orm import Session

from .models import Alert, AlertMemory
from .triage_score import find_similar_alerts

logger = logging.getLogger("darkgreen-siem.rag")

NOTE_MAX = 500
CASE_NOTE_MAX = 200
BACKFILL_CAP = 2000

_INJECTION_RE = re.compile(
    r"(ignore\s+previous|system\s*prompt|javascript:|<script|```\s*system)",
    re.IGNORECASE,
)
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def sanitize_closure_note(note: str) -> tuple[str, bool]:
    """Strip HTML/control chars and injection-ish patterns. Returns (text, sanitized)."""
    raw = (note or "").strip()
    if not raw:
        return "", False
    sanitized = False
    text = _CTRL_RE.sub("", raw)
    text = re.sub(r"<[^>]+>", " ", text)
    text = text.replace("javascript:", "")
    if _INJECTION_RE.search(text):
        text = _INJECTION_RE.sub("[redacted]", text)
        sanitized = True
        text = text[: min(120, NOTE_MAX)]
    # Reject near-spam (same char repeated)
    if len(set(text.replace(" ", ""))) <= 2 and len(text) >= 10:
        return "nota rumore lab (spam ridotto)", True
    text = " ".join(text.split())
    if text != raw:
        sanitized = True
    return text[:NOTE_MAX], sanitized


def _entity_key(alert: Alert) -> str | None:
    from .entity_norm import alert_entity_keys

    keys = alert_entity_keys(alert)
    return keys[0] if keys else None


def _entity_keys(alert: Alert) -> list[str]:
    from .entity_norm import alert_entity_keys

    return alert_entity_keys(alert)


def _build_memory_text(
    *,
    title: str,
    rule_id: str,
    entity_key: str | None,
    mitre: str | None,
    note: str,
) -> str:
    parts = [
        title or "",
        rule_id or "",
        entity_key or "",
        mitre or "",
        note or "",
    ]
    return "\n".join(p.strip() for p in parts if p and str(p).strip())


def upsert_alert_memory(db: Session, alert: Alert) -> AlertMemory | None:
    """Index a closed alert into alert_memory. No-op if missing disposition/note."""
    if (alert.status or "").lower() != "closed":
        return None
    note_raw = (getattr(alert, "closure_note", None) or "").strip()
    disp = (getattr(alert, "disposition", None) or "").strip()
    note, was_sanitized = sanitize_closure_note(note_raw)
    if not disp or len(note) < 10:
        return None
    entity = _entity_key(alert)
    excerpt = note[:NOTE_MAX]
    if was_sanitized:
        excerpt = f"[sanitized] {excerpt}"[:NOTE_MAX]
    memory_text = _build_memory_text(
        title=alert.title or "",
        rule_id=alert.rule_id or "",
        entity_key=entity,
        mitre=getattr(alert, "mitre", None),
        note=excerpt,
    )
    closed_at = getattr(alert, "closed_at", None) or datetime.now(timezone.utc)
    row = db.get(AlertMemory, alert.id)
    if row is None:
        row = AlertMemory(alert_id=alert.id)
        db.add(row)
    row.tenant_id = getattr(alert, "tenant_id", None) or "lab"
    row.rule_id = alert.rule_id or ""
    row.entity_key = entity
    row.disposition = disp
    row.mitre = getattr(alert, "mitre", None)
    row.title = (alert.title or "")[:512]
    row.note_excerpt = excerpt
    row.memory_text = memory_text
    row.closed_at = closed_at
    db.flush()
    try:
        db.execute(
            text(
                "UPDATE alert_memory SET tsv = to_tsvector('simple', coalesce(memory_text, '')) "
                "WHERE alert_id = :aid"
            ),
            {"aid": alert.id},
        )
    except Exception:
        # Non-Postgres or missing tsv column: lexical retrieve still works on memory_text
        logger.debug("alert_memory tsv update skipped", exc_info=True)
    return row


def backfill_alert_memory(
    db: Session,
    *,
    tenant_id: str = "lab",
    limit: int = BACKFILL_CAP,
) -> int:
    """Index recent closed alerts with disposition+note. Returns rows upserted."""
    rows = list(
        db.scalars(
            select(Alert)
            .where(
                and_(
                    Alert.tenant_id == tenant_id,
                    Alert.status == "closed",
                    Alert.disposition.is_not(None),
                    Alert.closure_note.is_not(None),
                )
            )
            .order_by(Alert.closed_at.desc().nullslast(), Alert.id.desc())
            .limit(max(1, min(limit, BACKFILL_CAP)))
        ).all()
    )
    n = 0
    for alert in rows:
        if upsert_alert_memory(db, alert) is not None:
            n += 1
    return n


def _tokenize(q: str) -> list[str]:
    return [t for t in re.findall(r"[a-zA-Z0-9_.@:/-]+", (q or "").lower()) if len(t) > 1]


def _lexical_score(memory_text: str, tokens: list[str]) -> float:
    if not tokens:
        return 0.0
    hay = (memory_text or "").lower()
    hits = sum(1 for t in tokens if t in hay)
    return hits / max(1, len(tokens))


def _case_dict(
    *,
    alert_id: int,
    rule_id: str,
    title: str,
    disposition: str | None,
    note_excerpt: str,
    entity_key: str | None = None,
    mitre: str | None = None,
    score: float = 0.0,
    closed_at: datetime | None = None,
) -> dict[str, Any]:
    return {
        "alert_id": alert_id,
        "rule_id": rule_id,
        "title": title,
        "disposition": disposition,
        "note_excerpt": (note_excerpt or "")[:CASE_NOTE_MAX],
        "entity_key": entity_key,
        "mitre": mitre,
        "score": round(float(score), 4),
        "closed_at": closed_at.isoformat() if closed_at else None,
    }


def _query_from_alert(alert: Alert) -> str:
    sample = {}
    ev = dict(alert.evidence or {})
    if isinstance(ev.get("sample"), dict):
        sample = ev["sample"]
    parts = [
        alert.title or "",
        alert.rule_id or "",
        getattr(alert, "mitre", None) or "",
        _entity_key(alert) or "",
        str(sample.get("src_ip") or ""),
        str(sample.get("host") or ""),
        str(sample.get("user") or ""),
    ]
    return " ".join(p for p in parts if p)


def retrieve_cases(
    db: Session,
    alert: Alert,
    *,
    top_k: int = 5,
    prior_days: int = 30,
    rag_enabled: bool = True,
) -> list[dict[str, Any]]:
    """Hybrid retrieve: structured similar + FTS/lexical memory, boost rule/entity."""
    if not rag_enabled or db is None:
        return []
    top_k = max(1, min(10, int(top_k)))
    prior_days = max(1, int(prior_days))
    since = datetime.now(timezone.utc) - timedelta(days=prior_days)
    tenant = getattr(alert, "tenant_id", None) or "lab"
    entity = _entity_key(alert)
    rule_id = alert.rule_id or ""
    tokens = _tokenize(_query_from_alert(alert))
    scored: dict[int, dict[str, Any]] = {}

    # 1) Structured similar (same rule+entity)
    try:
        similar = find_similar_alerts(db, alert, days=prior_days, limit=top_k * 2)
    except Exception:
        similar = []
    for s in similar:
        if (getattr(s, "status", None) or "").lower() != "closed":
            # still useful if disposition present
            if not getattr(s, "disposition", None):
                continue
        note = (getattr(s, "closure_note", None) or "")[:CASE_NOTE_MAX]
        if not note and not getattr(s, "disposition", None):
            continue
        score = 3.0  # rule match from find_similar
        from .entity_norm import entity_keys_overlap

        if entity and (
            _entity_key(s) == entity
            or entity_keys_overlap(_entity_keys(alert), _entity_keys(s))
        ):
            score += 2.0
        if note:
            score += 0.5
        # Light boost from analyst thumbs on same rule (cap ±5)
        try:
            from .models import CopilotFeedback

            useful_n = (
                db.scalar(
                    select(func.count())
                    .select_from(CopilotFeedback)
                    .where(
                        and_(
                            CopilotFeedback.tenant_id == tenant,
                            CopilotFeedback.rule_id == (s.rule_id or rule_id),
                            CopilotFeedback.useful.is_(True),
                        )
                    )
                )
                or 0
            )
            unuseful_n = (
                db.scalar(
                    select(func.count())
                    .select_from(CopilotFeedback)
                    .where(
                        and_(
                            CopilotFeedback.tenant_id == tenant,
                            CopilotFeedback.rule_id == (s.rule_id or rule_id),
                            CopilotFeedback.useful.is_(False),
                        )
                    )
                )
                or 0
            )
            score += max(-5.0, min(5.0, float(useful_n - unuseful_n) * 0.5))
        except Exception:
            pass
        scored[s.id] = _case_dict(
            alert_id=s.id,
            rule_id=s.rule_id or "",
            title=s.title or "",
            disposition=getattr(s, "disposition", None),
            note_excerpt=note or (getattr(s, "disposition", None) or ""),
            entity_key=_entity_key(s),
            mitre=getattr(s, "mitre", None),
            score=score,
            closed_at=getattr(s, "closed_at", None),
        )

    # 2) Memory rows (FTS preferred, lexical fallback)
    q_text = " ".join(tokens[:12]) or (alert.title or rule_id or "alert")
    mem_rows: list[AlertMemory] = []
    try:
        fts = db.execute(
            text(
                """
                SELECT alert_id, tenant_id, rule_id, entity_key, disposition, mitre,
                       title, note_excerpt, memory_text, closed_at,
                       COALESCE(ts_rank(tsv, plainto_tsquery('simple', :q)), 0) AS rank
                FROM alert_memory
                WHERE tenant_id = :tenant
                  AND (closed_at IS NULL OR closed_at >= :since)
                  AND alert_id <> :aid
                  AND (
                    tsv @@ plainto_tsquery('simple', :q)
                    OR rule_id = :rule
                    OR (:entity <> '' AND entity_key = :entity)
                  )
                ORDER BY rank DESC, closed_at DESC NULLS LAST
                LIMIT :lim
                """
            ),
            {
                "q": q_text,
                "tenant": tenant,
                "since": since,
                "aid": alert.id or 0,
                "rule": rule_id,
                "entity": entity or "",
                "lim": top_k * 4,
            },
        ).mappings().all()
        for r in fts:
            aid = int(r["alert_id"])
            score = float(r.get("rank") or 0) * 4.0
            if r.get("rule_id") == rule_id:
                score += 3.0
            if entity and r.get("entity_key") == entity:
                score += 2.0
            closed = r.get("closed_at")
            if closed:
                if closed.tzinfo is None:
                    closed = closed.replace(tzinfo=timezone.utc)
                age_days = max(
                    0.0,
                    (datetime.now(timezone.utc) - closed).total_seconds() / 86400.0,
                )
                score += max(0.0, 1.0 - age_days / max(1, prior_days))
            prev = scored.get(aid)
            case = _case_dict(
                alert_id=aid,
                rule_id=r.get("rule_id") or "",
                title=r.get("title") or "",
                disposition=r.get("disposition"),
                note_excerpt=r.get("note_excerpt") or "",
                entity_key=r.get("entity_key"),
                mitre=r.get("mitre"),
                score=score + (prev["score"] if prev else 0),
                closed_at=closed,
            )
            scored[aid] = case
    except Exception:
        logger.debug("FTS retrieve fallback to ORM lexical", exc_info=True)
        mem_rows = list(
            db.scalars(
                select(AlertMemory)
                .where(
                    and_(
                        AlertMemory.tenant_id == tenant,
                        AlertMemory.alert_id != (alert.id or 0),
                        (
                            AlertMemory.closed_at.is_(None)
                            | (AlertMemory.closed_at >= since)
                        ),
                    )
                )
                .order_by(AlertMemory.closed_at.desc().nullslast())
                .limit(80)
            ).all()
        )
        for row in mem_rows:
            score = _lexical_score(row.memory_text or "", tokens) * 4.0
            if row.rule_id == rule_id:
                score += 3.0
            if entity and row.entity_key == entity:
                score += 2.0
            if score <= 0 and row.rule_id != rule_id and row.entity_key != entity:
                continue
            prev = scored.get(row.alert_id)
            case = _case_dict(
                alert_id=row.alert_id,
                rule_id=row.rule_id or "",
                title=row.title or "",
                disposition=row.disposition,
                note_excerpt=row.note_excerpt or "",
                entity_key=row.entity_key,
                mitre=row.mitre,
                score=score + (prev["score"] if prev else 0),
                closed_at=row.closed_at,
            )
            scored[row.alert_id] = case

    ranked = sorted(scored.values(), key=lambda c: c["score"], reverse=True)
    return ranked[:top_k]


def local_suggest_from_cases(
    cases: list[dict[str, Any]],
    *,
    similar_fp: int = 0,
    similar_tp: int = 0,
) -> dict[str, Any] | None:
    """
    Strong-prior short-circuit without LLM.
    Returns suggestion dict or None if not confident enough.
    """
    citations = [c["alert_id"] for c in cases if c.get("alert_id") is not None]
    if similar_fp >= 3 and similar_tp == 0:
        notes = [
            c.get("note_excerpt") or ""
            for c in cases
            if (c.get("disposition") or "") in {"false_positive", "benign"}
        ]
        note = (notes[0] if notes else "Pattern ricorrente FP/benign nello stesso contesto.")[:4000]
        if len(note) < 10:
            note = "Chiudi come false positive: priors locali forti (stesso contesto)."
        return {
            "available": True,
            "suggested_disposition": "false_positive",
            "suggested_note": note,
            "rationale": f"Local memory: similar_fp={similar_fp}, similar_tp={similar_tp}",
            "message": None,
            "source": "local_memory",
            "citations": citations[:10],
        }
    if similar_tp >= 2 and similar_fp == 0:
        notes = [
            c.get("note_excerpt") or ""
            for c in cases
            if (c.get("disposition") or "") == "true_positive"
        ]
        note = (notes[0] if notes else "Precedenti true positive sullo stesso contesto.")[:4000]
        if len(note) < 10:
            note = "Chiudi come true positive: priors locali forti (stesso contesto)."
        return {
            "available": True,
            "suggested_disposition": "true_positive",
            "suggested_note": note,
            "rationale": f"Local memory: similar_tp={similar_tp}, similar_fp={similar_fp}",
            "message": None,
            "source": "local_memory",
            "citations": citations[:10],
        }
    # Majority vote on retrieved cases if enough agreement
    disps = [c.get("disposition") for c in cases if c.get("disposition")]
    if len(disps) >= 3:
        top, n = Counter(disps).most_common(1)[0]
        if n >= 3:
            notes = [c.get("note_excerpt") or "" for c in cases if c.get("disposition") == top]
            note = (notes[0] if notes else f"Maggioranza locale: {top}")[:4000]
            if len(note) < 10:
                note = f"Disposition suggerita dalla memoria locale: {top}."
            return {
                "available": True,
                "suggested_disposition": top,
                "suggested_note": note,
                "rationale": f"Local majority vote ({n}/{len(disps)})",
                "message": None,
                "source": "local_memory",
                "citations": citations[:10],
            }
    return None


def majority_fallback_from_cases(cases: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Soft fallback when LLM fails but cases exist."""
    disps = [c.get("disposition") for c in cases if c.get("disposition")]
    if not disps:
        return None
    top, n = Counter(disps).most_common(1)[0]
    notes = [c.get("note_excerpt") or "" for c in cases if c.get("disposition") == top]
    note = (notes[0] if notes else f"Fallback memoria: {top}")[:4000]
    if len(note) < 10:
        note = f"Suggerimento da memoria locale (fallback): {top}."
    return {
        "available": True,
        "suggested_disposition": top,
        "suggested_note": note,
        "rationale": f"LLM unavailable; memory majority ({n}/{len(disps)})",
        "message": "LLM unavailable - fallback memoria",
        "source": "local_memory",
        "citations": [c["alert_id"] for c in cases if c.get("alert_id") is not None][:10],
    }


def memory_stats(db: Session, *, tenant_id: str = "lab") -> dict[str, Any]:
    rows = list(
        db.execute(
            select(AlertMemory.disposition, func.count())
            .where(AlertMemory.tenant_id == tenant_id)
            .group_by(AlertMemory.disposition)
        ).all()
    )
    by_disp = { (d or "unknown"): int(c) for d, c in rows }
    total = sum(by_disp.values())
    last = db.scalar(
        select(func.max(AlertMemory.closed_at)).where(AlertMemory.tenant_id == tenant_id)
    )
    return {
        "tenant_id": tenant_id,
        "total": total,
        "by_disposition": by_disp,
        "last_closed_at": last.isoformat() if last else None,
    }


def export_memory(
    db: Session,
    *,
    tenant_id: str = "lab",
    limit: int = 500,
) -> dict[str, Any]:
    limit = max(1, min(2000, int(limit)))
    rows = list(
        db.scalars(
            select(AlertMemory)
            .where(AlertMemory.tenant_id == tenant_id)
            .order_by(AlertMemory.closed_at.desc().nullslast())
            .limit(limit)
        ).all()
    )
    cases = [
        {
            "alert_id": r.alert_id,
            "rule_id": r.rule_id,
            "entity_key": r.entity_key,
            "disposition": r.disposition,
            "mitre": r.mitre,
            "title": r.title,
            "note_excerpt": r.note_excerpt,
            "closed_at": r.closed_at.isoformat() if r.closed_at else None,
        }
        for r in rows
    ]
    return {
        "version": 1,
        "tenant_id": tenant_id,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "count": len(cases),
        "cases": cases,
    }
