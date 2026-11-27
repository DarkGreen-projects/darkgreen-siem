"""Alert-to-alert link graph (same entity, temporal/MITRE chains, shared IOC)."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from .entity_norm import alert_entity_keys, canonical_values, entity_keys_overlap
from .models import Alert, AlertLink, AlertMemory

logger = logging.getLogger("darkgreen-siem.graph")

# Lightweight kill-chain follow-ons (technique prefix → likely next)
_MITRE_FOLLOWS: dict[str, frozenset[str]] = {
    "T1110": frozenset({"T1078", "T1021", "T1059"}),
    "T1078": frozenset({"T1021", "T1059", "T1003"}),
    "T1059": frozenset({"T1047", "T1105", "T1021"}),
    "T1204": frozenset({"T1059", "T1105", "T1041"}),
    "T1566": frozenset({"T1204", "T1059"}),
}

MAX_LINKS_PER_ALERT = 20


def _mitre_tokens(mitre: str | None) -> set[str]:
    if not mitre:
        return set()
    out: set[str] = set()
    for part in str(mitre).replace(";", ",").split(","):
        p = part.strip().upper()
        if not p:
            continue
        out.add(p)
        if "." in p:
            out.add(p.split(".", 1)[0])
    return out


def _mitre_chain_score(src_mitre: str | None, dst_mitre: str | None) -> int:
    a = _mitre_tokens(src_mitre)
    b = _mitre_tokens(dst_mitre)
    if not a or not b:
        return 0
    if a & b:
        return 15
    for t in a:
        base = t.split(".", 1)[0]
        follows = _MITRE_FOLLOWS.get(base, frozenset())
        for u in b:
            if u.split(".", 1)[0] in follows or u in follows:
                return 25
    return 0


def _ioc_set(alert: Alert) -> set[str]:
    keys = alert_entity_keys(alert)
    vals = canonical_values(keys)
    ev = dict(alert.evidence or {})
    sample = ev.get("sample") if isinstance(ev.get("sample"), dict) else {}
    for field in ("src_ip", "dst_ip", "host", "user"):
        if sample.get(field):
            vals.add(str(sample[field]).lower())
    labels = ev.get("labels") if isinstance(ev.get("labels"), dict) else {}
    for field in ("hash", "domain", "url"):
        if labels and labels.get(field):
            vals.add(str(labels[field]).lower())
    return vals


def _history_count(db: Session, tenant_id: str) -> int:
    from sqlalchemy import func

    n_mem = db.scalar(
        select(func.count()).select_from(AlertMemory).where(AlertMemory.tenant_id == tenant_id)
    ) or 0
    n_open = db.scalar(
        select(func.count())
        .select_from(Alert)
        .where(
            and_(
                Alert.tenant_id == tenant_id,
                Alert.status.in_(["open", "acked", "in_progress"]),
            )
        )
    ) or 0
    return int(n_mem) + int(n_open)


def _pending_link(
    db: Session, *, src_id: int, dst_id: int, relation: str
) -> AlertLink | None:
    """Find an unsaved AlertLink already pending in this session."""
    for obj in list(db.new):
        if not isinstance(obj, AlertLink):
            continue
        if (
            int(obj.src_alert_id) == src_id
            and int(obj.dst_alert_id) == dst_id
            and str(obj.relation) == relation
        ):
            return obj
    return None


def _upsert_link(
    db: Session,
    *,
    src_id: int,
    dst_id: int,
    tenant_id: str,
    relation: str,
    score: int,
    shared_keys: list[str],
) -> None:
    if src_id == dst_id:
        return
    capped = max(0, min(100, score))
    pending = _pending_link(db, src_id=src_id, dst_id=dst_id, relation=relation)
    if pending is not None:
        if capped > int(pending.score or 0):
            pending.score = capped
            pending.shared_keys = shared_keys
        return
    existing = db.scalar(
        select(AlertLink).where(
            and_(
                AlertLink.src_alert_id == src_id,
                AlertLink.dst_alert_id == dst_id,
                AlertLink.relation == relation,
            )
        )
    )
    if existing:
        if capped > int(existing.score or 0):
            existing.score = capped
            existing.shared_keys = shared_keys
        return
    db.add(
        AlertLink(
            src_alert_id=src_id,
            dst_alert_id=dst_id,
            tenant_id=tenant_id,
            relation=relation,
            score=capped,
            shared_keys=shared_keys,
        )
    )


def link_alert(db: Session, alert: Alert) -> int:
    """Build/update edges for alert. Returns number of links written/updated."""
    if not alert.id:
        db.flush()
    if not alert.id:
        return 0

    from .lab_settings import get_lab_state

    lab = get_lab_state()
    if not getattr(lab, "graph_enabled", True):
        return 0

    # Soft-skip heavy linking for clear noise with low score (still allow signal).
    hint = (getattr(alert, "noise_hint", None) or "").lower()
    risk = int(getattr(alert, "risk_score", None) or 0)
    if hint == "likely_noise" and risk < 40:
        return 0

    window = int(getattr(lab, "graph_window_minutes", 120) or 120)
    min_history = int(getattr(lab, "graph_min_history", 15) or 15)
    peer_limit = int(getattr(lab, "graph_peer_limit", 40) or 40)
    peer_limit = max(10, min(80, peer_limit))
    tenant = getattr(alert, "tenant_id", None) or "lab"
    mature = _history_count(db, tenant) >= min_history

    keys = alert_entity_keys(alert)
    iocs = _ioc_set(alert)
    if not keys and not iocs:
        return 0

    since = datetime.now(timezone.utc) - timedelta(minutes=max(5, window))
    peers = list(
        db.scalars(
            select(Alert)
            .where(
                and_(
                    Alert.tenant_id == tenant,
                    Alert.id != alert.id,
                    Alert.created_at >= since,
                )
            )
            .order_by(Alert.created_at.desc())
            .limit(peer_limit)
        ).all()
    )

    written = 0
    for peer in peers:
        shared = entity_keys_overlap(keys, alert_entity_keys(peer))
        shared_iocs = sorted(iocs & _ioc_set(peer))
        if not shared and not shared_iocs:
            continue

        # Orient edge: older -> newer
        a_created = getattr(alert, "created_at", None) or datetime.now(timezone.utc)
        p_created = getattr(peer, "created_at", None) or a_created
        if p_created <= a_created:
            src, dst = peer, alert
        else:
            src, dst = alert, peer

        score = 40 + min(30, 10 * len(shared))
        if shared_iocs:
            score += 15
            _upsert_link(
                db,
                src_id=src.id,
                dst_id=dst.id,
                tenant_id=tenant,
                relation="shared_ioc",
                score=min(100, score),
                shared_keys=shared_iocs[:10],
            )
            written += 1

        if shared:
            _upsert_link(
                db,
                src_id=src.id,
                dst_id=dst.id,
                tenant_id=tenant,
                relation="same_entity",
                score=min(100, score),
                shared_keys=shared[:10],
            )
            written += 1

        if mature:
            mitre_s = _mitre_chain_score(getattr(src, "mitre", None), getattr(dst, "mitre", None))
            if mitre_s:
                _upsert_link(
                    db,
                    src_id=src.id,
                    dst_id=dst.id,
                    tenant_id=tenant,
                    relation="mitre_chain",
                    score=min(100, 50 + mitre_s),
                    shared_keys=shared[:10] or shared_iocs[:10],
                )
                written += 1
            # temporal follows if same entity and src before dst within window
            if shared and p_created != a_created:
                _upsert_link(
                    db,
                    src_id=src.id,
                    dst_id=dst.id,
                    tenant_id=tenant,
                    relation="temporal_follows",
                    score=min(100, 55 + min(20, 5 * len(shared))),
                    shared_keys=shared[:10],
                )
                written += 1

        if written >= MAX_LINKS_PER_ALERT:
            break

    return written


def connected_alerts(
    db: Session,
    alert: Alert,
    *,
    limit: int = 15,
) -> list[dict[str, Any]]:
    """Return neighbor nodes with relation metadata for brief/UI."""
    if not alert.id:
        return []
    rows = list(
        db.scalars(
            select(AlertLink)
            .where(
                or_(
                    AlertLink.src_alert_id == alert.id,
                    AlertLink.dst_alert_id == alert.id,
                )
            )
            .order_by(AlertLink.score.desc())
            .limit(max(1, min(50, limit * 2)))
        ).all()
    )
    out: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    for link in rows:
        if link.src_alert_id == alert.id:
            other_id = link.dst_alert_id
            direction = "out"
        else:
            other_id = link.src_alert_id
            direction = "in"
        key = (other_id, link.relation)
        if key in seen:
            continue
        seen.add(key)
        other = db.get(Alert, other_id)
        if not other or other.tenant_id != (alert.tenant_id or "lab"):
            continue
        out.append(
            {
                "id": other.id,
                "title": other.title,
                "rule_id": other.rule_id,
                "severity": other.severity,
                "status": other.status,
                "disposition": getattr(other, "disposition", None),
                "mitre": getattr(other, "mitre", None),
                "relation": link.relation,
                "score": int(link.score or 0),
                "direction": direction,
                "shared_keys": list(link.shared_keys or [])[:10],
            }
        )
        if len(out) >= limit:
            break
    return out


def links_payload(db: Session, alert: Alert) -> dict[str, Any]:
    connected = connected_alerts(db, alert, limit=20)
    return {
        "alert_id": alert.id,
        "connected": connected,
        "count": len(connected),
    }
