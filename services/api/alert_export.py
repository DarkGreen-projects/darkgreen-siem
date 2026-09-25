"""CSV helpers for alert export."""

from __future__ import annotations

import csv
import io
import re
from typing import Any, Protocol


class AlertLike(Protocol):
    id: int
    created_at: Any
    status: str
    rule_id: str
    rule_name: str
    severity: str
    title: str
    evidence: dict[str, Any] | None


_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)


def _sample(evidence: dict[str, Any] | None) -> dict[str, Any]:
    if not evidence:
        return {}
    sample = evidence.get("sample")
    return sample if isinstance(sample, dict) else {}


def _collect_iocs(alert: AlertLike) -> str:
    evidence = dict(alert.evidence or {})
    sample = _sample(evidence)
    texts = [
        alert.title or "",
        str(getattr(alert, "description", "") or ""),
        str(evidence.get("threat_brief") or ""),
        str(sample.get("message") or ""),
        str(sample.get("src_ip") or ""),
        str(sample.get("dst_ip") or ""),
    ]
    found: list[str] = []
    seen: set[str] = set()
    for text in texts:
        for m in _IP_RE.findall(text):
            if m not in seen:
                seen.add(m)
                found.append(m)
    return ";".join(found[:20])


def alerts_to_csv(alerts: list[AlertLike]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "id",
            "created_at",
            "status",
            "rule_id",
            "rule_name",
            "severity",
            "title",
            "mitre",
            "src_ip",
            "dst_ip",
            "user",
            "host",
            "iocs",
        ]
    )
    for a in alerts:
        sample = _sample(dict(a.evidence or {}))
        created = a.created_at.isoformat() if getattr(a.created_at, "isoformat", None) else (a.created_at or "")
        mitre = getattr(a, "mitre", None) or (a.evidence or {}).get("mitre") or ""
        writer.writerow(
            [
                a.id,
                created,
                a.status,
                a.rule_id,
                a.rule_name,
                a.severity,
                a.title,
                mitre,
                sample.get("src_ip") or "",
                sample.get("dst_ip") or "",
                sample.get("user") or "",
                sample.get("host") or "",
                _collect_iocs(a),
            ]
        )
    return buf.getvalue()
