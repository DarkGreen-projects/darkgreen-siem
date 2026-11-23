"""Optional LLM copilot + local Alert Memory short-circuit (fail-soft)."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import httpx

from .lab_settings import get_lab_state
from .rag_memory import local_suggest_from_cases, majority_fallback_from_cases
from .schemas import ALERT_DISPOSITIONS

logger = logging.getLogger("darkgreen-siem.copilot")

_SYSTEM = (
    "You are a SOC lab assistant for DarkGreen SIEM. "
    "Given a structured alert fingerprint (entities, MITRE, connected alerts, past cases), "
    "suggest one disposition, a short Italian closure note, and optional related alert IDs "
    "only from the provided connected/cases lists. "
    "Prefer patterns from the provided cases and strong graph links. "
    "Respond ONLY with JSON: "
    '{"disposition":"true_positive|false_positive|benign|duplicate|tuning_needed",'
    '"note":"...","rationale":"...","related_alert_ids":[],"relation_hint":"..."}'
)


def _parse_json_blob(text: str) -> dict[str, Any] | None:
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{[\s\S]*\}", text)
        if not m:
            return None
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return None


def _compact_cases(cases: list[dict[str, Any]], top_k: int = 5) -> list[dict[str, Any]]:
    out = []
    for c in (cases or [])[:top_k]:
        out.append(
            {
                "alert_id": c.get("alert_id"),
                "disposition": c.get("disposition"),
                "rule_id": c.get("rule_id"),
                "note": (c.get("note_excerpt") or "")[:200],
                "score": c.get("score"),
            }
        )
    return out


def _allowed_related_ids(brief: dict[str, Any]) -> set[int]:
    allowed: set[int] = set()
    for c in brief.get("connected") or []:
        if c.get("id") is not None:
            allowed.add(int(c["id"]))
    for c in brief.get("cases") or []:
        if c.get("alert_id") is not None:
            allowed.add(int(c["alert_id"]))
    fp = brief.get("fingerprint") or {}
    for c in fp.get("connected") or []:
        if c.get("id") is not None:
            allowed.add(int(c["id"]))
    for c in fp.get("cases") or []:
        if c.get("alert_id") is not None:
            allowed.add(int(c["alert_id"]))
    return allowed


def _graph_related(brief: dict[str, Any]) -> tuple[list[int], str | None]:
    """Strong graph edges for local-first rationale."""
    connected = list(brief.get("connected") or [])
    strong = [
        c
        for c in connected
        if int(c.get("score") or 0) >= 55
        or (c.get("relation") or "") in {"temporal_follows", "mitre_chain", "shared_ioc"}
    ]
    strong.sort(key=lambda c: int(c.get("score") or 0), reverse=True)
    ids = [int(c["id"]) for c in strong[:5] if c.get("id") is not None]
    if not ids:
        return [], None
    top = strong[0]
    hint = f"{top.get('relation')} score={top.get('score')} dir={top.get('direction')}"
    return ids, hint


def _attach_related(result: dict[str, Any], brief: dict[str, Any]) -> dict[str, Any]:
    allowed = _allowed_related_ids(brief)
    ids, hint = _graph_related(brief)
    raw_ids = result.get("related_alert_ids")
    if isinstance(raw_ids, list) and raw_ids:
        filtered = [int(x) for x in raw_ids if int(x) in allowed]
        if filtered:
            ids = filtered[:8]
    if result.get("relation_hint"):
        hint = str(result.get("relation_hint"))[:300]
    result["related_alert_ids"] = ids
    result["relation_hint"] = hint
    return result


def suggest_closure(brief: dict[str, Any]) -> dict[str, Any]:
    """Return copilot suggestion. Local-first RAG; LLM only when needed. Fail-soft."""
    state = get_lab_state()
    cases = list(brief.get("cases") or [])
    similar_fp = int(brief.get("similar_fp") or 0)
    similar_tp = int(brief.get("similar_tp") or 0)

    local = local_suggest_from_cases(
        cases, similar_fp=similar_fp, similar_tp=similar_tp
    )
    if local:
        local["cases"] = cases
        ids, hint = _graph_related(brief)
        if ids:
            local["rationale"] = (
                (local.get("rationale") or "")
                + f" | Graph: {hint}; related={ids}"
            ).strip(" |")
        return _attach_related(local, brief)

    enabled = bool(getattr(state, "llm_enabled", False))
    key = (getattr(state, "llm_api_key", None) or "").strip()
    if not enabled or not key:
        fallback = majority_fallback_from_cases(cases)
        if fallback:
            fallback["cases"] = cases
            return _attach_related(fallback, brief)
        return _attach_related(
            {
                "available": False,
                "suggested_disposition": None,
                "suggested_note": None,
                "rationale": None,
                "message": "LLM non configurato (Setup → Copilot); memoria insufficiente",
                "source": None,
                "citations": [],
                "cases": cases,
            },
            brief,
        )

    url = (
        getattr(state, "llm_api_url", None)
        or "https://api.openai.com/v1/chat/completions"
    ).strip()
    model = (getattr(state, "llm_model", None) or "gpt-4o-mini").strip()
    try:
        from .url_safety import UnsafeUrlError, validate_egress_url

        url = validate_egress_url(url, purpose="LLM")
    except UnsafeUrlError:
        logger.warning("LLM URL rejected by url_safety")
        fallback = majority_fallback_from_cases(cases)
        if fallback:
            fallback["cases"] = cases
            return _attach_related(fallback, brief)
        return _attach_related(
            {
                "available": False,
                "suggested_disposition": None,
                "suggested_note": None,
                "rationale": None,
                "message": "LLM unavailable",
                "source": None,
                "citations": [],
                "cases": cases,
            },
            brief,
        )

    top_k = int(getattr(state, "rag_top_k", 5) or 5)
    fingerprint = brief.get("fingerprint") or {}
    if not fingerprint:
        fingerprint = {
            "summary": (brief.get("summary") or "")[:1200],
            "entities": brief.get("entities"),
            "noise_hint": brief.get("noise_hint"),
            "risk_score": brief.get("risk_score"),
            "mitre": brief.get("mitre"),
            "connected": brief.get("connected") or [],
            "cases": _compact_cases(cases, top_k=top_k),
        }
    else:
        fingerprint = dict(fingerprint)
        fingerprint["cases"] = _compact_cases(
            fingerprint.get("cases") or cases, top_k=top_k
        )
        fingerprint["connected"] = (fingerprint.get("connected") or brief.get("connected") or [])[
            :8
        ]

    user_content = json.dumps(
        {
            "fingerprint": fingerprint,
            "similar_fp": similar_fp,
            "similar_tp": similar_tp,
            "allowed_related_ids": sorted(_allowed_related_ids(brief)),
        },
        ensure_ascii=False,
    )
    payload = {
        "model": model,
        "temperature": 0.1,
        "max_tokens": 450,
        "messages": [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": user_content},
        ],
    }
    try:
        with httpx.Client(timeout=8.0, follow_redirects=False) as client:
            resp = client.post(
                url,
                headers={
                    "Authorization": f"Bearer {key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            if resp.status_code >= 400:
                logger.warning("LLM HTTP %s", resp.status_code)
                fallback = majority_fallback_from_cases(cases)
                if fallback:
                    fallback["cases"] = cases
                    return _attach_related(fallback, brief)
                return _attach_related(
                    {
                        "available": False,
                        "suggested_disposition": None,
                        "suggested_note": None,
                        "rationale": None,
                        "message": "LLM unavailable",
                        "source": None,
                        "citations": [],
                        "cases": cases,
                    },
                    brief,
                )
            data = resp.json()
            content = (
                ((data.get("choices") or [{}])[0].get("message") or {}).get("content")
                or ""
            )
    except Exception as exc:
        logger.warning("LLM request failed: %s", type(exc).__name__)
        fallback = majority_fallback_from_cases(cases)
        if fallback:
            fallback["cases"] = cases
            return _attach_related(fallback, brief)
        return _attach_related(
            {
                "available": False,
                "suggested_disposition": None,
                "suggested_note": None,
                "rationale": None,
                "message": "LLM unavailable",
                "source": None,
                "citations": [],
                "cases": cases,
            },
            brief,
        )

    parsed = _parse_json_blob(content)
    if not parsed:
        fallback = majority_fallback_from_cases(cases)
        if fallback:
            fallback["cases"] = cases
            return _attach_related(fallback, brief)
        return _attach_related(
            {
                "available": False,
                "suggested_disposition": None,
                "suggested_note": None,
                "rationale": None,
                "message": "Risposta LLM non valida",
                "source": None,
                "citations": [],
                "cases": cases,
            },
            brief,
        )
    disp = str(parsed.get("disposition") or "").strip().lower()
    if disp not in ALERT_DISPOSITIONS:
        disp = "tuning_needed"
    note = str(parsed.get("note") or "").strip()
    if len(note) < 10:
        note = (note + " (suggerimento automatico DarkGreen)").strip()
    citations = [c["alert_id"] for c in cases if c.get("alert_id") is not None]
    return _attach_related(
        {
            "available": True,
            "suggested_disposition": disp,
            "suggested_note": note[:4000],
            "rationale": str(parsed.get("rationale") or "")[:1000] or None,
            "message": None,
            "source": "llm_rag",
            "citations": citations[:10],
            "cases": cases,
            "related_alert_ids": parsed.get("related_alert_ids") or [],
            "relation_hint": parsed.get("relation_hint"),
        },
        brief,
    )
