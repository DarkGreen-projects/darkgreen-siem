"""Optional LLM copilot + local Alert Memory short-circuit (fail-soft)."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from .lab_settings import get_lab_state
from .rag_memory import local_suggest_from_cases, majority_fallback_from_cases
from .schemas import ALERT_DISPOSITIONS

logger = logging.getLogger("darkgreen-siem.copilot")


def _safe_int(value: Any, default: int | None = None) -> int | None:
    try:
        if value is None or isinstance(value, bool):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default

_SYSTEM = (
    "You are a SOC lab assistant for DarkGreen SIEM. "
    "Given a structured alert fingerprint (entities, MITRE, connected alerts, past cases), "
    "suggest one disposition, a short Italian closure note, priority, noise_action, "
    "and optional related alert IDs only from the provided connected/cases lists. "
    "Prefer patterns from the provided cases and strong graph links. "
    "Never auto-close; suggestions only. "
    "Respond ONLY with JSON: "
    '{"disposition":"true_positive|false_positive|benign|duplicate|tuning_needed",'
    '"note":"...","rationale":"...","priority":"p1|p2|p3",'
    '"noise_action":"keep|demote|merge_candidate",'
    '"related_alert_ids":[],"relation_hint":"..."}'
)

def should_call_llm(
    brief: dict[str, Any],
    *,
    local_confidence: bool,
) -> tuple[bool, str]:
    """Hard pre-LLM gate (does not consume budget). Returns (ok, reason)."""
    if local_confidence:
        return False, "local_rag_confident"
    noise = (brief.get("noise_hint") or "").lower()
    fp_n = _safe_int(brief.get("similar_fp"), 0) or 0
    tp_n = _safe_int(brief.get("similar_tp"), 0) or 0
    if noise == "likely_noise" and fp_n >= 2 and tp_n == 0:
        return False, "likely_noise_strong_fp_priors"
    return True, "ok"


def _redact_ioc_value(value: Any) -> str:
    text = str(value or "")
    if len(text) <= 4:
        return "****"
    if "." in text and text.replace(".", "").isdigit():
        parts = text.split(".")
        return ".".join(parts[:2] + ["*", "*"])
    return text[:4] + "…" + text[-4:]


def redact_fingerprint_for_llm(fingerprint: dict[str, Any]) -> dict[str, Any]:
    """Mask hashes/IOCs before sending to external LLM (llm_effort=low)."""
    import copy

    fp = copy.deepcopy(fingerprint or {})
    entities = fp.get("entities")
    if isinstance(entities, dict):
        fp["entities"] = {k: _redact_ioc_value(v) for k, v in entities.items()}
    iocs = fp.get("iocs")
    if isinstance(iocs, list):
        fp["iocs"] = [_redact_ioc_value(x) for x in iocs]
    sample = fp.get("sample")
    if isinstance(sample, dict):
        fp["sample"] = {
            k: _redact_ioc_value(v) if k in {"src_ip", "dst_ip", "host", "user", "hash"} else v
            for k, v in sample.items()
        }
    labels = fp.get("labels")
    if isinstance(labels, dict):
        fp["labels"] = {
            k: _redact_ioc_value(v) if k in {"hash", "sha256", "domain", "url"} else v
            for k, v in labels.items()
        }
    fp["llm_redacted"] = True
    return fp


def _normalize_priority(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if text in {"p1", "p2", "p3"}:
        return text
    return None


def _normalize_noise_action(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if text in {"keep", "demote", "merge_candidate"}:
        return text
    return None


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
        vid = _safe_int(c.get("id"))
        if vid is not None:
            allowed.add(vid)
    for c in brief.get("cases") or []:
        vid = _safe_int(c.get("alert_id"))
        if vid is not None:
            allowed.add(vid)
    fp = brief.get("fingerprint") or {}
    for c in fp.get("connected") or []:
        vid = _safe_int(c.get("id"))
        if vid is not None:
            allowed.add(vid)
    for c in fp.get("cases") or []:
        vid = _safe_int(c.get("alert_id"))
        if vid is not None:
            allowed.add(vid)
    return allowed


def _graph_related(brief: dict[str, Any]) -> tuple[list[int], str | None]:
    """Strong graph edges for local-first rationale."""
    connected = list(brief.get("connected") or [])
    strong = []
    for c in connected:
        score = _safe_int(c.get("score"), 0) or 0
        if score >= 55 or (c.get("relation") or "") in {
            "temporal_follows",
            "mitre_chain",
            "shared_ioc",
        }:
            strong.append(c)
    strong.sort(key=lambda c: _safe_int(c.get("score"), 0) or 0, reverse=True)
    ids: list[int] = []
    for c in strong[:5]:
        vid = _safe_int(c.get("id"))
        if vid is not None:
            ids.append(vid)
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
        filtered: list[int] = []
        for x in raw_ids:
            vid = _safe_int(x)
            if vid is not None and vid in allowed:
                filtered.append(vid)
        if filtered:
            ids = filtered[:8]
    if result.get("relation_hint"):
        hint = str(result.get("relation_hint"))[:300]
    result["related_alert_ids"] = ids
    result["relation_hint"] = hint
    return result


def suggest_closure(
    brief: dict[str, Any],
    *,
    db: Any = None,
    tenant_id: str = "lab",
) -> dict[str, Any]:
    """Return copilot suggestion. Local-first RAG; LLM only when needed. Fail-soft."""
    state = get_lab_state()
    cases = list(brief.get("cases") or [])
    similar_fp = _safe_int(brief.get("similar_fp"), 0) or 0
    similar_tp = _safe_int(brief.get("similar_tp"), 0) or 0

    local = local_suggest_from_cases(
        cases, similar_fp=similar_fp, similar_tp=similar_tp
    )
    if local:
        local["cases"] = cases
        local.setdefault("priority", "p2" if (brief.get("noise_hint") or "") == "likely_signal" else "p3")
        local.setdefault(
            "noise_action",
            "demote" if (brief.get("noise_hint") or "") == "likely_noise" else "keep",
        )
        ids, hint = _graph_related(brief)
        if ids:
            local["rationale"] = (
                (local.get("rationale") or "")
                + f" | Graph: {hint}; related={ids}"
            ).strip(" |")
            if len(ids) >= 2:
                local["noise_action"] = "merge_candidate"
        return _attach_related(local, brief)

    gate_ok, gate_reason = should_call_llm(brief, local_confidence=False)
    enabled = bool(getattr(state, "llm_enabled", False))
    key = (getattr(state, "llm_api_key", None) or "").strip()
    if enabled and key and gate_ok:
        from .rate_limit import enforce_copilot_llm_budget

        if not enforce_copilot_llm_budget(tenant_id=tenant_id, db=db):
            gate_ok = False
            gate_reason = "llm_budget_exhausted"
    if not enabled or not key or not gate_ok:
        fallback = majority_fallback_from_cases(cases)
        if fallback:
            fallback["cases"] = cases
            fallback.setdefault("priority", "p3")
            fallback.setdefault("noise_action", "keep")
            return _attach_related(fallback, brief)
        msg = "LLM non configurato (Setup → Copilot); memoria insufficiente"
        if not gate_ok:
            msg = f"LLM saltato ({gate_reason}); usa briefing locale"
        return _attach_related(
            {
                "available": False,
                "suggested_disposition": None,
                "suggested_note": None,
                "rationale": None,
                "message": msg,
                "source": None,
                "citations": [],
                "cases": cases,
                "priority": None,
                "noise_action": "demote" if gate_reason.startswith("likely_noise") else None,
                "llm_skipped": gate_reason if not gate_ok else None,
            },
            brief,
        )

    url = (
        getattr(state, "llm_api_url", None)
        or "https://api.openai.com/v1/chat/completions"
    ).strip()
    model = (getattr(state, "llm_model", None) or "gpt-4o-mini").strip()
    top_k = _safe_int(getattr(state, "rag_top_k", 5), 5) or 5
    effort = (getattr(state, "llm_effort", None) or "low").strip().lower()
    max_tokens = 700 if effort == "high" else 450
    connected = list(brief.get("connected") or [])[:8]
    cluster_summary = {
        "size": len(connected),
        "relations": sorted(
            {
                str(c.get("relation"))
                for c in connected
                if c.get("relation")
            }
        )[:6],
        "top_ids": [
            _safe_int(c.get("id"))
            for c in connected[:5]
            if _safe_int(c.get("id")) is not None
        ],
    }
    fingerprint = brief.get("fingerprint") or {}
    if not fingerprint:
        fingerprint = {
            "summary": (brief.get("summary") or "")[:1200],
            "entities": brief.get("entities"),
            "noise_hint": brief.get("noise_hint"),
            "risk_score": brief.get("risk_score"),
            "mitre": brief.get("mitre"),
            "connected": connected,
            "cluster_summary": cluster_summary,
            "cases": _compact_cases(cases, top_k=top_k),
        }
    else:
        fingerprint = dict(fingerprint)
        fingerprint["cases"] = _compact_cases(
            fingerprint.get("cases") or cases, top_k=top_k
        )
        fingerprint["connected"] = (
            fingerprint.get("connected") or connected
        )[:8]
        fingerprint["cluster_summary"] = cluster_summary

    llm_redacted = False
    if effort != "high":
        fingerprint = redact_fingerprint_for_llm(fingerprint)
        llm_redacted = True

    user_content = json.dumps(
        {
            "fingerprint": fingerprint,
            "similar_fp": similar_fp,
            "similar_tp": similar_tp,
            "allowed_related_ids": sorted(_allowed_related_ids(brief)),
            "llm_redacted": llm_redacted,
        },
        ensure_ascii=False,
    )
    payload = {
        "model": model,
        "temperature": 0.1,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": user_content},
        ],
    }
    try:
        from .url_safety import UnsafeUrlError, egress_post

        try:
            resp = egress_post(
                url,
                purpose="LLM",
                timeout=8.0,
                headers={
                    "Authorization": f"Bearer {key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
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
            ((data.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
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
    priority = _normalize_priority(parsed.get("priority")) or (
        "p1"
        if (brief.get("noise_hint") or "") == "likely_signal"
        else "p2"
    )
    noise_action = _normalize_noise_action(parsed.get("noise_action")) or "keep"
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
            "priority": priority,
            "noise_action": noise_action,
            "llm_redacted": llm_redacted,
        },
        brief,
    )
