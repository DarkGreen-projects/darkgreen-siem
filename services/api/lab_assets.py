"""Lab asset/owner map for brief enrichment (mock CMDB)."""

from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger("darkgreen-siem.assets")


@lru_cache
def _load_assets(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        return {"hosts": {}, "users": {}}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {"hosts": {}, "users": {}}
    except Exception:
        logger.warning("Failed to load lab assets from %s", path)
        return {"hosts": {}, "users": {}}


def resolve_asset_context(
    *,
    host: str | None = None,
    user: str | None = None,
    samples_dir: str | Path | None = None,
) -> dict[str, Any] | None:
    from .config import get_settings

    base = Path(samples_dir or get_settings().samples_dir)
    data = _load_assets(str(base / "lab_assets.json"))
    out: dict[str, Any] = {}
    if host:
        h = data.get("hosts") or {}
        if host in h:
            out["host"] = {"name": host, **dict(h[host])}
    if user:
        u = data.get("users") or {}
        # strip domain
        short = user.split("@", 1)[0]
        if short in u:
            out["user"] = {"name": short, **dict(u[short])}
        elif user in u:
            out["user"] = {"name": user, **dict(u[user])}
    return out or None
