"""RBAC permission matrix and tenant_id on normalized rows."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.api.rbac import hash_password, role_allows, verify_password
from services.normalizers import normalize_event


def test_password_hash_roundtrip():
    h = hash_password("darkgreen")
    assert verify_password("darkgreen", h)
    assert not verify_password("wrong", h)


def test_viewer_cannot_purge_or_setup():
    assert not role_allows("viewer", "purge")
    assert not role_allows("viewer", "setup")
    assert role_allows("viewer", "search")


def test_firewall_row_has_tenant_default():
    ev = normalize_event(
        'srcip=1.2.3.4 action=deny msg=x',
        source_type="firewall",
    )
    row = ev.to_row()
    assert row["tenant_id"] == "lab"
