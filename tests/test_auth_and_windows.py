"""Auth helpers, RBAC, Windows ECS-lite fields."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.api.auth import (
    check_password,
    issue_user_token,
    require_auth,
    require_perm,
    verify_user_token,
)
from services.api.config import Settings
from services.api.rbac import role_allows
from services.api.rule_validate import validate_rule_payload
from services.normalizers import normalize_event


def _lab_settings(**kwargs) -> Settings:
    base = dict(
        auth_enabled=True,
        demo_username="analyst",
        demo_password="darkgreen",
        auth_secret="test-secret-lab",
        siem_api_token="machine-token-lab",
        default_tenant_id="lab",
    )
    base.update(kwargs)
    return Settings(**base)


def _db() -> MagicMock:
    db = MagicMock()
    db.scalar.return_value = None
    return db


def test_login_credentials_ok():
    s = _lab_settings()
    assert check_password(s, "analyst", "darkgreen")
    assert not check_password(s, "analyst", "wrong")
    assert not check_password(s, "other", "darkgreen")


def test_user_token_roundtrip():
    s = _lab_settings()
    token, exp = issue_user_token(s, "analyst", role="admin", tenant_id="lab")
    assert exp > 0
    assert verify_user_token(s, token) == ("analyst", "admin", "lab")
    assert verify_user_token(s, token + "x") is None
    assert verify_user_token(s, "not.a.token") is None


def test_require_auth_rejects_without_token():
    request = MagicMock()
    request.url.path = "/api/stats"
    with pytest.raises(HTTPException) as ei:
        require_auth(request, authorization=None, settings=_lab_settings(), db=_db())
    assert ei.value.status_code == 401


def test_require_auth_accepts_machine_and_user_token():
    request = MagicMock()
    request.url.path = "/api/ingest"
    s = _lab_settings()
    machine = require_auth(
        request, authorization="Bearer machine-token-lab", settings=s, db=_db()
    )
    assert machine.kind == "machine"
    assert machine.role == "ingest"
    token, _ = issue_user_token(s, "analyst", role="admin", tenant_id="lab")
    user = require_auth(
        request, authorization=f"Bearer {token}", settings=s, db=_db()
    )
    assert user.kind == "user"
    assert user.username == "analyst"
    assert user.role == "admin"


def test_require_auth_public_login():
    request = MagicMock()
    request.url.path = "/api/auth/login"
    principal = require_auth(
        request, authorization=None, settings=_lab_settings(), db=_db()
    )
    assert principal.kind == "public"


def test_viewer_denied_purge():
    request = MagicMock()
    request.url.path = "/api/admin/purge"
    s = _lab_settings()
    token, _ = issue_user_token(s, "viewer", role="viewer", tenant_id="lab")
    principal = require_auth(
        request, authorization=f"Bearer {token}", settings=s, db=_db()
    )
    dep = require_perm("purge")
    with pytest.raises(HTTPException) as ei:
        dep(principal=principal)
    assert ei.value.status_code == 403


def test_role_allows_matrix():
    assert role_allows("admin", "setup")
    assert role_allows("analyst", "rules_write")
    assert not role_allows("viewer", "purge")
    assert role_allows("ingest", "ingest")
    assert not role_allows("viewer", "enrich")


def test_windows_audit_cleared_1102():
    payload = {
        "EventID": 1102,
        "Channel": "Security",
        "ProviderName": "Microsoft-Windows-Eventlog",
        "Computer": "win-dc01.lab.local",
        "SubjectUserName": "a.admin",
        "Message": "The audit log was cleared",
    }
    ev = normalize_event(payload, source_type="windows")
    assert ev.action == "audit_cleared"
    assert ev.severity == "critical"
    assert ev.event_id == "1102"
    assert ev.channel == "Security"
    assert ev.provider == "Microsoft-Windows-Eventlog"
    assert ev.labels.get("event_id") == "1102"


def test_windows_failed_logon_has_channel_provider():
    payload = {
        "EventID": 4625,
        "Channel": "Security",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "Computer": "win-dc01.lab.local",
        "TargetUserName": "j.doe",
        "IpAddress": "203.0.113.45",
        "Message": "fail",
    }
    ev = normalize_event(payload, source_type="windows")
    assert ev.action == "login_failed"
    assert ev.event_id == "4625"
    assert ev.channel == "Security"
    assert ev.provider == "Microsoft-Windows-Security-Auditing"


def test_new_yaml_rules_validate():
    rules_dir = ROOT / "rules"
    for name in (
        "password-spray-windows.yml",
        "windows-audit-cleared.yml",
        "firewall-deny-hot-dst.yml",
    ):
        raw = yaml.safe_load((rules_dir / name).read_text(encoding="utf-8"))
        validated = validate_rule_payload(raw)
        assert validated["id"]
        assert validated["type"] in {"match", "threshold"}
        assert validated["match"]
