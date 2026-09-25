"""Security hardening + raw compression."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.api.auth import issue_user_token, require_auth
from services.api.config import Settings
from services.api.input_limits import MAX_SYSLOG_BYTES
from services.api.maintenance import purge_old_events
from services.api.syslog_server import SyslogProtocol
from services.normalizers.compress import compress_raw, decompress_raw, is_compressed
from services.normalizers.schema import NormalizedEvent


def test_compress_roundtrip_large():
    text = "x" * 2000 + " srcip=203.0.113.1 action=deny"
    stored = compress_raw(text)
    assert is_compressed(stored)
    assert len(stored) < len(text)
    assert decompress_raw(stored) == text


def test_compress_skips_small():
    text = "short"
    assert compress_raw(text) == text
    assert not is_compressed(text)


def test_normalized_to_row_compresses():
    ev = NormalizedEvent(message="m", raw="R" * 800, source_type="firewall")
    row = ev.to_row()
    assert is_compressed(row["raw"])
    assert decompress_raw(row["raw"]).startswith("R")


def test_syslog_drops_oversized():
    seen: list[str] = []
    proto = SyslogProtocol(lambda t, h: seen.append(t))
    proto.datagram_received(b"x" * (MAX_SYSLOG_BYTES + 10), ("203.0.113.1", 514))
    assert seen == []
    proto.datagram_received(b"ok-line srcip=1.2.3.4", ("203.0.113.1", 514))
    assert seen == ["ok-line srcip=1.2.3.4"]


def test_purge_scoped_to_tenant():
    db = MagicMock()
    result = MagicMock()
    result.rowcount = 3
    db.execute.return_value = result
    out = purge_old_events(db, retention_days=7, tenant_id="lab")
    assert out["deleted"] == 3
    assert out["skipped"] is False


def test_deleted_user_token_rejected_when_users_exist():
    s = Settings(
        auth_enabled=True,
        auth_secret="test-secret-lab",
        siem_api_token="machine-token-lab",
        default_tenant_id="lab",
    )
    token, _ = issue_user_token(s, "gone", role="admin", tenant_id="lab")
    request = MagicMock()
    request.url.path = "/api/stats"
    db = MagicMock()
    # first scalar: User lookup None; second: any user id exists
    db.scalar.side_effect = [None, 42]
    with pytest.raises(HTTPException) as ei:
        require_auth(request, authorization=f"Bearer {token}", settings=s, db=db)
    assert ei.value.status_code == 401


def test_auth_disabled_requires_allow_flag():
    s = Settings(
        auth_enabled=False,
        allow_insecure_no_auth=False,
        auth_secret="test-secret-lab",
        default_tenant_id="lab",
    )
    request = MagicMock()
    request.url.path = "/api/stats"
    with pytest.raises(HTTPException) as ei:
        require_auth(request, authorization=None, settings=s, db=MagicMock())
    assert ei.value.status_code == 503
