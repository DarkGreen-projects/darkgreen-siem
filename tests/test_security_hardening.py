"""Security hardening: SSRF, secrets, syslog secret, rate limit, auth tighten."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.api.auth import issue_user_token, require_auth, verify_user_token
from services.api.config import Settings, enforce_startup_secrets, secrets_are_weak
from services.api.input_limits import escape_like
from services.api.rate_limit import enforce_login_rate, reset_limiters_for_tests
from services.api.secret_crypto import ENC_PREFIX, seal, unseal
from services.api.syslog_server import SyslogProtocol, strip_syslog_shared_secret
from services.api.url_safety import UnsafeUrlError, validate_egress_url


def test_escape_like_metacharacters():
    assert escape_like("T1059%") == "T1059\\%"
    assert escape_like("a_b") == "a\\_b"
    assert escape_like("a\\b") == "a\\\\b"


def test_url_blocks_loopback_and_http():
    with patch("services.api.url_safety.get_settings") as gs:
        gs.return_value = Settings(allow_insecure_webhooks=False, egress_host_allowlist="")
        with pytest.raises(UnsafeUrlError):
            validate_egress_url("http://example.com/hook", purpose="notify")
        with pytest.raises(UnsafeUrlError):
            validate_egress_url("https://127.0.0.1/hook", purpose="notify")
        with pytest.raises(UnsafeUrlError):
            validate_egress_url("https://169.254.169.254/latest", purpose="notify")
        with pytest.raises(UnsafeUrlError):
            validate_egress_url("https://localhost/hook", purpose="LLM")


def test_url_allows_https_public_when_resolves_public():
    with (
        patch("services.api.url_safety.get_settings") as gs,
        patch("services.api.url_safety.socket.getaddrinfo") as gai,
    ):
        gs.return_value = Settings(allow_insecure_webhooks=False, egress_host_allowlist="")
        gai.return_value = [(None, None, None, None, ("93.184.216.34", 0))]
        out = validate_egress_url("https://example.com/v1/hook", purpose="notify")
        assert out.startswith("https://example.com")


def test_url_allowlist_enforced():
    with (
        patch("services.api.url_safety.get_settings") as gs,
        patch("services.api.url_safety.socket.getaddrinfo") as gai,
    ):
        gs.return_value = Settings(
            allow_insecure_webhooks=False,
            egress_host_allowlist="hooks.slack.com",
        )
        gai.return_value = [(None, None, None, None, ("93.184.216.34", 0))]
        with pytest.raises(UnsafeUrlError):
            validate_egress_url("https://example.com/hook", purpose="notify")
        assert validate_egress_url(
            "https://hooks.slack.com/services/x", purpose="notify"
        )


def test_fernet_seal_unseal_roundtrip():
    with patch("services.api.secret_crypto.get_settings") as gs:
        gs.return_value = Settings(auth_secret="unit-test-auth-secret-xyz")
        sealed = seal("sk-test-key-value")
        assert sealed.startswith(ENC_PREFIX)
        assert unseal(sealed) == "sk-test-key-value"
        assert unseal("legacy-plaintext") == "legacy-plaintext"


def test_syslog_shared_secret_accept_reject():
    assert strip_syslog_shared_secret("hello", "") == "hello"
    assert strip_syslog_shared_secret("sec msg", "sec") == "msg"
    assert strip_syslog_shared_secret("#dg-token=sec body", "sec") == "body"
    assert strip_syslog_shared_secret("wrong msg", "sec") is None
    assert strip_syslog_shared_secret("<14>sec after", "sec") == "<14>after"

    seen: list[str] = []
    proto = SyslogProtocol(lambda t, h: seen.append(t), shared_secret="labsecret")
    proto.datagram_received(b"nope", ("203.0.113.1", 514))
    assert seen == []
    proto.datagram_received(b"labsecret ok-line", ("203.0.113.1", 514))
    assert seen == ["ok-line"]


def test_login_rate_limit_429():
    reset_limiters_for_tests()
    req = MagicMock()
    req.headers = {}
    req.client = MagicMock()
    req.client.host = "203.0.113.50"
    for _ in range(10):
        enforce_login_rate(req)
    with pytest.raises(HTTPException) as ei:
        enforce_login_rate(req)
    assert ei.value.status_code == 429
    assert "Retry-After" in (ei.value.headers or {})


def test_strict_secrets_blocks_weak_defaults():
    weak = Settings(
        auth_secret="darkgreen-siem-dev-secret-change-me",
        siem_api_token="dg-lab-token-change-me",
        strict_secrets=True,
    )
    assert secrets_are_weak(weak)
    with pytest.raises(RuntimeError):
        enforce_startup_secrets(weak)
    ok = Settings(auth_secret="strong-enough-secret", siem_api_token="strong-token", strict_secrets=True)
    enforce_startup_secrets(ok)


def test_legacy_token_rejected_when_strict():
    s = Settings(auth_secret="test-secret-lab", strict_secrets=True, default_tenant_id="lab")
    # craft legacy username|exp manually
    import base64
    import hashlib
    import hmac
    import time

    exp = int(time.time()) + 3600
    payload = f"analyst|{exp}".encode("utf-8")
    sig = hmac.new(s.auth_secret.encode(), payload, hashlib.sha256).digest()

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    legacy = f"{b64(payload)}.{b64(sig)}"
    assert verify_user_token(s, legacy) is None


def test_empty_users_bootstrap_forces_viewer():
    s = Settings(
        auth_enabled=True,
        auth_secret="test-secret-lab",
        siem_api_token="machine-token-lab",
        default_tenant_id="lab",
    )
    token, _ = issue_user_token(s, "boot", role="admin", tenant_id="lab")
    request = MagicMock()
    request.url.path = "/api/stats"
    db = MagicMock()
    # User missing, no users in table
    db.scalar.side_effect = [None, None]
    principal = require_auth(request, authorization=f"Bearer {token}", settings=s, db=db)
    assert principal.role == "viewer"
    assert principal.username == "boot"


def test_mask_webhook_no_tail():
    from services.api.lab_settings import mask_secret

    assert mask_secret("https://hooks.example/abc", reveal_tail=False) == "****"
    assert mask_secret("abcd1234", reveal_tail=True) == "****1234"
