"""Unit tests for normalizers and search query parsing (no DB required)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.api.query_parse import parse_query
from services.normalizers import detect_source_type, normalize_event


def test_firewall_syslog_normalize():
    raw = (
        'devname="fw-edge-01" srcip=203.0.113.45 dstip=10.0.10.22 '
        'action=deny msg="blocked"'
    )
    ev = normalize_event(raw, source_type="firewall", ingest_channel="syslog")
    assert ev.source_type == "firewall"
    assert ev.src_ip == "203.0.113.45"
    assert ev.action == "deny"
    assert ev.severity == "high"
    assert ev.ingest_channel == "syslog"


def test_windows_failed_logon():
    payload = {
        "EventID": 4625,
        "Computer": "win-dc01.lab.local",
        "TargetUserName": "j.doe",
        "IpAddress": "203.0.113.45",
        "Message": "fail",
    }
    ev = normalize_event(payload, source_type="windows")
    assert ev.action == "login_failed"
    assert ev.user == "j.doe"
    assert ev.severity == "high"


def test_cloud_auth_detect():
    payload = {
        "vendor": "EntraID",
        "userPrincipalName": "a@contoso.example",
        "clientIp": "198.51.100.1",
        "result": "failure",
    }
    assert detect_source_type(payload) == "cloud_auth"
    ev = normalize_event(payload)
    assert ev.source_type == "cloud_auth"
    assert ev.action == "login_failed"


def test_siem_export_malware():
    payload = {
        "AlertId": "CY-1",
        "Product": "Cynet",
        "Severity": "high",
        "Activity": "Malware Detected",
        "Hostname": "host1",
        "Description": "bad file",
    }
    ev = normalize_event(payload)
    assert ev.source_type == "siem_export"
    assert ev.action == "malware_detected"
    assert ev.severity == "high"


def test_parse_query_fields_and_free_text():
    fields, free = parse_query('src_ip:10.0.0.1 AND action:deny malware')
    assert ("src_ip", "10.0.0.1") in fields
    assert ("action", "deny") in fields
    assert "malware" in free


def test_parse_query_quoted():
    fields, free = parse_query('message:"blocked outbound"')
    assert fields == [("message", "blocked outbound")]
    assert free == []
