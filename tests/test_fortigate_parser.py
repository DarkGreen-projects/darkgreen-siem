"""FortiGate / firewall normalizer coverage."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.normalizers import detect_source_type, normalize_event
from services.normalizers.parsers import strip_syslog_header


def test_strip_syslog_header_pri():
    raw = '<134>date=2026-09-09 time=08:01:12 devname="fw" srcip=1.2.3.4'
    assert strip_syslog_header(raw).startswith("date=")


def test_traffic_deny_maps_high():
    raw = (
        '<134>date=2026-09-09 time=08:01:12 devname="fw-edge-01" devid="FG1" '
        'logid="0000000013" type="traffic" subtype="forward" level="warning" '
        "srcip=203.0.113.45 dstip=10.0.10.22 srcport=54321 dstport=443 "
        'srcintf="wan1" dstintf="lan" proto=6 action=deny policyid=12 '
        'policyname="block" sessionid=99 msg="blocked"'
    )
    assert detect_source_type(raw) == "firewall"
    ev = normalize_event(raw, source_type="firewall")
    assert ev.action == "deny"
    assert ev.severity == "medium"  # level=warning → medium
    assert ev.src_ip == "203.0.113.45"
    assert ev.labels.get("logid") == "0000000013"
    assert ev.labels.get("srcintf") == "wan1"
    assert ev.labels.get("policyname") == "block"
    assert ev.vendor == "Fortinet"


def test_accept_maps_allow():
    raw = (
        'date=2026-09-09 time=08:03:10 type="traffic" subtype="forward" '
        "level=notice action=accept srcip=10.0.0.1 dstip=8.8.8.8 msg=ok"
    )
    ev = normalize_event(raw, source_type="firewall")
    assert ev.action == "allow"
    assert ev.severity == "low"


def test_utm_virus():
    raw = (
        'logid="0211008192" type="utm" subtype="virus" level="alert" '
        "srcip=10.0.20.40 dstip=198.51.100.50 action=blocked "
        'filename="invoice.exe" url="http://mal.example/x" msg="virus detected"'
    )
    ev = normalize_event(raw, source_type="firewall")
    assert ev.action == "virus"
    assert ev.severity == "critical"
    assert ev.labels.get("filename") == "invoice.exe"
    assert "mal.example" in (ev.labels.get("url") or "")


def test_utm_ips_attack_label():
    raw = (
        'type="utm" subtype="ips" level="critical" action=dropped '
        'attack="MS.SMB.Remote.Code.Execution" srcip=203.0.113.200 dstip=10.0.10.22 '
        "msg=ips"
    )
    ev = normalize_event(raw, source_type="firewall")
    assert ev.action == "ips"
    assert ev.labels.get("attack") == "MS.SMB.Remote.Code.Execution"
    assert detect_source_type(raw) == "firewall"


def test_detect_logid_alone():
    assert detect_source_type('logid="1" type=traffic subtype=forward') == "firewall"
