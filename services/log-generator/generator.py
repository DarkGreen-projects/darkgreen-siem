#!/usr/bin/env python3
"""Continuously generate multi-source demo traffic into DarkGreen SIEM."""

from __future__ import annotations

import json
import os
import random
import socket
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

API_URL = os.getenv("API_URL", "http://localhost:8000").rstrip("/")
SYSLOG_HOST = os.getenv("SYSLOG_HOST", "127.0.0.1")
SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "5140"))
INTERVAL = float(os.getenv("INTERVAL_SEC", "2"))
SIEM_API_TOKEN = os.getenv("SIEM_API_TOKEN", "").strip()

USERS = ["j.doe", "a.admin", "svc.backup", "r.rossi", "ext.vendor"]
HOSTS = ["win-dc01.lab.local", "win-ws42.lab.local", "fw-edge-01", "app-api-01"]
IPS_EXT = ["203.0.113.45", "203.0.113.88", "198.51.100.22", "198.51.100.80"]
IPS_INT = ["10.0.20.15", "10.0.20.8", "10.0.30.2", "10.0.50.3"]
HOT_DST = ["203.0.113.200", "198.51.100.200", "192.0.2.200"]
SPRAY_SRC = "203.0.113.45"


def _auth_headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if SIEM_API_TOKEN:
        headers["Authorization"] = f"Bearer {SIEM_API_TOKEN}"
    return headers


def post_ingest(payload, source_type: str) -> None:
    body = json.dumps(
        {
            "raw": payload,
            "source_type": source_type,
            "ingest_channel": "http",
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        f"{API_URL}/api/ingest",
        data=body,
        headers=_auth_headers(),
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        resp.read()


def send_syslog(line: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        msg = f"<134>{line}".encode("utf-8")
        sock.sendto(msg, (SYSLOG_HOST, SYSLOG_PORT))
    finally:
        sock.close()


def gen_firewall(*, hot: bool = False) -> str:
    kind = random.choice(["traffic", "traffic", "utm_virus", "utm_ips"]) if not hot else "traffic"
    now = datetime.now(timezone.utc)
    if kind == "utm_virus":
        src = random.choice(IPS_INT)
        dst = random.choice(IPS_EXT)
        return (
            f'<134>date={now:%Y-%m-%d} time={now:%H:%M:%S} devname="fw-edge-01" devid="FG100DDEMO" '
            f'vd="root" logid="0211008192" type="utm" subtype="virus" level="alert" '
            f'srcip={src} dstip={dst} srcport={random.randint(1024,65535)} dstport=80 '
            f'srcintf="lan" dstintf="wan1" proto=6 action=blocked policyid={random.randint(1,99)} '
            f'filename="demo.exe" url="http://mal.example/demo.exe" msg="virus detected" '
            f'sessionid={random.randint(100000,999999)}'
        )
    if kind == "utm_ips":
        src = random.choice(IPS_EXT)
        dst = random.choice(IPS_INT)
        return (
            f'date={now:%Y-%m-%d} time={now:%H:%M:%S} devname="fw-edge-01" devid="FG100DDEMO" '
            f'vd="root" logid="0419016384" type="utm" subtype="ips" level="critical" '
            f'srcip={src} dstip={dst} srcport={random.randint(1024,65535)} dstport=445 '
            f'srcintf="wan1" dstintf="lan" proto=6 action=dropped '
            f'attack="MS.SMB.Remote.Code.Execution" policyid={random.randint(1,99)} '
            f'msg="IPS signature match" sessionid={random.randint(100000,999999)}'
        )
    action = "deny" if hot else random.choice(["deny", "deny", "accept", "deny"])
    src = random.choice(IPS_EXT if action == "deny" else IPS_INT)
    if hot:
        dst = random.choice(HOT_DST)
    else:
        dst = random.choice(IPS_INT if action == "deny" else IPS_EXT)
    port = random.choice([22, 443, 3389, 8080, 53])
    level = "warning" if action == "deny" else "notice"
    return (
        f'<134>date={now:%Y-%m-%d} time={now:%H:%M:%S} '
        f'devname="fw-edge-01" devid="FG100DDEMO" vd="root" logid="0000000013" '
        f'type="traffic" subtype="forward" level="{level}" '
        f'srcip={src} dstip={dst} srcport={random.randint(1024,65535)} '
        f'dstport={port} srcintf="wan1" dstintf="lan" proto=6 action={action} '
        f'policyid={random.randint(1,99)} policyname="demo-pol" '
        f'sessionid={random.randint(100000,999999)} msg="demo traffic {action}"'
    )


def gen_windows(*, kind: str = "logon") -> dict:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if kind == "audit_cleared":
        return {
            "TimeCreated": now,
            "EventID": 1102,
            "Channel": "Security",
            "ProviderName": "Microsoft-Windows-Eventlog",
            "Computer": "win-dc01.lab.local",
            "SubjectUserName": "a.admin",
            "Message": "The audit log was cleared",
        }
    if kind == "spray":
        return {
            "TimeCreated": now,
            "EventID": 4625,
            "Channel": "Security",
            "ProviderName": "Microsoft-Windows-Security-Auditing",
            "Computer": "win-dc01.lab.local",
            "TargetUserName": random.choice(USERS),
            "IpAddress": SPRAY_SRC,
            "LogonType": 3,
            "Message": "An account failed to log on",
        }
    failed = random.random() < 0.7
    return {
        "TimeCreated": now,
        "EventID": 4625 if failed else 4624,
        "Channel": "Security",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "Computer": random.choice(HOSTS),
        "TargetUserName": random.choice(USERS),
        "IpAddress": random.choice(IPS_EXT if failed else IPS_INT),
        "LogonType": 3,
        "Message": "An account failed to log on" if failed else "An account was successfully logged on",
    }


def gen_cloud() -> dict:
    failed = random.random() < 0.6
    return {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "vendor": random.choice(["EntraID", "Okta"]),
        "app": "Microsoft 365",
        "user": f"{random.choice(USERS)}@contoso.example",
        "ip": random.choice(IPS_EXT),
        "result": "failure" if failed else "success",
        "action": "login_failed" if failed else "login_success",
        "mfa": not failed,
        "geo": random.choice(["IT", "FI", "US", "DE"]),
        "message": "Generated cloud auth event",
    }


def gen_siem() -> dict:
    return {
        "AlertId": f"CY-{random.randint(20000, 29999)}",
        "DetectionTime": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "Product": "Cynet",
        "Severity": random.choice(["low", "medium", "high"]),
        "Hostname": random.choice(HOSTS),
        "User": random.choice(USERS),
        "SourceIP": random.choice(IPS_INT),
        "Activity": random.choice(["Suspicious Connection", "Policy Violation", "Malware Detected"]),
        "Description": "Generated SIEM export event",
        "category": "demo",
    }


def wait_for_api() -> None:
    for _ in range(60):
        try:
            with urllib.request.urlopen(f"{API_URL}/health", timeout=2) as resp:
                if resp.status == 200:
                    return
        except Exception:
            time.sleep(2)
    raise RuntimeError("API not reachable")


def main() -> None:
    print(f"log-generator targeting {API_URL} syslog={SYSLOG_HOST}:{SYSLOG_PORT}")
    wait_for_api()
    generators = [
        ("firewall", "syslog"),
        ("firewall_hot", "http"),
        ("windows", "http"),
        ("windows_spray", "http"),
        ("windows_audit", "http"),
        ("cloud_auth", "http"),
        ("siem_export", "http"),
        ("firewall", "http"),
    ]
    while True:
        kind, channel = random.choice(generators)
        try:
            if kind == "firewall" and channel == "syslog":
                send_syslog(gen_firewall())
            elif kind == "firewall":
                post_ingest(gen_firewall(), "firewall")
            elif kind == "firewall_hot":
                post_ingest(gen_firewall(hot=True), "firewall")
            elif kind == "windows_spray":
                post_ingest(gen_windows(kind="spray"), "windows")
            elif kind == "windows_audit":
                # rarer: only sometimes emit 1102
                if random.random() < 0.35:
                    post_ingest(gen_windows(kind="audit_cleared"), "windows")
                else:
                    post_ingest(gen_windows(), "windows")
            elif kind == "windows":
                post_ingest(gen_windows(), "windows")
            elif kind == "cloud_auth":
                post_ingest(gen_cloud(), "cloud_auth")
            else:
                post_ingest(gen_siem(), "siem_export")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            print(f"warn: {exc}")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
