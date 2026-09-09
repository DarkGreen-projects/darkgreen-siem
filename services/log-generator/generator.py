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

USERS = ["j.doe", "a.admin", "svc.backup", "r.rossi", "ext.vendor"]
HOSTS = ["win-dc01.lab.local", "win-ws42.lab.local", "fw-edge-01", "app-api-01"]
IPS_EXT = ["203.0.113.45", "203.0.113.88", "198.51.100.22", "198.51.100.80"]
IPS_INT = ["10.0.20.15", "10.0.20.8", "10.0.30.2", "10.0.50.3"]


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
        headers={"Content-Type": "application/json"},
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


def gen_firewall() -> str:
    action = random.choice(["deny", "deny", "accept", "deny"])
    src = random.choice(IPS_EXT if action == "deny" else IPS_INT)
    dst = random.choice(IPS_INT if action == "deny" else IPS_EXT)
    port = random.choice([22, 443, 3389, 8080, 53])
    return (
        f'date={datetime.now(timezone.utc):%Y-%m-%d} time={datetime.now(timezone.utc):%H:%M:%S} '
        f'devname="fw-edge-01" srcip={src} dstip={dst} srcport={random.randint(1024,65535)} '
        f'dstport={port} proto=tcp action={action} policyid={random.randint(1,99)} '
        f'msg="demo traffic {action}"'
    )


def gen_windows() -> dict:
    failed = random.random() < 0.7
    return {
        "TimeCreated": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "EventID": 4625 if failed else 4624,
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
        ("windows", "http"),
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
