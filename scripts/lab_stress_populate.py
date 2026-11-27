#!/usr/bin/env python3
"""Lab stress harness: flood ingest, run rules, measure latencies, write report.

Examples:
  python scripts/lab_stress_populate.py --events 5000 --profile mix --run-rules
  python scripts/lab_stress_populate.py --events 1000 --profile signal --seed-dispositions 20
"""

from __future__ import annotations

import argparse
import json
import os
import random
import statistics
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "docs" / "lab-reports" / "latest"

USERS = ["j.doe", "a.admin", "svc.backup", "r.rossi", "ext.vendor"]
HOSTS = ["win-dc01.lab.local", "win-ws42.lab.local", "fw-edge-01", "app-api-01"]
IPS_EXT = ["203.0.113.45", "203.0.113.88", "198.51.100.22", "198.51.100.80"]
IPS_INT = ["10.0.20.15", "10.0.20.8", "10.0.30.2", "10.0.50.3"]
HOT_DST = ["203.0.113.200", "198.51.100.200", "192.0.2.200"]
SPRAY_SRC = "203.0.113.45"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def gen_firewall_deny(*, hot: bool = False) -> str:
    now = datetime.now(timezone.utc)
    src = random.choice(IPS_EXT)
    dst = random.choice(HOT_DST if hot else IPS_INT)
    port = random.choice([22, 443, 3389, 8080])
    return (
        f'<134>date={now:%Y-%m-%d} time={now:%H:%M:%S} '
        f'devname="fw-edge-01" devid="FG100DDEMO" vd="root" logid="0000000013" '
        f'type="traffic" subtype="forward" level="warning" '
        f'srcip={src} dstip={dst} srcport={random.randint(1024,65535)} '
        f'dstport={port} srcintf="wan1" dstintf="lan" proto=6 action=deny '
        f'policyid={random.randint(1,99)} policyname="demo-pol" '
        f'sessionid={random.randint(100000,999999)} msg="stress deny"'
    )


def gen_windows_fail() -> dict:
    return {
        "TimeCreated": _now_iso(),
        "EventID": 4625,
        "Channel": "Security",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "Computer": "win-dc01.lab.local",
        "TargetUserName": random.choice(USERS),
        "IpAddress": SPRAY_SRC,
        "LogonType": 3,
        "Message": "An account failed to log on",
    }


def gen_windows_success() -> dict:
    return {
        "TimeCreated": _now_iso(),
        "EventID": 4624,
        "Channel": "Security",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "Computer": "win-dc01.lab.local",
        "TargetUserName": random.choice(USERS),
        "IpAddress": SPRAY_SRC,
        "LogonType": 3,
        "Message": "An account was successfully logged on",
    }


def gen_cloud_fail() -> dict:
    return {
        "timestamp": _now_iso(),
        "vendor": "EntraID",
        "app": "Microsoft 365",
        "user": f"{random.choice(USERS)}@contoso.example",
        "ip": random.choice(IPS_EXT),
        "result": "failure",
        "action": "login_failed",
        "mfa": False,
        "geo": "FI",
        "message": "Stress cloud auth failure",
    }


def gen_malware() -> dict:
    return {
        "AlertId": f"CY-{random.randint(30000, 39999)}",
        "DetectionTime": _now_iso(),
        "Product": "Cynet",
        "Hostname": random.choice(HOSTS),
        "User": random.choice(USERS),
        "SourceIP": random.choice(IPS_INT),
        "SensorId": f"CY-SENSOR-{random.randint(1, 40)}",
        "Severity": "high",
        "Activity": "Malware Detected",
        "DetectionName": "Trojan.Generic.KD",
        "Description": "Stress Cynet malware with hash",
        "category": "malware",
        "mitre": "T1204.002",
        "FileName": "dropper.exe",
        "Sha256": "a" * 64,
        "ProcessName": "dropper.exe",
        "ProcessPath": "C:\\Temp\\dropper.exe",
        "CommandLine": "dropper.exe",
        "ParentProcess": "explorer.exe",
    }


def gen_suspicious_process() -> dict:
    return {
        "AlertId": f"CY-{random.randint(40000, 49999)}",
        "DetectionTime": _now_iso(),
        "Product": "Cynet",
        "Hostname": random.choice(HOSTS),
        "User": random.choice(USERS),
        "SourceIP": random.choice(IPS_INT),
        "SensorId": f"CY-SENSOR-{random.randint(1, 40)}",
        "Severity": "critical",
        "Activity": "Suspicious Process",
        "DetectionName": "Encoded PowerShell",
        "Description": "Stress Cynet suspicious process",
        "category": "execution",
        "mitre": "T1059.001",
        "ProcessName": "powershell.exe",
        "ProcessPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -enc AAAA",
        "ParentProcess": "winword.exe",
    }


NOISE_GENS = [
    ("firewall", lambda: gen_firewall_deny(hot=False)),
    ("windows", gen_windows_fail),
    ("cloud_auth", gen_cloud_fail),
]
SIGNAL_GENS = [
    ("firewall", lambda: gen_firewall_deny(hot=True)),
    ("siem_export", gen_malware),
    ("siem_export", gen_suspicious_process),
    ("windows", gen_windows_success),
]


class ApiClient:
    def __init__(self, base: str, token: str) -> None:
        self.base = base.rstrip("/")
        self.token = token

    def _req(
        self,
        method: str,
        path: str,
        *,
        body: dict | None = None,
        timeout: float = 60.0,
    ) -> tuple[int, Any, float]:
        data = None
        headers = {"Authorization": f"Bearer {self.token}"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(
            f"{self.base}{path}", data=data, headers=headers, method=method
        )
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                elapsed = time.perf_counter() - t0
                if not raw:
                    return resp.status, None, elapsed
                try:
                    return resp.status, json.loads(raw.decode("utf-8")), elapsed
                except json.JSONDecodeError:
                    return resp.status, raw.decode("utf-8", errors="replace"), elapsed
        except urllib.error.HTTPError as exc:
            elapsed = time.perf_counter() - t0
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"{method} {path} -> {exc.code}: {detail[:300]}") from exc

    def login(self, username: str, password: str) -> str:
        status, data, _ = self._req(
            "POST",
            "/api/auth/login",
            body={"username": username, "password": password},
        )
        if status >= 400 or not isinstance(data, dict):
            raise RuntimeError(f"login failed: {status} {data}")
        self.token = str(data["token"])
        return self.token

    def ingest_batch(self, events: list[dict]) -> int:
        _, data, _ = self._req("POST", "/api/ingest", body={"events": events})
        if isinstance(data, dict):
            return int(data.get("inserted") or 0)
        return 0

    def run_rules(self) -> tuple[Any, float]:
        _, data, elapsed = self._req("POST", "/api/rules/run", body={}, timeout=300.0)
        return data, elapsed

    def get(self, path: str) -> tuple[Any, float]:
        _, data, elapsed = self._req("GET", path)
        return data, elapsed


def pick_event(profile: str) -> tuple[str, Any]:
    if profile == "noise":
        gens = NOISE_GENS
    elif profile == "signal":
        gens = SIGNAL_GENS
    else:
        gens = SIGNAL_GENS if random.random() < 0.20 else NOISE_GENS
    source_type, fn = random.choice(gens)
    return source_type, fn()


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round((p / 100.0) * (len(ordered) - 1)))))
    return ordered[idx]


def measure(client: ApiClient) -> dict:
    latencies: dict[str, list[float]] = {
        "alerts": [],
        "queue": [],
        "stats": [],
        "brief": [],
        "copilot": [],
        "memory_stats": [],
    }
    stats, t = client.get("/api/stats")
    latencies["stats"].append(t)
    for _ in range(5):
        _, t = client.get("/api/alerts?limit=50")
        latencies["alerts"].append(t)
        _, t = client.get("/api/alerts/queue?limit=50")
        latencies["queue"].append(t)
        _, t = client.get("/api/stats")
        latencies["stats"].append(t)

    alerts, _ = client.get("/api/alerts?limit=20")
    alert_ids = []
    if isinstance(alerts, list):
        alert_ids = [a.get("id") for a in alerts if isinstance(a, dict) and a.get("id")]
    for aid in alert_ids[:5]:
        _, t = client.get(f"/api/alerts/{aid}/brief")
        latencies["brief"].append(t)
        try:
            _, _, t = client._req("POST", f"/api/alerts/{aid}/copilot-suggest", body={})
            latencies["copilot"].append(t)
        except Exception as exc:
            latencies.setdefault("copilot_errors", [])  # type: ignore[arg-type]
            latencies["copilot_errors"].append(str(exc)[:120])  # type: ignore[index]

    mem, t = client.get("/api/memory/stats")
    latencies["memory_stats"].append(t)

    noise_counts = {"likely_noise": 0, "likely_signal": 0, "unclear": 0, "missing": 0}
    sample_alerts, _ = client.get("/api/alerts?limit=200")
    if isinstance(sample_alerts, list):
        for a in sample_alerts:
            if not isinstance(a, dict):
                continue
            nh = (a.get("noise_hint") or "missing").lower()
            if nh in noise_counts:
                noise_counts[nh] += 1
            else:
                noise_counts["missing"] += 1

    summary = {
        "stats": stats if isinstance(stats, dict) else {},
        "memory": mem if isinstance(mem, dict) else {},
        "noise_hint_sample": noise_counts,
        "latency_ms": {
            k: {
                "n": len(v),
                "p50": round(percentile(v, 50) * 1000, 1),
                "p95": round(percentile(v, 95) * 1000, 1),
                "max": round(max(v) * 1000, 1) if v else 0.0,
                "mean": round(statistics.fmean(v) * 1000, 1) if v else 0.0,
            }
            for k, v in latencies.items()
            if isinstance(v, list) and v and isinstance(v[0], float)
        },
    }
    return summary


def seed_dispositions(client: ApiClient, n: int) -> int:
    alerts, _ = client.get("/api/alerts?status=open&limit=200")
    if not isinstance(alerts, list):
        return 0
    closed = 0
    for i, a in enumerate(alerts[:n]):
        if not isinstance(a, dict) or not a.get("id"):
            continue
        # Prefer FP on deny-ish titles, TP on malware
        title = (a.get("title") or "").lower()
        if "malware" in title or "cynet" in title or "powershell" in title:
            disp = "true_positive"
            note = "Stress seed: confirmed malicious activity for RAG learning priors."
        else:
            disp = "false_positive"
            note = "Stress seed: known scanner or lab noise, safe to demote as FP."
        try:
            client._req(
                "PATCH",
                f"/api/alerts/{a['id']}/status",
                body={
                    "status": "closed",
                    "disposition": disp,
                    "closure_note": note,
                },
            )
            closed += 1
        except Exception:
            continue
    return closed


def write_report(out_dir: Path, metrics: dict) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    metrics_path = out_dir / "stress-metrics.json"
    report_path = out_dir / "stress-report.md"
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    stats = metrics.get("after", {}).get("stats") or {}
    lat = metrics.get("after", {}).get("latency_ms") or {}
    lines = [
        "# Lab stress report",
        "",
        f"Generated: {metrics.get('generated_at')}",
        f"Profile: `{metrics.get('profile')}` · events requested: {metrics.get('events_requested')}",
        "",
        "## Volume",
        "",
        f"- Events inserted: **{metrics.get('inserted')}**",
        f"- Rules run duration: **{metrics.get('rules_run_ms')} ms**",
        f"- Total events (stats): **{stats.get('total_events')}**",
        f"- Total alerts (stats): **{stats.get('total_alerts')}**",
        f"- Open alerts: **{stats.get('open_alerts')}**",
        f"- Dispositions seeded: **{metrics.get('dispositions_seeded')}**",
        "",
        "## Latency (ms)",
        "",
        "| Endpoint | p50 | p95 | max |",
        "|----------|-----|-----|-----|",
    ]
    for name, row in lat.items():
        lines.append(
            f"| {name} | {row.get('p50')} | {row.get('p95')} | {row.get('max')} |"
        )
    lines.extend(
        [
            "",
            "## Noise hint sample (up to 200 alerts)",
            "",
            "```json",
            json.dumps(metrics.get("after", {}).get("noise_hint_sample") or {}, indent=2),
            "```",
            "",
            "## Observations",
            "",
        ]
    )
    red = []
    for name, row in lat.items():
        if float(row.get("p95") or 0) > 2000:
            red.append(f"- RED: `{name}` p95={row.get('p95')}ms (>2s)")
    if red:
        lines.extend(red)
    else:
        lines.append("- GREEN: no endpoint p95 above 2s in this run.")
    lines.append("")
    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {metrics_path}")
    print(f"Wrote {report_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="DarkGreen SIEM lab stress populate")
    parser.add_argument("--api", default=os.getenv("SIEM_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--token", default=os.getenv("SIEM_API_TOKEN", "dg-lab-token-compose"))
    parser.add_argument("--username", default=os.getenv("DEMO_USERNAME", "analyst"))
    parser.add_argument("--password", default=os.getenv("DEMO_PASSWORD", "darkgreen"))
    parser.add_argument("--login", action="store_true", help="Login as analyst instead of machine token")
    parser.add_argument("--events", type=int, default=5000)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--profile", choices=["mix", "noise", "signal"], default="mix")
    parser.add_argument("--run-rules", action="store_true", default=True)
    parser.add_argument("--no-run-rules", action="store_true")
    parser.add_argument("--seed-dispositions", type=int, default=30)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--measure-only", action="store_true")
    args = parser.parse_args()

    client = ApiClient(args.api, args.token)
    if args.login:
        client.login(args.username, args.password)
        print(f"Logged in as {args.username}")

    if args.measure_only:
        after = measure(client)
        metrics = {
            "generated_at": _now_iso(),
            "profile": "measure-only",
            "events_requested": 0,
            "inserted": 0,
            "rules_run_ms": 0,
            "dispositions_seeded": 0,
            "after": after,
        }
        write_report(args.out, metrics)
        return 0

    before = measure(client)
    inserted = 0
    batch: list[dict] = []
    t_ingest0 = time.perf_counter()
    for i in range(args.events):
        source_type, payload = pick_event(args.profile)
        batch.append(
            {
                "source_type": source_type,
                "ingest_channel": "http",
                "payload": payload,
            }
        )
        if len(batch) >= max(1, min(200, args.batch_size)):
            inserted += client.ingest_batch(batch)
            batch = []
            if (i + 1) % 500 == 0:
                print(f"  ingested ~{i + 1}/{args.events}")
    if batch:
        inserted += client.ingest_batch(batch)
    ingest_ms = round((time.perf_counter() - t_ingest0) * 1000, 1)
    print(f"Inserted {inserted} events in {ingest_ms} ms")

    rules_ms = 0.0
    rules_error = None
    if args.run_rules and not args.no_run_rules:
        print("Running rules…")
        try:
            _, elapsed = client.run_rules()
            rules_ms = round(elapsed * 1000, 1)
            print(f"Rules run in {rules_ms} ms")
        except Exception as exc:
            rules_error = str(exc)[:400]
            print(f"Rules run failed (continuing measure): {rules_error}")

    dispositions = 0
    if args.seed_dispositions > 0:
        # Need analyst token for alerts_write
        try:
            client.login(args.username, args.password)
        except Exception as exc:
            print(f"Skip dispositions (login failed): {exc}")
        else:
            dispositions = seed_dispositions(client, args.seed_dispositions)
            print(f"Seeded {dispositions} dispositions")

    after = measure(client)
    metrics = {
        "generated_at": _now_iso(),
        "profile": args.profile,
        "events_requested": args.events,
        "inserted": inserted,
        "ingest_ms": ingest_ms,
        "rules_run_ms": rules_ms,
        "rules_error": rules_error,
        "dispositions_seeded": dispositions,
        "before": before,
        "after": after,
    }
    write_report(args.out, metrics)
    return 0


if __name__ == "__main__":
    sys.exit(main())
