"""Regression checks for lean stack + installer + docs (upgrade proofs)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def test_compose_lean_defaults():
    text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "RULE_INTERVAL_SEC" in text
    assert "mem_limit" in text
    assert "log-generator" in text
    assert "demo" in text
    assert "INTERVAL_SEC" in text


def test_env_example_documents_lean_knobs():
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    for key in ("RULE_INTERVAL_SEC", "INTERVAL_SEC", "PURGE_INTERVAL_SEC", "RETENTION_DAYS"):
        assert key in text


def test_installer_pack_present():
    pack = ROOT / "tools" / "connect-installer"
    assert (pack / "DarkGreen-Setup.ps1").is_file()
    assert (pack / "DarkGreen-Setup.cmd").is_file()
    assert (pack / "build_exe.ps1").is_file()
    assert (pack / "connect-darkgreen.sh").is_file()
    assert (pack / "README.md").is_file()


def test_visible_interval_hook_exists():
    assert (ROOT / "web" / "src" / "hooks" / "useVisibleInterval.ts").is_file()


def test_alert_graph_and_fingerprint_modules():
    api = ROOT / "services" / "api"
    for name in (
        "entity_norm.py",
        "alert_graph.py",
        "alert_fingerprint.py",
        "rag_memory.py",
        "triage_brief.py",
        "copilot.py",
        "url_safety.py",
    ):
        assert (api / name).is_file(), name


def test_docs_setup_and_diagrams():
    docs = ROOT / "docs"
    assert (docs / "setup-guide.md").is_file()
    assert (docs / "architecture.md").is_file()
    for svg in (
        "setup-flow.svg",
        "pipeline-overview.svg",
        "alert-graph-flow.svg",
        "workbench-turno.svg",
    ):
        assert (docs / "assets" / svg).is_file(), svg


def test_seed_rules_have_types_and_ids():
    from services.api.rule_store import load_rules

    rules = load_rules(ROOT / "rules")
    assert len(rules) >= 8
    types = {str(r.get("type")) for r in rules}
    assert "match" in types or "threshold" in types
    assert "correlation" in types
    ids = [r.get("id") for r in rules]
    assert len(ids) == len(set(ids))
