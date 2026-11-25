"""Generate and validate lab-proof mini-report (charts + metrics)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.lab_proof.generate_report import generate_lab_proof_report


def test_generate_lab_proof_report_artifacts(tmp_path: Path):
    out = tmp_path / "latest"
    metrics = generate_lab_proof_report(
        repo=ROOT, out_dir=out, run_pytest=False, publish_docs=False
    )

    assert (out / "report.md").is_file()
    assert (out / "report.html").is_file()
    assert (out / "metrics.json").is_file()
    charts = list((out / "charts").glob("*.svg"))
    assert len(charts) >= 5

    data = json.loads((out / "metrics.json").read_text(encoding="utf-8"))
    assert data["rules"]["coverage"]["rules_total"] >= 1
    assert data["tests"]["tests_estimated"] >= 50
    assert data["lean"]["pass_pct"] >= 70
    assert metrics["artifacts"]["charts"]


def test_rule_coverage_quality_bounds():
    metrics = generate_lab_proof_report(
        repo=ROOT,
        out_dir=ROOT / "tests" / "lab_proof" / "out" / "latest",
        run_pytest=False,
        publish_docs=True,
    )
    cov = metrics["rules"]["coverage"]
    assert 0 <= cov["quality_score"] <= 100
    assert cov["rules_total"] >= 8
    assert any(r["impact_weight"] >= 3 for r in metrics["rules"]["top_impact_rules"])
    docs_latest = ROOT / "docs" / "lab-reports" / "latest"
    assert (docs_latest / "report.md").is_file()
    assert (docs_latest / "charts" / "lean_impact.svg").is_file()
