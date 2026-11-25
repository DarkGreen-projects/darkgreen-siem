# Lab reports (pubblicati)

Snapshot reali generati dalla suite `tests/lab_proof` e versionati nel repo per GitHub.

## Ultimo report

| File | Link |
|------|------|
| Report Markdown | [latest/report.md](latest/report.md) |
| Report HTML | [latest/report.html](latest/report.html) |
| Metriche JSON | [latest/metrics.json](latest/metrics.json) |
| **Lab populate (live)** | [latest/lab-populate-report.md](latest/lab-populate-report.md) |
| Metriche populate | [latest/lab-populate-metrics.json](latest/lab-populate-metrics.json) |
| Screenshot dashboard | [../assets/dashboard-lab.png](../assets/dashboard-lab.png) |

### Grafici

| Chart | Anteprima |
|-------|-----------|
| Lean impact | ![lean](latest/charts/lean_impact.svg) |
| Rule quality | ![quality](latest/charts/rule_quality.svg) |
| Rules by type | ![types](latest/charts/rules_by_type.svg) |
| Rules by severity | ![sev](latest/charts/rules_by_severity.svg) |
| MITRE | ![mitre](latest/charts/mitre_coverage.svg) |
| Tests by upgrade area | ![tests](latest/charts/tests_by_upgrade_area.svg) |
| Lab events by source | ![lab src](latest/charts/lab_events_by_source.svg) |
| Lab alerts by status | ![lab st](latest/charts/lab_alerts_by_status.svg) |

## Rigenerare e pubblicare

```bash
python -m tests.lab_proof --with-pytest
```

Copia automatica in `docs/lab-reports/latest/` + `tests/lab_proof/out/latest/`.

Vedi anche [../README.md](../README.md) e [../../tests/lab_proof/README.md](../../tests/lab_proof/README.md).
