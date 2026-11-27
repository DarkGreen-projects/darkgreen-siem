# Lab proof reports

Mini-report automatici su **regole**, **copertura**, **mappa test delle upgrade** e **impatto lean**, con grafici SVG.

## Genera report

```bash
python -m tests.lab_proof.generate_report
# oppure includi un run pytest nel report:
python -m tests.lab_proof.generate_report --with-pytest
```

Output in `tests/lab_proof/out/latest/`:

| File | Contenuto |
|------|-----------|
| `report.md` | Mini-report Markdown (GitHub-friendly) |
| `report.html` | Dashboard HTML con KPI + immagini |
| `metrics.json` | Metriche machine-readable |
| `charts/*.svg` | Grafici regole / MITRE / test areas / lean impact |

## Test

```bash
pytest tests/test_lab_proof_report.py tests/test_optimization_regressions.py -q
```

Queste prove vanno eseguite a ogni upgrade: validano lean Compose, installer, moduli graph/RAG e rigenerano gli artifact del report.

## Stress harness (live lab)

Oltre al lab_proof statico, per latenza/noise sotto carico:

```bash
python scripts/lab_stress_populate.py --events 1000 --profile mix --login --seed-dispositions 10
python scripts/lab_stress_measure.py --login
```

Report pubblicati in [docs/lab-reports/latest/stress-report.md](../../docs/lab-reports/latest/stress-report.md).  
Gate CI: `.github/workflows/stress-lab.yml`. Pytest hardening: `tests/test_hardening_enhancements.py`.
