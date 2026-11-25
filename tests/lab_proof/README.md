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
