# Lab stress report

Generated: 2026-11-27T09:25:42.258887Z
Profile: `mix` · events requested: 1000

## Volume

- Events inserted: **1000**
- Rules run duration: **278.9 ms**
- Total events (stats): **16572**
- Total alerts (stats): **340**
- Open alerts: **198**
- Dispositions seeded: **10**

## Latency (ms)

| Endpoint | p50 | p95 | max |
|----------|-----|-----|-----|
| alerts | 40.1 | 43.9 | 43.9 |
| queue | 44.2 | 58.0 | 58.0 |
| stats | 71.0 | 74.3 | 74.3 |
| brief | 17.1 | 22.8 | 22.8 |
| copilot | 28.1 | 29.2 | 29.2 |
| memory_stats | 16.0 | 16.0 | 16.0 |

## Noise hint sample (up to 200 alerts)

```json
{
  "likely_noise": 8,
  "likely_signal": 53,
  "unclear": 70,
  "missing": 69
}
```

## Observations

- GREEN: no endpoint p95 above 2s in this run.
- Post-hardening (secrets/syslog/rate/RAG/LLM/campaign/backfill): rules ~279 ms su 1k eventi; stack lab ancora usabile.
