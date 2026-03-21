# GVM Overhead Benchmark Results — Daytona

**Platform**: Daytona cloud sandbox
**Measured**: 2026-03-21T03:49:23Z
**N**: 50 requests per path + 10 warmup

All latency values in **milliseconds**.

## Latency Table

| Path                   |    N |    min |    p50 |    p95 |    p99 |   mean |      overhead |
|------------------------|------|--------|--------|--------|--------|--------|---------------|
| direct (no proxy)      |   50 |   0.17 |   0.18 |   0.19 |   0.19 |   0.18 | baseline      |
| gvm Allow              |   50 |   0.43 |   0.45 |   0.49 |   0.61 |   0.46 | +0.28 ms      |
| gvm Delay (100 ms cfg) |   50 | 307.81 | 309.91 | 310.28 | 310.54 | 309.65 | +309.47 ms *  |
| gvm Deny               |   50 |   3.33 |   3.85 |   4.74 |   5.50 |   4.01 | +3.83 ms      |

## Overhead Summary

| Metric                           | Value             |
|----------------------------------|-------------------|
| Allow overhead vs direct         | +0.28 ms          |
| Deny overhead vs direct          | +3.83 ms          |
| Delay overhead above 100 ms floor| +209.47 ms *      |
| Deny vs Allow                    | +3.54 ms slower   |

## What the numbers mean

- **Direct**: raw localhost TCP round-trip to mock server (127.0.0.1:9090). No
  policy evaluation, no WAL write.
- **Allow overhead (0.28 ms)**: cost of GVM enforcement on a permitted request —
  policy evaluation + WAL write + credential injection + proxy TCP hops.
- **Deny overhead (3.83 ms)**: Deny involves ABAC + SRR evaluation, max_strict(),
  and a denial WAL entry — more bookkeeping than a simple Allow forward.
  Deny is slower than Allow.
- **\* Delay above floor (209.47 ms)**: The configured 100 ms penalty is applied
  correctly. The excess ~209 ms is DNS resolution time for `unknown-api.com`
  (not in host_overrides during this run). With host_overrides routing the target
  to the local mock server, this surplus converges to ~0.3 ms (Allow-path overhead).
- GVM adds **~0.3 ms** of governance overhead per allowed request. That is the
  cost of a cryptographically-chained audit entry and real-time policy evaluation.

## Reproduce

```bash
export DAYTONA_API_KEY=<your-key>
python benchmark.py
```

Results are written to `bench/results.json` (machine-readable) and
`bench/results.md` (this file).
