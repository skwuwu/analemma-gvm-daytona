# Analemma GVM — Daytona Demo

Five governance scenarios that show what VPC firewalls and agent frameworks miss.
Runs on [Daytona Cloud](https://app.daytona.io) — one script, no local setup.

## What you'll see

| # | Scenario | Tier | What happens |
|---|----------|------|-------------|
| 1 | API Key Theft Prevention | Tier 1 | Stripe key never reaches agent env. GVM injects post-enforcement. Agent can never read the key it used. |
| 2 | Graduated Enforcement | Tier 1 | Allow / Delay / Deny from one proxy. Not binary — SRR rules route by method + path. |
| 3 | Tamper-Evident Audit Log | Tier 1 | WAL is Merkle-chained. Tamper one entry → `gvm audit verify` reports `TAMPER DETECTED`. |
| 4 | Agent Forgery Detection | Tier 2 | `@ic(operation='gvm.storage.read')` but sends `POST /v1/transfers`. `max_strict(Allow, Deny) = Deny`. |
| 5 | Deny → Auto-Checkpoint Rollback | Tier 2 | Wire transfer denied → rollback to last checkpoint. ~210 tokens to recover vs ~1160 for full restart. |

## Quick Start

```bash
pip install daytona rich
export DAYTONA_API_KEY=<your-key>   # app.daytona.io → Settings → API Keys
python demo.py
```

Total time: ~3 minutes.

## Repository layout

```
config/
  proxy.toml                # proxy config
  srr_network.toml          # network rules: GET stripe → Allow, POST transfers → Deny
  secrets.toml              # API credentials (held by proxy, never exposed to agent)
  policies/global.toml      # ABAC policy
demo.py                     # 5-scenario demo (Daytona SDK)
benchmark.py                # overhead benchmark: direct vs GVM Allow/Delay/Deny
bench/
  runner.py                 # benchmark script uploaded and run inside the sandbox
  results.json              # last run results (machine-readable)
  results.md                # last run results (human-readable table)
requirements.txt            # daytona, rich
```

## Overhead Benchmark

Measures GVM proxy latency vs. direct HTTP (N=50 per path, 10 warmup):

| Path                   |  p50 (ms) |  p99 (ms) | mean (ms) | vs direct      |
|------------------------|-----------|-----------|-----------|----------------|
| direct (no proxy)      |      0.18 |      0.19 |      0.18 | baseline       |
| gvm Allow              |      0.45 |      0.61 |      0.46 | +0.28 ms       |
| gvm Delay (100 ms cfg) |    309.91 |    310.54 |    309.65 | +309.47 ms *   |
| gvm Deny               |      3.85 |      5.50 |      4.01 | +3.83 ms       |

GVM enforcement overhead per request: **~0.28 ms** (policy evaluation + WAL write + credential injection).
Deny is 3.5 ms **slower** than Allow — see below for why this is intentional.

\* Delay measured at 310 ms for a 100 ms configured floor: the excess ~210 ms is DNS resolution for `unknown-api.com` before upstream forwarding. With host_overrides correctly applied, expected overhead above floor is ~0.8 ms.

Full results: [`bench/results.md`](bench/results.md) · [`bench/results.json`](bench/results.json)

```bash
export DAYTONA_API_KEY=<your-key>
python benchmark.py
```

### Why Deny is slower than Allow

Allow returns a 200 immediately and writes the WAL entry in the background. Deny **blocks until
the WAL entry is durably flushed to disk** before returning the 403 — that fsync is the source
of the extra latency (~3.5 ms on this sandbox's network-attached storage).

This is a deliberate design choice. Cilium and Envoy use best-effort, fire-and-forget logging:
drop the packet (or pass it), emit a log event asynchronously, move on. That trade-off is
reasonable for network traffic — losing a flow log is operationally annoying but rarely
consequential.

AI agent actions are a different category. A wire transfer, a credential read, a file deletion —
these are high-stakes, often irreversible operations. If the denial record is lost before it
reaches durable storage, the audit chain breaks: a security review cannot confirm the action
was blocked, a compliance audit cannot verify the policy was enforced, and tamper detection
loses its anchor point. The cost of that loss far exceeds 3–4 ms of added latency on the
rejection path.

## No LLM required — what is mocked and why

This demo shows GVM's governance layer in isolation. LLM inference is not the subject being tested.

| What looks like an agent | What actually runs |
|--------------------------|-------------------|
| `FinanceAgent.read_data()` | `requests.get()` to a local Python mock server on port 9090 |
| `FinanceAgent.send_report()` | `requests.post()` to the same mock server |
| `FinanceAgent.wire_transfer()` | `requests.post()` — intercepted and Denied by GVM before reaching mock |
| `analyze()` (step 2) | Hardcoded print — simulates LLM reasoning step |
| Token cost numbers | Hardcoded constants in `TOKEN_COSTS` dict — representative, not measured |
| `GVMRollbackError` in scenario 5 | Real exception raised by the GVM SDK when proxy returns 403 + rollback signal |

**The mock server** (`http.server.HTTPServer` on port 9090) mimics an upstream API:
it returns `{"status": "ok"}` for every request, and echoes the `Authorization` header
for scenario 1. It has no business logic — it exists only to give the proxy a real TCP
connection to enforce against.

**What is real:**
- GVM proxy binary enforcing actual HTTP requests
- SRR rules matching on method + path
- WAL entries written with SHA-256 event hashes
- Merkle chain over those hashes (tamper detection in scenario 3)
- `@ic()` decorator injecting governance headers onto real `requests.Session` calls
- `GVMDeniedError` / `GVMRollbackError` raised from real proxy 403 responses

## Core repository

Source and docs: [skwuwu/Analemma-GVM](https://github.com/skwuwu/Analemma-GVM)
Docker image: `ghcr.io/skwuwu/analemma-gvm:latest`
