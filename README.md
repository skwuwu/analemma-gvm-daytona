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
requirements.txt            # daytona, rich
```

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
