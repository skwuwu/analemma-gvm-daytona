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

## Core repository

Source and docs: [skwuwu/Analemma-GVM](https://github.com/skwuwu/Analemma-GVM)
Docker image: `ghcr.io/skwuwu/analemma-gvm:latest`
