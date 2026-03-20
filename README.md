# Analemma GVM — Daytona Demo

Three governance scenarios that show what VPC firewalls miss.
Runs on [Daytona Cloud](https://app.daytona.io) — no local setup beyond a Daytona account.

## What you'll see

| Scenario | What happens |
|----------|-------------|
| 1. Semantic Forgery | Agent declares `gvm.payment.read`, sends `POST /v1/transfers`. VPC passes (domain allowed). GVM detects method/path mismatch → 403 Deny. |
| 2. Batch Forensics | 100 calls, 3 injected forgeries. WAL records every decision. Merkle chain verifies audit integrity. |
| 3. API Key Isolation | Stripe key never reaches agent process. GVM injects post-enforcement. `--sandbox` blocks credential exfiltration at syscall level. |

## Quick Start

### Daytona Cloud (recommended)

```bash
daytona login
daytona create https://github.com/skwuwu/analemma-gvm-daytona
```

Inside the workspace (two terminals):

```bash
# Terminal 1 — start proxy
make start

# Terminal 2 — run demo
make demo
```

Total time: ~3 minutes.

### Local

Requires [Daytona CLI](https://www.daytona.io/docs/installation/installation/) installed locally.

```bash
daytona create https://github.com/skwuwu/analemma-gvm-daytona
# workspace opens; same two-terminal flow above
```

## Workspace layout

```
.devcontainer/
  devcontainer.json     # installs gvm-proxy + gvm-cli, mounts config/
config/
  proxy.toml            # proxy config (hot_reload enabled)
  srr_network.toml      # network rules: GET stripe → Allow, POST transfers → Deny
  secrets.toml          # API credentials (held by proxy, never exposed to agent)
  policies/
    global.toml         # ABAC policy
Makefile                # make help for full target list
demo.py                 # demo script (Python, requests + rich)
```

## Editing rules live

Policy files hot-reload — edit and save, proxy picks up changes within 1 second:

```bash
# Example: block all POST to a new endpoint
cat >> config/srr_network.toml << 'EOF'

[[rules]]
id          = "deny-example"
priority    = 150
method      = "POST"
host_pattern = { type = "Exact", value = "api.example.com" }
path_pattern = { type = "Prefix", value = "/v1/withdraw" }
decision    = { type = "Deny" }
EOF
# No restart needed — make check-deny to verify
```

## Core repository

Source and docs: [skwuwu/Analemma-GVM](https://github.com/skwuwu/Analemma-GVM)
Docker image: `ghcr.io/skwuwu/analemma-gvm:latest`
