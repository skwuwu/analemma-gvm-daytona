# Analemma GVM — Daytona Workspace

Development environment for integrating and testing the [Analemma GVM](https://github.com/skwuwu/Analemma-GVM) governance proxy.

Opens in a pre-configured workspace with `gvm-proxy` and `gvm-cli` already installed.
Policy changes reload live — no restart needed.

## Quick Start

```bash
# Open in Daytona
daytona create https://github.com/skwuwu/analemma-gvm-daytona

# Inside the workspace — set your secrets key and start the proxy
export GVM_SECRETS_KEY=$(openssl rand -hex 16)
make start

# Test governance decisions
make check-deny    # CRITICAL → 403 Deny
make check-allow   # Medium   → 200 Allow

# Watch audit trail
make tail-wal
```

## Workspace Structure

```
.devcontainer/
  devcontainer.json     # VS Code / Daytona devcontainer config
daytona.yaml            # Daytona workspace definition
config/
  proxy.toml            # Proxy config (hot_reload enabled)
  global.toml           # Top-level policy (edit without restart)
  srr_network.toml      # Network routing rules
  srr_semantic.toml     # Semantic operation rules
  secrets.toml          # API credentials (add your own — do not commit)
  operation_registry.toml
  policies/
    global.toml         # Policy file (hot_reload watches this directory)
scripts/
  setup.sh              # Runs once at workspace creation
Makefile                # Dev shortcuts (make help for full list)
```

## Editing Policies

Policy files are hot-reloaded. Edit and save — the proxy picks up changes within 1 second:

```bash
# Example: deny all PII access
cat >> config/policies/global.toml << 'EOF'

[[rules]]
id       = "deny-pii"
priority = 90
conditions = [{ field = "resource.sensitivity", operator = "Eq", value = "PII" }]
decision  = { type = "Deny" }
ic_level  = 3
EOF
# No restart needed
```

## Core Repository

Source: [skwuwu/Analemma-GVM](https://github.com/skwuwu/Analemma-GVM)
Docker image: `ghcr.io/skwuwu/analemma-gvm:latest`
