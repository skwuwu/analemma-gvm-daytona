#!/usr/bin/env bash
# Workspace setup: copy default configs into /app/config if not already present.
# Runs once after `daytona create` / devcontainer postCreate.

set -euo pipefail

CONFIG_SRC="/workspaces/config"
CONFIG_DST="/app/config"
DATA_DIR="/app/data"

echo "Setting up Analemma GVM workspace..."

# Config files
mkdir -p "${CONFIG_DST}/policies" "${DATA_DIR}"

for f in proxy.toml srr_network.toml srr_semantic.toml secrets.toml operation_registry.toml; do
    if [ ! -f "${CONFIG_DST}/${f}" ]; then
        cp "${CONFIG_SRC}/${f}" "${CONFIG_DST}/${f}"
        echo "  Copied ${f}"
    else
        echo "  Skipped ${f} (already exists)"
    fi
done

if [ ! -f "${CONFIG_DST}/policies/global.toml" ]; then
    cp "${CONFIG_SRC}/policies/global.toml" "${CONFIG_DST}/policies/global.toml"
    echo "  Copied policies/global.toml"
fi

echo ""
echo "Setup complete."
echo "  Config: ${CONFIG_DST}/proxy.toml"
echo "  Data:   ${DATA_DIR}/"
echo ""
echo "To start the proxy:"
echo "  make start"
echo "  # or: GVM_SECRETS_KEY=<32-byte-key> gvm-proxy --config ${CONFIG_DST}/proxy.toml"
