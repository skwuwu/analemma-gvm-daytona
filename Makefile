# Analemma GVM — Daytona workspace shortcuts
# Usage: make <target>

CONFIG ?= /app/config/proxy.toml
PROXY_URL ?= http://127.0.0.1:8080

.PHONY: start stop logs events stats check-deny check-allow tail-wal help

help:
	@echo "Analemma GVM workspace targets:"
	@echo "  make start        Start GVM proxy (requires GVM_SECRETS_KEY env var)"
	@echo "  make stop         Kill running proxy"
	@echo "  make logs         Tail proxy logs"
	@echo "  make events       List recent WAL events (gvm-cli)"
	@echo "  make stats        Show governance stats (gvm-cli)"
	@echo "  make check-deny   Send a CRITICAL request (expect 403 Deny)"
	@echo "  make check-allow  Send a Medium request (expect 200 Allow)"
	@echo "  make tail-wal     Tail raw WAL file"

start:
	@if [ -z "$$GVM_SECRETS_KEY" ]; then \
	    echo "ERROR: GVM_SECRETS_KEY not set."; \
	    echo "  export GVM_SECRETS_KEY=\$$(openssl rand -hex 16)"; \
	    exit 1; \
	fi
	GVM_CONFIG=$(CONFIG) gvm-proxy &
	@echo "Proxy started on $(PROXY_URL)"

stop:
	@pkill gvm-proxy || echo "No proxy running"

logs:
	@tail -f /app/data/proxy.log 2>/dev/null || echo "No log file yet — run 'make start'"

events:
	gvm events list --limit 20

stats:
	gvm stats

check-deny:
	@echo "Sending CRITICAL sensitivity request (expect 403 Deny)..."
	@curl -s -X POST $(PROXY_URL) \
	    -H 'X-GVM-Operation: delete.production_database' \
	    -H 'X-GVM-Resource: {"sensitivity":"Critical","type":"database"}' \
	    -H 'X-GVM-Context: {"agent_id":"dev-agent","tenant_id":"test"}' \
	    -H 'Content-Type: application/json' \
	    -d '{"confirm":true}' | jq .

check-allow:
	@echo "Sending Medium sensitivity request (expect 200 Allow)..."
	@curl -s -X POST $(PROXY_URL) \
	    -H 'X-GVM-Operation: read.document' \
	    -H 'X-GVM-Resource: {"sensitivity":"Medium","type":"document"}' \
	    -H 'X-GVM-Context: {"agent_id":"dev-agent","tenant_id":"test"}' \
	    -H 'Content-Type: application/json' \
	    -d '{"id":"doc-001"}' | jq . || echo "(upstream not configured — check proxy.toml)"

tail-wal:
	@tail -f /app/data/audit.wal 2>/dev/null | while read line; do \
	    echo "$$line" | jq -r '"\(.timestamp) [\(.decision)] \(.operation) agent=\(.agent_id)"' 2>/dev/null || echo "$$line"; \
	done
