# Analemma GVM — Daytona workspace shortcuts

CONFIG    ?= /app/config/proxy.toml
PROXY_URL ?= http://127.0.0.1:8080
WAL_PATH  ?= /app/data/audit.wal

.PHONY: start stop demo logs events stats check-deny check-allow tail-wal help

help:
	@echo "Analemma GVM workspace targets:"
	@echo "  make start        Start GVM proxy (requires GVM_SECRETS_KEY env var)"
	@echo "  make stop         Kill running proxy"
	@echo "  make demo         Run the 3-scenario Daytona demo"
	@echo "  make logs         Tail proxy logs"
	@echo "  make events       List recent WAL events (gvm-cli)"
	@echo "  make stats        Show governance stats (gvm-cli)"
	@echo "  make check-deny   Send a forgery request (expect 403 Deny)"
	@echo "  make check-allow  Send a legitimate read (expect 200 Allow)"
	@echo "  make tail-wal     Tail raw WAL file"

start:
	@if [ -z "$$GVM_SECRETS_KEY" ]; then \
	    echo "ERROR: GVM_SECRETS_KEY not set."; \
	    echo "  export GVM_SECRETS_KEY=$$(openssl rand -hex 16)"; \
	    exit 1; \
	fi
	GVM_CONFIG=$(CONFIG) GVM_SECRETS_KEY=$$GVM_SECRETS_KEY gvm-proxy > /app/data/proxy.log 2>&1 &
	@sleep 1 && echo "Proxy started on $(PROXY_URL)"

stop:
	@pkill gvm-proxy && echo "Stopped." || echo "No proxy running."

demo:
	@pip install -q requests rich 2>/dev/null || true
	GVM_PROXY_URL=$(PROXY_URL) GVM_WAL_PATH=$(WAL_PATH) python demo.py

logs:
	@tail -f /app/data/proxy.log 2>/dev/null || echo "No log file yet — run 'make start'"

events:
	gvm events list --limit 20

stats:
	gvm stats

check-deny:
	@echo "Forgery: declares read, sends POST /v1/transfers (expect 403)..."
	@curl -s -X POST http://api.stripe.com/v1/transfers \
	    --proxy $(PROXY_URL) \
	    -H 'X-GVM-Agent-Id: test-agent' \
	    -H 'X-GVM-Operation: gvm.payment.read' \
	    -H 'X-GVM-Resource: {"sensitivity":"low","service":"stripe"}' \
	    -H 'X-GVM-Context: {}' \
	    -H 'Content-Type: application/json' \
	    -d '{"amount":50000}' | jq .

check-allow:
	@echo "Legitimate read: GET /v1/charges (expect 200 Allow)..."
	@curl -s -X GET http://api.stripe.com/v1/charges \
	    --proxy $(PROXY_URL) \
	    -H 'X-GVM-Agent-Id: test-agent' \
	    -H 'X-GVM-Operation: gvm.payment.read' \
	    -H 'X-GVM-Resource: {"sensitivity":"low","service":"stripe"}' \
	    -H 'X-GVM-Context: {}' | jq .

tail-wal:
	@tail -f $(WAL_PATH) 2>/dev/null | while read line; do \
	    echo "$$line" | jq -r '"\(.timestamp) [\(.decision)] \(.operation) → \(.transport.method) \(.transport.host)\(.transport.path)"' 2>/dev/null || echo "$$line"; \
	done
