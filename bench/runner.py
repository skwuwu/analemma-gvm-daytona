#!/usr/bin/env python3
"""
GVM overhead benchmark runner — executes inside the sandbox.

Usage:
  python3 runner.py <mock_port> <proxy_port> <deny_url> <delay_floor_ms> [mode]

mode:
  all   (default) — direct, gvm_allow, gvm_delay, gvm_deny
  deny             — direct + gvm_deny only (used for batch_window comparison)

Outputs a single-line JSON object to stdout.
"""

import http.client
import json
import statistics
import sys
import time

MOCK_PORT      = int(sys.argv[1])  if len(sys.argv) > 1 else 9090
PROXY_PORT     = int(sys.argv[2])  if len(sys.argv) > 2 else 8080
DENY_URL       = sys.argv[3]       if len(sys.argv) > 3 else "http://api.stripe.com/v1/transfers"
DELAY_FLOOR_MS = int(sys.argv[4])  if len(sys.argv) > 4 else 100
MODE           = sys.argv[5]       if len(sys.argv) > 5 else "all"

ALLOW_URL = "http://api.stripe.com/v1/charges"
DELAY_URL = "http://unknown-api.com/v1/data"

N_WARMUP = 10
N_BENCH  = 50


def direct_call():
    conn = http.client.HTTPConnection("127.0.0.1", MOCK_PORT, timeout=8)
    t0 = time.perf_counter()
    try:
        conn.request("GET", "/v1/charges")
        resp = conn.getresponse()
        resp.read()
        code = resp.status
    except Exception:
        code = 0
    elapsed_ms = (time.perf_counter() - t0) * 1000
    conn.close()
    return code, elapsed_ms


def proxy_call(method, target_url, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", PROXY_PORT, timeout=8)
    headers = {}
    if body is not None:
        headers["Content-Type"] = "application/json"
    t0 = time.perf_counter()
    try:
        conn.request(method, target_url, body=body, headers=headers)
        resp = conn.getresponse()
        resp.read()
        code = resp.status
    except Exception:
        code = 0
    elapsed_ms = (time.perf_counter() - t0) * 1000
    conn.close()
    return code, elapsed_ms


def measure(fn, n_warmup=N_WARMUP, n=N_BENCH):
    for _ in range(n_warmup):
        fn()
    samples = []
    for _ in range(n):
        _, ms = fn()
        samples.append(ms)
    s = sorted(samples)
    return {
        "n":    n,
        "min":  round(s[0], 3),
        "p50":  round(s[n // 2], 3),
        "p95":  round(s[max(0, int(n * 0.95) - 1)], 3),
        "p99":  round(s[max(0, int(n * 0.99) - 1)], 3),
        "max":  round(s[-1], 3),
        "mean": round(statistics.mean(s), 3),
    }


if MODE == "deny":
    results = {
        "direct":         measure(direct_call),
        "gvm_deny":       measure(lambda: proxy_call("POST", DENY_URL, b'{"amount":15000}')),
        "delay_floor_ms": DELAY_FLOOR_MS,
    }
else:
    results = {
        "direct":         measure(direct_call),
        "gvm_allow":      measure(lambda: proxy_call("GET",  ALLOW_URL)),
        "gvm_delay":      measure(lambda: proxy_call("POST", DELAY_URL, b'{"amount":1}')),
        "gvm_deny":       measure(lambda: proxy_call("POST", DENY_URL,  b'{"amount":15000}')),
        "delay_floor_ms": DELAY_FLOOR_MS,
    }

print(json.dumps(results))
