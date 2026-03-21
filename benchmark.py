"""
Analemma GVM — Latency & Overhead Benchmark (Daytona)
======================================================

Measures per-request latency with and without the GVM proxy:

  direct    — GET straight to mock server, no proxy
  gvm_allow — GET through proxy, SRR Allow rule matches
  gvm_delay — POST through proxy, default Delay (100 ms) applies
  gvm_deny  — POST through proxy, SRR Deny rule matches

Results are printed to the console and saved to:
  bench/results.json   machine-readable
  bench/results.md     human-readable summary table

Run:
  export DAYTONA_API_KEY=<your-key>
  python benchmark.py
"""

import json
import os
import sys
import time
from datetime import timezone, datetime

from daytona import Daytona, DaytonaConfig, CreateSandboxFromImageParams, Image
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

_GVM_BASE = (
    "ghcr.io/skwuwu/analemma-gvm"
    "@sha256:40d56438e24d93d8db0a109c30b39219e9661eeaa09a002314b20db5aa67116c"
)
IMAGE = (
    Image.base(_GVM_BASE)
    .run_commands(
        "apt-get update && apt-get install -y --no-install-recommends "
        "python3 python3-pip curl && rm -rf /var/lib/apt/lists/*"
    )
)

PROXY_PORT     = 8080
MOCK_PORT      = 9090
PROXY_URL      = f"http://127.0.0.1:{PROXY_PORT}"
DENY_URL       = "http://api.stripe.com/v1/transfers"
DELAY_FLOOR_MS = 100
N_BENCH        = 50
CONFIG_DIR     = os.path.join(os.path.dirname(__file__), "config")

console = Console()


# ── Daytona helpers ──────────────────────────────────────────────────────────

def make_client() -> Daytona:
    api_key = os.environ.get("DAYTONA_API_KEY")
    if not api_key:
        console.print("[red]DAYTONA_API_KEY env var not set.[/red]")
        console.print("Get your key at https://app.daytona.io → Settings → API Keys")
        sys.exit(1)
    return Daytona(DaytonaConfig(api_key=api_key))


def run(sandbox, cmd: str, timeout: int = 30) -> str:
    r = sandbox.process.exec(cmd, timeout=timeout)
    return r.result or ""


def upload(sandbox, path: str, content: str):
    sandbox.fs.upload_file(content.encode("utf-8"), path)


def wait_for_proxy(sandbox, timeout: int = 40) -> bool:
    time.sleep(3)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            out = run(sandbox,
                f"bash -c '(echo > /dev/tcp/127.0.0.1/{PROXY_PORT}) 2>/dev/null "
                f"&& echo up || echo down'"
            )
            if "up" in out:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def setup_sandbox(sandbox):
    run(sandbox, "sudo chown -R user:user /app/data && mkdir -p /app/config/policies")
    for fname, dst in [
        ("proxy.toml",              "/app/config/proxy.toml"),
        ("secrets.toml",            "/app/config/secrets.toml"),
        ("srr_network.toml",        "/app/config/srr_network.toml"),
        ("srr_semantic.toml",       "/app/config/srr_semantic.toml"),
        ("operation_registry.toml", "/app/config/operation_registry.toml"),
        ("policies/global.toml",    "/app/config/policies/global.toml"),
    ]:
        src = os.path.join(CONFIG_DIR, fname)
        upload(sandbox, dst, open(src, encoding="utf-8").read())

    mock_script = (
        f"import http.server, json\n"
        f"class H(http.server.BaseHTTPRequestHandler):\n"
        f"  def log_message(self, *a): pass\n"
        f"  def _ok(self):\n"
        f"    b=b'{{\"status\":\"ok\"}}'\n"
        f"    self.send_response(200)\n"
        f"    self.send_header('Content-Type','application/json')\n"
        f"    self.send_header('Content-Length',str(len(b)))\n"
        f"    self.end_headers()\n"
        f"    self.wfile.write(b)\n"
        f"  def do_GET(self): self._ok()\n"
        f"  def do_POST(self): self.rfile.read(int(self.headers.get('Content-Length',0))); self._ok()\n"
        f"http.server.HTTPServer(('127.0.0.1',{MOCK_PORT}),H).serve_forever()\n"
    )
    upload(sandbox, "/tmp/mock_server.py", mock_script)
    upload(sandbox, "/tmp/start_mock.sh",
           "#!/bin/bash\nnohup python3 /tmp/mock_server.py > /tmp/mock.log 2>&1 &\n")
    run(sandbox, "chmod +x /tmp/start_mock.sh && /tmp/start_mock.sh")
    time.sleep(0.3)

    upload(sandbox, "/tmp/start_proxy.sh",
        "#!/bin/bash\n"
        "cd /app\n"
        "export GVM_SECRETS_KEY=demo-key-32bytes-padded-here\n"
        "nohup gvm-proxy > /tmp/proxy.log 2>&1 &\n"
    )
    run(sandbox, "chmod +x /tmp/start_proxy.sh && /tmp/start_proxy.sh")

    if not wait_for_proxy(sandbox):
        log = run(sandbox, "cat /tmp/proxy.log 2>/dev/null || echo '(no log)'")
        console.print(f"[red]Proxy failed to start:[/red]\n{log}")
        sys.exit(1)


# ── Results formatting ───────────────────────────────────────────────────────

def _pct(base: float, val: float) -> str:
    if base == 0:
        return "N/A"
    return f"+{((val - base) / base * 100):.0f}%"


def print_table(results: dict):
    direct_mean = results["direct"]["mean"]

    table = Table(
        title="GVM Overhead Benchmark — Daytona",
        border_style="cyan",
        show_lines=True,
    )
    table.add_column("Path",         style="bold white",  width=20)
    table.add_column("N",            style="dim",          width=5)
    table.add_column("min (ms)",     style="dim",          width=9)
    table.add_column("p50 (ms)",     style="cyan",         width=9)
    table.add_column("p95 (ms)",     style="yellow",       width=9)
    table.add_column("p99 (ms)",     style="red",          width=9)
    table.add_column("mean (ms)",    style="bold",         width=10)
    table.add_column("vs direct",    style="bold magenta", width=20)

    rows = [
        ("direct",    "direct (no proxy)", "green"),
        ("gvm_allow", "gvm  Allow",        "cyan"),
        ("gvm_delay", f"gvm  Delay {DELAY_FLOOR_MS}ms", "yellow"),
        ("gvm_deny",  "gvm  Deny",         "red"),
    ]
    for key, label, color in rows:
        r = results[key]
        mean = r["mean"]
        if key == "direct":
            overhead_str = "baseline"
        else:
            delta = round(mean - direct_mean, 2)
            overhead_str = f"+{delta:.2f} ms"
        table.add_row(
            f"[{color}]{label}[/{color}]",
            str(r["n"]),
            f"{r['min']:.2f}",
            f"{r['p50']:.2f}",
            f"{r['p95']:.2f}",
            f"{r['p99']:.2f}",
            f"{r['mean']:.2f}",
            overhead_str,
        )
    console.print(table)


def save_results(results: dict, timestamp: str):
    direct_mean = results["direct"]["mean"]
    allow_mean  = results["gvm_allow"]["mean"]
    deny_mean   = results["gvm_deny"]["mean"]
    delay_mean  = results["gvm_delay"]["mean"]

    overhead = {
        "allow_vs_direct_ms":   round(allow_mean - direct_mean, 3),
        "deny_vs_direct_ms":    round(deny_mean  - direct_mean, 3),
        "delay_above_floor_ms": round(delay_mean - direct_mean - DELAY_FLOOR_MS, 3),
        "deny_vs_allow_ms":     round(deny_mean  - allow_mean, 3),
    }

    payload = {
        "platform":      "daytona",
        "timestamp":     timestamp,
        "sandbox_image": _GVM_BASE,
        "n_warmup":      10,
        "n_bench":       N_BENCH,
        "delay_floor_ms": DELAY_FLOOR_MS,
        "deny_url":      DENY_URL,
        "results":       {k: v for k, v in results.items() if k != "delay_floor_ms"},
        "overhead":      overhead,
    }

    os.makedirs("bench", exist_ok=True)
    with open("bench/results.json", "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    col_w = [22, 6, 8, 8, 8, 8, 8, 14]
    def row(*cells):
        return "| " + " | ".join(str(c).ljust(w) for c, w in zip(cells, col_w)) + " |"

    header = row("Path", "N", "min", "p50", "p95", "p99", "mean", "overhead")
    sep    = row(*["-" * w for w in col_w])
    lines  = [header, sep]

    for key, label in [
        ("direct",    "direct (no proxy)"),
        ("gvm_allow", "gvm Allow"),
        ("gvm_delay", f"gvm Delay ({DELAY_FLOOR_MS} ms)"),
        ("gvm_deny",  "gvm Deny"),
    ]:
        r = results[key]
        m = r["mean"]
        if key == "direct":
            ov = "baseline"
        else:
            delta = round(m - direct_mean, 2)
            ov = f"+{delta:.2f} ms"
        lines.append(row(
            label, r["n"],
            f"{r['min']:.2f}", f"{r['p50']:.2f}",
            f"{r['p95']:.2f}", f"{r['p99']:.2f}", f"{r['mean']:.2f}",
            ov,
        ))

    allow_ov    = overhead["allow_vs_direct_ms"]
    deny_ov     = overhead["deny_vs_direct_ms"]
    floor_ov    = overhead["delay_above_floor_ms"]
    deny_vs_allow = overhead["deny_vs_allow_ms"]
    deny_relation = f"+{deny_vs_allow:.2f} ms slower" if deny_vs_allow >= 0 else f"{abs(deny_vs_allow):.2f} ms faster"

    md = f"""\
# GVM Overhead Benchmark Results — Daytona

**Platform**: Daytona cloud sandbox
**Measured**: {timestamp}
**N**: {payload['n_bench']} requests per path + {payload['n_warmup']} warmup

All latency values in **milliseconds**.

## Latency Table

{chr(10).join(lines)}

## Overhead Summary

| Metric                           | Value           |
|----------------------------------|-----------------|
| Allow overhead vs direct         | +{allow_ov:.2f} ms      |
| Deny overhead vs direct          | +{deny_ov:.2f} ms      |
| Delay overhead above {DELAY_FLOOR_MS} ms floor | +{floor_ov:.2f} ms      |
| Deny vs Allow                    | {deny_relation} |

## What the numbers mean

- **Direct**: raw localhost TCP round-trip to mock server (127.0.0.1:9090). No
  policy evaluation, no WAL write.
- **Allow overhead ({allow_ov:.2f} ms)**: cost of GVM enforcement on a permitted request —
  policy evaluation + WAL write + credential injection + proxy TCP hops.
- **Deny overhead ({deny_ov:.2f} ms)**: Deny involves ABAC + SRR evaluation, max_strict(),
  and a denial WAL entry — more bookkeeping than a simple Allow forward.
  {'Deny is slower than Allow.' if deny_vs_allow >= 0 else 'Deny is faster than Allow.'}
- **Delay above floor ({floor_ov:.2f} ms)**: The configured {DELAY_FLOOR_MS} ms penalty is applied
  correctly. Excess above the floor reflects upstream connection time. If
  host_overrides routes the delay target to the local mock server, this surplus
  converges to ~{allow_ov:.1f} ms (same as Allow-path overhead).
- GVM adds ~{allow_ov:.1f} ms of governance overhead per allowed request. That is the
  cost of a cryptographically-chained audit entry and real-time policy evaluation.

## Reproduce

```bash
export DAYTONA_API_KEY=<your-key>
python benchmark.py
```

Results are written to `bench/results.json` (machine-readable) and
`bench/results.md` (this file).
"""

    with open("bench/results.md", "w", encoding="utf-8") as f:
        f.write(md)

    console.print("[dim]Saved bench/results.json and bench/results.md[/dim]")


# ── Main ─────────────────────────────────────────────────────────────────────

def run_benchmark():
    console.print(Panel.fit(
        "[bold cyan]Analemma GVM — Overhead Benchmark[/bold cyan]\n"
        "[dim]direct vs. GVM Allow / Delay / Deny  |  N=50 per path[/dim]",
        border_style="cyan",
    ))

    client = make_client()
    sandbox = None

    try:
        with console.status("Creating Daytona sandbox…"):
            sandbox = client.create(
                CreateSandboxFromImageParams(image=IMAGE),
                timeout=120,
            )

        with console.status("Starting sandbox services (mock server + GVM proxy)…"):
            setup_sandbox(sandbox)

        console.print("[green]Proxy ready.[/green] Uploading bench runner…")
        upload(sandbox, "/tmp/bench_runner.py",
               open("bench/runner.py", encoding="utf-8").read())

        with console.status(f"Running benchmark (N={N_BENCH} × 4 paths + warmup)…"):
            raw = run(sandbox,
                f"python3 /tmp/bench_runner.py {MOCK_PORT} {PROXY_PORT} "
                f"'{DENY_URL}' {DELAY_FLOOR_MS}",
                timeout=180,
            )

        raw = raw.strip()
        if not raw:
            console.print("[red]Benchmark returned no output.[/red]")
            log = run(sandbox, "cat /tmp/proxy.log 2>/dev/null || echo '(no log)'")
            console.print(f"proxy log:\n{log[:400]}")
            return

        try:
            results = json.loads(raw)
        except json.JSONDecodeError as exc:
            console.print(f"[red]Failed to parse benchmark output:[/red] {exc}")
            console.print(f"raw: {raw[:400]}")
            return

        print_table(results)

        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        save_results(results, ts)

    finally:
        if sandbox:
            with console.status("Deleting sandbox…"):
                client.delete(sandbox)


if __name__ == "__main__":
    run_benchmark()
