# Architecture

## Overview

`sift-mcp` is a custom MCP server that turns Claude Code into an IR analyst against a real home network. All tools run on a SANS SIFT VM bridged onto the LAN; Claude Code on a separate workstation invokes them over stdio.

```
┌────────────────────┐
│ Claude Code        │  (any workstation with `claude` CLI installed)
│ (orchestrator)     │
└──────────┬─────────┘
           │ stdio / MCP
┌──────────▼─────────┐
│ server.py          │  Tool registry + dispatch
│   ├─ constraints   │  Path allowlist, case-id required
│   └─ audit         │  JSONL trail per session
└──────────┬─────────┘
           │
   ┌───────┴────────┬──────────┬──────────┬──────────┬────────┐
   ▼                ▼          ▼          ▼          ▼        ▼
 network          logs       memory      ioc       timeline  case
 (AdGuard,       (paramiko    (vol3)     (YARA,    (Plaso)   (JSON +
  nmap)           SSH)                    hashlib)            InfluxDB)
```

## Components

### `server.py`
Single MCP entry point. Registers tools from each module under a `<prefix>_*` namespace (`network_*`, `memory_*`, etc.) and dispatches calls based on prefix.

### `constraints.py`
Enforces what tools can touch *before* the dispatch:
- `ALLOWED_READ_PATHS` — forensic tools need broad read (`/var`, `/etc`, `/tmp`, etc.) but write is strict
- `ALLOWED_WRITE_PATHS` — only `/cases` and the server's own `logs/`
- `require_case(case_id)` — every finding-producing tool refuses to run without a case context, so nothing writes findings into the void

These run in Python, not in the prompt — a confused model can't talk its way around them.

### `audit.py`
Every dispatch logs a JSONL record to `logs/session-<ts>.jsonl` with timestamp, tool name, arguments, and result summary. Recovers from `kill -9` because each call flushes on write.

## Data Layer

Findings go three places:

1. **`/cases/<case_id>/`** — JSON case file + per-finding records + a Markdown report on demand
2. **InfluxDB `sift-ir` bucket** (`10.0.0.11:8086`, org `owen-homelab`) — one `ir_finding` measurement per finding, tagged with `case_id` and `severity`
3. **Home Assistant webhook** — high/critical findings POST to an HA automation that can trigger LED notifiers, Pushover, etc.

A Grafana dashboard (`SIFT-IR Findings`, UID `adc8967` on `10.0.0.11:3030`) reads the bucket and shows Active Cases, Findings by Severity, Total Findings, and Findings Over Time.

## Tool Modules

| Module | Tools | External deps |
|---|---|---|
| `network` | `network_dns_query`, `network_device_scan` | AdGuard HTTP API, `nmap` |
| `logs` | `logs_container`, `logs_list_containers` | `paramiko` → SSH to Docker host |
| `memory` | `memory_pslist`, `memory_netscan`, `memory_malfind`, `memory_cmdline`, `memory_dlllist` | Volatility 3 with kernel-specific ISF |
| `ioc` | `ioc_yara_scan`, `ioc_hash`, `ioc_list_rules` | `yara-python`, `hashlib` |
| `timeline` | `timeline_create`, `timeline_query` | Plaso (`log2timeline.py` + `psort.py`) |
| `case` | `case_create`, `case_add_finding`, `case_report` | `influxdb-client` |

## Design Choices

**stdio transport, not a daemon.** MCP is launched by Claude Code per session. That keeps the security model simple: tools only run when the user has a Claude session open, and there's no exposed network surface on the SIFT box.

**Per-device InfluxDB tokens.** The `.env` token is scoped to the `sift-ir` bucket only — even if the SIFT VM is compromised, the blast radius doesn't reach the homeassistant bucket or other homelab data.

**Real network, not lab data.** Live AdGuard logs, real Docker containers, an actual home LAN with smart-home traffic. Findings are reproducible because the data source isn't synthetic.

**Memory capture is a deliberate step.** No "auto-capture on every query" — `avml` is run explicitly when needed and the image stays in `~/sift-mcp/captures/`. Keeps the VM responsive and gives the analyst control over what's in scope.
