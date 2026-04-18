# sift-mcp

Autonomous incident response agent built on the [SANS SIFT Workstation](https://www.sans.org/tools/sift-workstation/) and [Protocol SIFT](https://github.com/teamdfir/protocol-sift). Submitted to the **Find Evil! hackathon (Apr 15 – Jun 15, 2026)**.

## What It Does

`sift-mcp` is a custom MCP server that gives Claude Code autonomous IR capabilities across two layers:

| Layer | Tools | Data Sources |
|---|---|---|
| Live Network Triage | DNS log analysis, device discovery, container log triage | AdGuard Home API, nmap, Docker SSH |
| Deep Forensics | Memory analysis, IOC scanning, timeline generation | Volatility3, YARA, Plaso, EZ Tools |

Findings flow through a structured audit trail into InfluxDB and Grafana, with optional Home Assistant alerts for high-severity events. The server runs as a persistent systemd service on the SIFT VM, analyzing a real home network with ~50 devices.

## Architecture

```
Claude Code (orchestrator)
        │
        │ stdio (MCP protocol)
        ▼
┌─────────────────────────────────────────┐
│              server.py                  │
│         MCP Tool Registry               │
├──────────────┬──────────────────────────┤
│  constraints.py  │  audit.py            │
│  (guardrails)    │  (structured log)    │
├──────────────┴──────────────────────────┤
│              tools/                     │
│  network.py  logs.py  memory.py         │
│  ioc.py      timeline.py  case.py       │
└─────────────────────────────────────────┘
        │                    │
        ▼                    ▼
  Live Network          Deep Forensics
  (AdGuard, nmap,       (Volatility3,
   Docker logs)          YARA, Plaso)
        │
        ▼
  InfluxDB (sift-ir bucket) → Grafana dashboard
  Home Assistant webhook (high-severity alerts)
```

See [`docs/architecture.md`](docs/architecture.md) for full detail.

## Judging Criteria Alignment

| Criterion | Implementation |
|---|---|
| **Autonomous Execution Quality** | Claude Code orchestrates full IR pipeline without human intervention; tools chain automatically from triage → forensics → report |
| **IR Accuracy** | Real network data — live AdGuard DNS logs, actual device inventory, real memory/disk artifacts |
| **Breadth & Depth** | 6 tool modules spanning live triage, memory forensics, IOC scanning, timeline analysis, and case management |
| **Constraint Implementation** | Architectural guardrails in `constraints.py`: read-only by default, path allowlist, no arbitrary exec, explicit confirmation for destructive ops — enforced at the MCP layer, not prompt-based |
| **Audit Trail Quality** | Structured JSON logs via `audit.py` for every tool call: timestamp, tool, args, result summary, severity |
| **Usability / Documentation** | Try-it-out instructions below; CLAUDE.md for AI-assisted operation; Grafana dashboard for findings visibility |

## Tools

| Tool | Module | Description |
|---|---|---|
| `network_dns_query` | network.py | Query AdGuard DNS logs for a host/IP |
| `network_device_scan` | network.py | nmap sweep, identify unknown devices |
| `logs_container` | logs.py | Tail/search Docker container logs via SSH |
| `memory_pslist` | memory.py | List processes from memory dump (Volatility3) |
| `memory_netscan` | memory.py | Network connections from memory |
| `memory_malfind` | memory.py | Find injected code in memory |
| `ioc_yara_scan` | ioc.py | YARA scan file or directory |
| `ioc_hash` | ioc.py | Hash a file (md5/sha1/sha256) |
| `timeline_create` | timeline.py | Run log2timeline on an artifact |
| `case_create` | case.py | Initialize a new case |
| `case_add_finding` | case.py | Record a finding with severity |
| `case_report` | case.py | Generate case report, write to InfluxDB |

## Requirements

- SANS SIFT Workstation (Ubuntu 24.04)
- Python 3.12+ with venv
- Claude Code (claude-code CLI)
- SSH access to Docker host (for container log triage)

## Try It Out

See [`docs/try-it-out.md`](docs/try-it-out.md) for full setup and usage instructions.

Quick start:
```bash
git clone https://github.com/mowen628/sift-mcp.git ~/sift-mcp
cd ~/sift-mcp
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # fill in your values
# Register MCP server with Claude Code
claude mcp add sift-mcp -- python /path/to/sift-mcp/server.py
claude  # start Claude Code — sift-mcp tools are now available
```

## Deliverables

- [x] GitHub repository
- [ ] 5-minute demo video
- [ ] Architecture diagram (`docs/architecture.md`)
- [ ] Devpost writeup
- [ ] Dataset documentation (`docs/dataset.md`)
- [ ] Accuracy report (`docs/accuracy-report.md`)
- [ ] Try-it-out instructions (`docs/try-it-out.md`)
- [ ] Agent execution logs (`logs/`)

## License

MIT — see [LICENSE](LICENSE)
