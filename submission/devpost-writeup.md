# Devpost Submission — sift-mcp

Drop the project story directly into Devpost's markdown editor. The fields underneath it match Devpost's standard hackathon form.

---

## Project Name
**sift-mcp** — Autonomous IR for the SANS SIFT Workstation

## Elevator Pitch (≤200 chars)
A custom MCP server that turns Claude Code into an IR analyst on the SANS SIFT VM — live triage, memory forensics, Plaso timelines, and an audit-trailed case file, all chained autonomously.

---

## Project Story

### Inspiration
The Find Evil hackathon prompt — "what if a Claude agent could actually do IR on a real network?" — landed at the same time I was rebuilding my homelab. I run a real, slightly noisy `10.0.0.0/24`: pfSense gateway, AdGuard DNS, a dozen ESPs, ~50 devices total. There's *plenty* of evil to look for in real DNS logs and container logs. I wanted an agent that doesn't just answer questions about IR — it actually performs the investigation.

### What It Does
`sift-mcp` is a custom MCP server wrapping the SIFT toolchain. From a single Claude Code session you can:

- Pull live DNS queries from AdGuard, filter for anomalies
- Discover unknown devices on the LAN via nmap + the pfSense static-map table
- Triage container logs over SSH against the Docker host
- Capture and analyze memory with Volatility 3
- Hash files, YARA-scan directories
- Build and query Plaso timelines
- Open a case, attach findings with severity, ship them to InfluxDB + Grafana, optionally page Home Assistant on high/critical

All chained autonomously — Claude orchestrates the pipeline, the MCP server runs the tools, every call is audit-logged.

### How I Built It
- **Language/runtime**: Python 3.12 on the SANS SIFT Workstation (Ubuntu 24.04)
- **Transport**: stdio MCP — launched per Claude session, no persistent daemon, no exposed surface
- **Forensics**: Volatility 3 + dwarf2json-generated ISFs, Plaso (`log2timeline.py`/`psort.py`), `avml` for live memory capture, YARA for IOCs
- **Live telemetry**: AdGuard Home REST API, paramiko SSH to the Docker host, nmap
- **Case + reporting**: filesystem JSON + Markdown reports + `influxdb-client` writes into a bucket-scoped `sift-ir` token; Grafana dashboard with 5 panels
- **Guardrails**: a `constraints.py` layer running *in Python*, not in prompts — path allowlist, write restricted to `/cases` + tool log dir, every finding-producing tool refuses to run without a case context
- **Audit trail**: JSONL per session, flushed on every call

### Judging Criteria Alignment

| Criterion | Implementation |
|---|---|
| **Autonomous Execution Quality** | Single Claude session chains `case_create` → triage tools → forensics → `case_report` without human steps |
| **IR Accuracy** | Live data, not mocks — real AdGuard logs, real device inventory, real 4 GB memory capture (226 procs recovered), real Plaso run (4,361 events) |
| **Breadth & Depth** | 6 tool modules: network, logs, memory, ioc, timeline, case — covers triage through deep forensics |
| **Constraint Implementation** | Enforced at the MCP layer in `constraints.py` — read allowlist, narrow write paths, mandatory case context. Can't be talked around by a confused agent. |
| **Audit Trail Quality** | `audit.py` writes JSONL per call: timestamp, tool, args, result summary. Survives `kill -9`. |
| **Usability / Documentation** | `README.md`, `docs/architecture.md`, `docs/try-it-out.md`, `docs/dataset.md`, `docs/accuracy-report.md` — including honest known issues |

### Challenges I Ran Into
- **A homelab cutover mid-hackathon.** Three weeks before the deadline I migrated my server stack from a Lenovo box at `10.0.0.3` to a new Proxmox host on a Lenovo M920q at `10.0.0.11`. Everything `sift-mcp` talked to (InfluxDB, AdGuard, Docker host SSH) moved IP. Recovery required repointing `.env`, regranting SSH key trust, and dealing with stale NM DNS configs.
- **Kernel/ISF pinning.** The VM auto-upgraded to a newer kernel I didn't have symbols for. Solution: `grub-reboot` into the kernel matching my existing ISF rather than rebuilding the symbol file.
- **VirtualBox bridged NIC under sustained Plaso load.** The bridge would drop the DHCP lease mid-run. Mitigated by bounding timeline source size — a great forcing function for sane defaults.
- **Schema-vs-dispatch validation gap.** My case tool declared a `severity` enum but didn't enforce it at dispatch — an `info` value got through and crashed `case_report` later when it tried to sort. Honest bug documented in `accuracy-report.md`; fix is trivial.

### Accomplishments I'm Proud Of
- Architectural guardrails in code, not prompts — the agent can't pick its way around them
- Bucket-scoped Influx token so a SIFT compromise doesn't take down the homelab
- Honest accuracy reporting — including the bugs I found, not just the things that worked
- End-to-end verified pipeline: tool call → finding → InfluxDB → Grafana dashboard panel

### What I Learned
- Real-network data is *messy* in productive ways. You discover edge cases you never would in a lab.
- MCP stdio transport is the right call for analyst tools — no daemon surface, lifetime tied to the analyst's session.
- ISF management is the single largest operational cost of running Volatility — worth scripting if this grew further.

### What's Next
- Build out the unverified surface in `accuracy-report.md`: `memory_malfind/netscan/cmdline/dlllist`, `network_device_scan` against the live LAN, `ioc_yara_scan` against a real sample
- Enforce schema enums at dispatch, not just declare them
- Detect partial `.plaso` files and recover automatically
- Surface SSH failures as errors instead of `[OK]` with an error body

---

## Built With
`python` · `mcp` · `claude-code` · `volatility3` · `plaso` · `yara` · `avml` · `paramiko` · `influxdb` · `grafana` · `adguard-home` · `pfsense` · `proxmox` · `home-assistant` · `sans-sift`

## Try It Out
- **Repo**: https://github.com/mowen628/sift-mcp
- **Docs**: [docs/architecture.md](https://github.com/mowen628/sift-mcp/blob/main/docs/architecture.md) · [docs/try-it-out.md](https://github.com/mowen628/sift-mcp/blob/main/docs/try-it-out.md) · [docs/dataset.md](https://github.com/mowen628/sift-mcp/blob/main/docs/dataset.md) · [docs/accuracy-report.md](https://github.com/mowen628/sift-mcp/blob/main/docs/accuracy-report.md)
- **License**: MIT

---

# Asset checklist (capture before submitting)

| Asset | Where to grab | Why it matters |
|---|---|---|
| **Screenshot: SIFT-IR Findings Grafana dashboard** | http://10.0.0.11:3030/d/adc8967/sift-ir-findings — set time range to "Last 1h" so the smoke-test finding is visible | Visual proof the pipeline lands in observability |
| **Screenshot: a generated case report** | `cat /cases/smoke-test-20260614b/reports/report-2026-06-14.md` on the VM, or render with a Markdown viewer | Shows the audit-trail output shape |
| **Screenshot: audit JSONL** | `tail ~/sift-mcp/logs/session-*.jsonl` on the VM — pick 5–10 lines | Demonstrates the structured trail per tool call |
| **Screenshot: Claude Code session driving the tools** | Open a Claude session on the VM, run the demo prompt in `docs/try-it-out.md` §6, screenshot the tool-call sequence | Shows the *autonomous* part visually |
| **Demo video (≤5 min)** | Loom or QuickTime — narrate the same demo prompt | Devpost gives bonus visibility to entries with a video |
| **Memory pslist sample** | `head -50 /cases/smoke-test-20260614b/analysis/pslist.txt` if you want a forensic-output screenshot | Optional, but it's a credible deep-forensics artifact |

## Devpost form quick-fill

- **Project name**: sift-mcp
- **Tagline**: same as the elevator pitch above
- **Description**: paste the Project Story section
- **Built With tags**: paste the Built With list
- **Try It Out link**: https://github.com/mowen628/sift-mcp
- **Repo link**: https://github.com/mowen628/sift-mcp
- **Video**: (record demo, paste link)
- **Image gallery**: upload the screenshots above; thumbnail = the Grafana dashboard
