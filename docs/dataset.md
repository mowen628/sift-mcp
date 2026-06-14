# Dataset

`sift-mcp` runs against a real home network, not synthetic data. This document inventories what the demo investigates.

## Environment

| Component | Details |
|---|---|
| LAN | `10.0.0.0/24`, gateway `pfSense CE 2.7.2` on `10.0.0.1` |
| WAN | AT&T residential, IP Passthrough enabled → public IP terminates on pfSense |
| Hosts | ~50 devices: 3 workstations, 6 ESPs, 3 Pis, 2 cams, smart home, family phones |
| Docker host | LXC at `10.0.0.11` running Home Assistant, AdGuard, InfluxDB, Grafana, Mosquitto, Vaultwarden, Cloudflared, Frigate, Homepage |
| Analysis box | SANS SIFT VM (bridged to LAN), running this MCP server |

## Live Data Sources

### AdGuard Home DNS log
`network_dns_query` hits `/control/querylog` on AdGuard at `10.0.0.11:3080`. Real lookups from real clients — phones, smart bulbs, ESPs, ALL the LAN traffic.

Example finding shape (live, not mocked):
```
2026-06-14 23:05:48 | 10.0.0.179 → android.clients.google.com [A]
  → android.l.google.com., 173.194.45.100, 192.178.218.139, ...
```

### Docker container logs
`logs_container` SSHes to the Docker host and runs `docker logs --tail=N <name> [| grep <kw>]`. Known containers in the demo install: `homeassistant`, `esphome`, `homepage`, `samba`, `mosquitto`, `influxdb`, `grafana`, `adguard`, `telegraf`, `cloudflared`, `ring-mqtt`, `vaultwarden`.

### nmap sweeps
`network_device_scan` runs `nmap -sn <subnet>` and matches MACs against the pfSense static-mapping table to flag unknown devices.

## Forensic Artifacts

### Memory image
- `sift-vm-20260614.mem` — 4.0 GB, captured live with `avml` from the SIFT analysis VM itself (`uname -r = 6.8.0-106-generic`)
- ISF: `linux-6.8.0-106.json` (generated via `dwarf2json` from the matching `dbgsym` package)
- 226 processes recovered by `memory_pslist` end-to-end through the MCP tool

### Plaso timeline
- Source: `/var/log/dpkg.log.1` (apt history) — 4,355 raw log lines
- `timeline.plaso` storage: 2.1 MB SQLite, 4,361 parsed events
- Demonstrates the full `timeline_create` → `timeline_query` chain with a bounded source

### YARA rules
- `yara_rules/network_iocs.yar` — network-related IOCs
- `yara_rules/suspicious_scripts.yar` — shell-script red flags
- Both auto-discovered by `ioc_list_rules`; `ioc_yara_scan` accepts a path and recurses

## Findings Store

- `/cases/<case_id>/case.json` — case metadata
- `/cases/<case_id>/findings.json` — append-only finding list
- `/cases/<case_id>/reports/report-<date>.md` — generated narrative
- InfluxDB `sift-ir` bucket — measurement `ir_finding`, tagged by `case_id`/`severity`, one record per finding written on `case_report`
- Grafana dashboard `SIFT-IR Findings` (UID `adc8967`) — Active Cases, Findings by Severity, Findings Over Time, Total Findings, Findings table

## Reproducibility

The dataset above isn't shipped as a static dump — it's live and changes with the network. To reproduce against your own LAN, follow `try-it-out.md` and point `.env` at your equivalents. The tool *behavior* is reproducible; the *findings* are environmental.
