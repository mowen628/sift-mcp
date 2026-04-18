# sift-mcp — Claude Code Instructions

## What This Is
An MCP server for autonomous incident response on a SANS SIFT Workstation.
Tools span live network triage and deep forensics. All findings are logged
to a structured audit trail and written to InfluxDB.

## Ground Rules
- All forensic tools are READ-ONLY by default
- Never write to /cases without explicit case_create first
- Never execute arbitrary shell commands — use only registered MCP tools
- Always call case_create before starting an investigation
- Always call case_report when an investigation is complete

## Workflow
1. Start with live triage: network_device_scan → network_dns_query → logs_container
2. Escalate to deep forensics if triage flags anomalies
3. Document every finding with case_add_finding (include severity: low/medium/high/critical)
4. Close with case_report — this writes to InfluxDB and generates the human-readable report

## Tool Locations (SIFT VM)
- Volatility3: Python module in ~/sift-mcp-env
- Plaso: /usr/bin/log2timeline.py
- EZ Tools: /opt/zimmermantools/
- YARA: yara-python module in ~/sift-mcp-env
- Cases: /cases/
- Audit logs: ~/sift-mcp/logs/

## Environment
Activate venv before running server: `source ~/sift-mcp-env/bin/activate`
