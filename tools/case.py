# tools/case.py — case management, findings, and InfluxDB reporting

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
from mcp.types import TextContent, Tool

from constraints import check_path, require_case

load_dotenv(Path(__file__).parent.parent / ".env")

CASES_DIR = Path(os.getenv("CASES_DIR", "/cases"))
INFLUXDB_URL = os.getenv("INFLUXDB_URL")
INFLUXDB_TOKEN = os.getenv("INFLUXDB_TOKEN")
INFLUXDB_ORG = os.getenv("INFLUXDB_ORG")
INFLUXDB_BUCKET = os.getenv("INFLUXDB_BUCKET", "sift-ir")
HA_WEBHOOK_URL = os.getenv("HA_WEBHOOK_URL", "")

SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def tool_definitions() -> list[Tool]:
    return [
        Tool(
            name="case_create",
            description="Initialize a new IR case. Creates case directory structure and registers the case in the audit log.",
            inputSchema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "Unique case identifier (e.g. IR-2026-001)"},
                    "description": {"type": "string", "description": "Brief description of the incident or investigation"},
                },
                "required": ["case_id", "description"],
            },
        ),
        Tool(
            name="case_add_finding",
            description="Record a finding within an active case. Severity must be one of: low, medium, high, critical.",
            inputSchema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "Active case ID"},
                    "title": {"type": "string", "description": "Short finding title"},
                    "description": {"type": "string", "description": "Detailed finding description"},
                    "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                    "evidence": {"type": "string", "description": "Supporting evidence or artifact reference"},
                },
                "required": ["case_id", "title", "description", "severity"],
            },
        ),
        Tool(
            name="case_report",
            description="Generate a case report, write findings to InfluxDB (sift-ir bucket), and trigger a Home Assistant alert for high/critical findings.",
            inputSchema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "Case ID to report on"},
                },
                "required": ["case_id"],
            },
        ),
    ]


async def dispatch(name: str, arguments: dict):
    if name == "case_create":
        return await _case_create(arguments["case_id"], arguments["description"])
    elif name == "case_add_finding":
        return await _case_add_finding(
            arguments["case_id"],
            arguments["title"],
            arguments["description"],
            arguments["severity"],
            arguments.get("evidence", ""),
        )
    elif name == "case_report":
        return await _case_report(arguments["case_id"])
    raise ValueError(f"Unknown tool: {name}")


async def _case_create(case_id: str, description: str):
    case_dir = CASES_DIR / case_id
    check_path(str(case_dir), write=True)

    if case_dir.exists():
        return [TextContent(type="text", text=f"Case {case_id} already exists at {case_dir}")]

    for subdir in ["analysis", "exports", "reports"]:
        (case_dir / subdir).mkdir(parents=True, exist_ok=True)

    metadata = {
        "case_id": case_id,
        "description": description,
        "created": datetime.now(timezone.utc).isoformat(),
        "status": "open",
    }
    (case_dir / "case.json").write_text(json.dumps(metadata, indent=2))
    (case_dir / "findings.json").write_text(json.dumps([], indent=2))

    return [TextContent(type="text", text=f"Case {case_id} created at {case_dir}\n{json.dumps(metadata, indent=2)}")]


async def _case_add_finding(case_id: str, title: str, description: str, severity: str, evidence: str):
    require_case(case_id)
    case_dir = CASES_DIR / case_id
    findings_file = case_dir / "findings.json"
    check_path(str(findings_file), write=True)

    findings = json.loads(findings_file.read_text())
    finding = {
        "id": len(findings) + 1,
        "title": title,
        "description": description,
        "severity": severity,
        "evidence": evidence,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    findings.append(finding)
    findings_file.write_text(json.dumps(findings, indent=2))

    return [TextContent(
        type="text",
        text=f"Finding #{finding['id']} added to {case_id}\nSeverity: {severity.upper()}\n{title}"
    )]


async def _case_report(case_id: str):
    require_case(case_id)
    case_dir = CASES_DIR / case_id
    check_path(str(case_dir))

    metadata = json.loads((case_dir / "case.json").read_text())
    findings = json.loads((case_dir / "findings.json").read_text())

    # Sort findings by severity descending
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]), reverse=True)

    # Build report
    now = datetime.now(timezone.utc).isoformat()
    lines = [
        f"# IR Case Report: {case_id}",
        f"Generated: {now}",
        f"Description: {metadata['description']}",
        f"Status: {metadata['status']}",
        f"Total findings: {len(findings)}",
        "",
    ]
    for severity in reversed(SEVERITY_ORDER):
        group = [f for f in findings if f["severity"] == severity]
        if group:
            lines.append(f"## {severity.upper()} ({len(group)})")
            for f in group:
                lines.append(f"  [{f['id']}] {f['title']}")
                lines.append(f"      {f['description']}")
                if f.get("evidence"):
                    lines.append(f"      Evidence: {f['evidence']}")
            lines.append("")

    report_text = "\n".join(lines)
    report_path = case_dir / "reports" / f"report-{now[:10]}.md"
    check_path(str(report_path), write=True)
    report_path.write_text(report_text)

    # Write findings to InfluxDB
    influx_status = "skipped (no token)"
    if INFLUXDB_TOKEN:
        try:
            client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
            write_api = client.write_api(write_options=SYNCHRONOUS)
            for f in findings:
                point = (
                    Point("ir_finding")
                    .tag("case_id", case_id)
                    .tag("severity", f["severity"])
                    .field("title", f["title"])
                    .field("description", f["description"])
                    .field("evidence", f.get("evidence", ""))
                    .time(f["timestamp"])
                )
                write_api.write(bucket=INFLUXDB_BUCKET, record=point)
            client.close()
            influx_status = f"{len(findings)} findings written to InfluxDB ({INFLUXDB_BUCKET})"
        except Exception as e:
            influx_status = f"InfluxDB write failed: {e}"

    # HA webhook for high/critical findings
    ha_status = "skipped"
    high_count = sum(1 for f in findings if f["severity"] in ("high", "critical"))
    if HA_WEBHOOK_URL and high_count:
        try:
            import requests
            requests.post(HA_WEBHOOK_URL, json={
                "case_id": case_id,
                "high_critical_findings": high_count,
                "report": report_path.name,
            }, timeout=5)
            ha_status = f"HA alert sent ({high_count} high/critical findings)"
        except Exception as e:
            ha_status = f"HA webhook failed: {e}"

    return [TextContent(
        type="text",
        text=f"{report_text}\n---\nReport saved: {report_path}\nInfluxDB: {influx_status}\nHA: {ha_status}"
    )]
