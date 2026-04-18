# tools/case.py — case management, findings, and InfluxDB reporting
# TODO: implement

from mcp.types import Tool


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
            description="Generate a case report, write findings to InfluxDB (sift-ir bucket), and optionally trigger a Home Assistant alert for high/critical findings.",
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
    raise NotImplementedError(f"{name} not yet implemented")
