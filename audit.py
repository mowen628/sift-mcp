# audit.py — structured JSON audit trail for every MCP tool call

import json
import os
from datetime import datetime, timezone
from pathlib import Path


LOGS_DIR = Path(os.getenv("LOGS_DIR", "/home/sansforensics/sift-mcp/logs"))


class AuditLogger:
    def __init__(self):
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        self._session_file = LOGS_DIR / f"session-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.jsonl"

    def _write(self, record: dict) -> None:
        record["timestamp"] = datetime.now(timezone.utc).isoformat()
        with open(self._session_file, "a") as f:
            f.write(json.dumps(record) + "\n")

    def log_call(self, tool: str, arguments: dict) -> None:
        self._write({"event": "tool_call", "tool": tool, "arguments": arguments})

    def log_result(self, tool: str, result) -> None:
        # Summarize result — avoid logging large binary blobs
        summary = str(result)[:500] if result else None
        self._write({"event": "tool_result", "tool": tool, "result_summary": summary})

    def log_error(self, tool: str, error: str) -> None:
        self._write({"event": "tool_error", "tool": tool, "error": error})

    def log_finding(self, case_id: str, severity: str, description: str) -> None:
        self._write({
            "event": "finding",
            "case_id": case_id,
            "severity": severity,
            "description": description,
        })
