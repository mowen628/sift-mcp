# tools/timeline.py — timeline generation via Plaso (log2timeline) + psort

import asyncio
import os
from pathlib import Path

from dotenv import load_dotenv
from mcp.types import TextContent, Tool

from constraints import check_path, require_case

load_dotenv(Path(__file__).parent.parent / ".env")

CASES_DIR = Path(os.getenv("CASES_DIR", "/cases"))
LOG2TIMELINE = os.getenv("LOG2TIMELINE_BIN", "/usr/bin/log2timeline.py")
PSORT = os.getenv("PSORT_BIN", "/usr/bin/psort.py")


def tool_definitions() -> list[Tool]:
    return [
        Tool(
            name="timeline_create",
            description=(
                "Run log2timeline (Plaso) on an artifact to build a forensic timeline. "
                "Accepts a disk image, directory, or single file. "
                "Output is a Plaso storage file (.plaso) saved in the case directory. "
                "Large sources can take many minutes."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "source": {
                        "type": "string",
                        "description": "Absolute path to artifact (disk image, directory, or file)",
                    },
                    "case_id": {"type": "string", "description": "Active case ID"},
                },
                "required": ["source", "case_id"],
            },
        ),
        Tool(
            name="timeline_query",
            description=(
                "Query a Plaso storage file with psort. Filter by date range and/or keyword. "
                "Returns matching events as a sorted CSV snippet. "
                "Run timeline_create first to generate the .plaso file."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "Active case ID"},
                    "filter": {
                        "type": "string",
                        "description": (
                            "Optional psort filter expression, e.g. "
                            "\"date > '2024-01-01' AND date < '2024-01-02'\" "
                            "or a keyword string for grep-style filtering"
                        ),
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max events to return (default 200)",
                    },
                },
                "required": ["case_id"],
            },
        ),
    ]


async def dispatch(name: str, arguments: dict):
    if name == "timeline_create":
        return await _create_timeline(arguments["source"], arguments["case_id"])
    elif name == "timeline_query":
        return await _query_timeline(
            arguments["case_id"],
            arguments.get("filter", ""),
            arguments.get("limit", 200),
        )
    raise ValueError(f"Unknown tool: {name}")


async def _create_timeline(source: str, case_id: str):
    check_path(source)
    require_case(case_id)

    source_path = Path(source)
    if not source_path.exists():
        return [TextContent(type="text", text=f"Source not found: {source}")]

    case_dir = CASES_DIR / case_id
    analysis_dir = case_dir / "analysis"
    analysis_dir.mkdir(exist_ok=True)

    plaso_file = analysis_dir / "timeline.plaso"

    cmd = [
        "sudo", LOG2TIMELINE,
        "--storage-file", str(plaso_file),
        "--status-view", "none",
        str(source_path),
    ]

    stdout, stderr, rc = await _run_cmd(cmd, timeout=3600)  # 1 hour max

    if rc != 0:
        return [TextContent(type="text", text=f"log2timeline failed:\n{stderr[-2000:]}")]

    size = plaso_file.stat().st_size if plaso_file.exists() else 0
    return [TextContent(
        type="text",
        text=(
            f"timeline_create | case: {case_id} | source: {source_path.name}\n"
            f"{'─' * 60}\n"
            f"Plaso storage: {plaso_file}\n"
            f"Size: {size:,} bytes\n"
            f"Run timeline_query to extract events."
        ),
    )]


async def _query_timeline(case_id: str, filter_expr: str, limit: int):
    require_case(case_id)

    plaso_file = CASES_DIR / case_id / "analysis" / "timeline.plaso"
    if not plaso_file.exists():
        return [TextContent(
            type="text",
            text=f"No timeline found for case {case_id}. Run timeline_create first.",
        )]

    out_file = CASES_DIR / case_id / "analysis" / "timeline.csv"

    cmd = [PSORT, "-o", "dynamic", str(plaso_file), "-w", str(out_file)]
    if filter_expr and not _looks_like_keyword(filter_expr):
        cmd += [filter_expr]

    stdout, stderr, rc = await _run_cmd(cmd, timeout=600)

    if rc != 0:
        return [TextContent(type="text", text=f"psort failed:\n{stderr[-2000:]}")]

    if not out_file.exists():
        return [TextContent(type="text", text="psort produced no output.")]

    # Read CSV, apply keyword filter if needed, return up to limit lines
    lines = out_file.read_text(errors="replace").splitlines()
    if filter_expr and _looks_like_keyword(filter_expr):
        kw = filter_expr.lower()
        header = lines[:1]
        lines = header + [l for l in lines[1:] if kw in l.lower()]

    total = len(lines) - 1  # exclude header
    truncated = ""
    if len(lines) > limit + 1:
        truncated = f"\n... ({total - limit} events truncated — full output at {out_file})"
        lines = lines[:limit + 1]

    return [TextContent(
        type="text",
        text=(
            f"timeline_query | case: {case_id} | filter: {filter_expr or 'none'} | {total} events\n"
            f"{'─' * 60}\n"
            + "\n".join(lines)
            + truncated
        ),
    )]


def _looks_like_keyword(expr: str) -> bool:
    """Distinguish a psort filter expression from a plain keyword search."""
    return not any(op in expr for op in ["AND", "OR", "date", ">", "<", "="])


async def _run_cmd(cmd: list, timeout: int = 600) -> tuple[str, str, int]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        return stdout_bytes.decode(), stderr_bytes.decode(), proc.returncode
    except asyncio.TimeoutError:
        return "", f"Command timed out after {timeout}s", 1
    except FileNotFoundError as e:
        return "", f"Binary not found: {e} — check LOG2TIMELINE_BIN / PSORT_BIN in .env", 1
