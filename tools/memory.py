# tools/memory.py — memory forensics via Volatility3

import asyncio
import os
from pathlib import Path

from dotenv import load_dotenv
from mcp.types import TextContent, Tool

from constraints import check_path, require_case

load_dotenv(Path(__file__).parent.parent / ".env")

CASES_DIR = Path(os.getenv("CASES_DIR", "/cases"))


def tool_definitions() -> list[Tool]:
    return [
        Tool(
            name="memory_pslist",
            description=(
                "List running processes from a memory image using Volatility3. "
                "Supports Windows (windows.pslist) and Linux (linux.pslist) images. "
                "Auto-detects OS."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "image": {"type": "string", "description": "Absolute path to memory image file"},
                    "case_id": {"type": "string", "description": "Active case ID"},
                    "pid": {"type": "integer", "description": "Optional: filter to a specific PID"},
                },
                "required": ["image", "case_id"],
            },
        ),
        Tool(
            name="memory_netscan",
            description=(
                "List network connections and open sockets from a memory image using Volatility3 netscan. "
                "Windows images only."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "image": {"type": "string", "description": "Absolute path to memory image file"},
                    "case_id": {"type": "string", "description": "Active case ID"},
                },
                "required": ["image", "case_id"],
            },
        ),
        Tool(
            name="memory_malfind",
            description=(
                "Identify memory regions with suspicious characteristics — executable, not backed by a file, "
                "or with MZ/PE headers. Uses Volatility3 malfind. Windows images only."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "image": {"type": "string", "description": "Absolute path to memory image file"},
                    "case_id": {"type": "string", "description": "Active case ID"},
                },
                "required": ["image", "case_id"],
            },
        ),
        Tool(
            name="memory_cmdline",
            description="Show command-line arguments for all processes from a memory image. Windows images only.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image": {"type": "string", "description": "Absolute path to memory image file"},
                    "case_id": {"type": "string", "description": "Active case ID"},
                    "pid": {"type": "integer", "description": "Optional: filter to a specific PID"},
                },
                "required": ["image", "case_id"],
            },
        ),
        Tool(
            name="memory_dlllist",
            description="List loaded DLLs for processes from a memory image. Windows images only.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image": {"type": "string", "description": "Absolute path to memory image file"},
                    "case_id": {"type": "string", "description": "Active case ID"},
                    "pid": {"type": "integer", "description": "Filter to a specific PID (recommended — output is large)"},
                },
                "required": ["image", "case_id", "pid"],
            },
        ),
    ]


async def dispatch(name: str, arguments: dict):
    image = arguments["image"]
    case_id = arguments["case_id"]
    pid = arguments.get("pid")

    check_path(image)
    require_case(case_id)

    if name == "memory_pslist":
        return await _run_vol3(image, case_id, "pslist", pid=pid)
    elif name == "memory_netscan":
        return await _run_vol3(image, case_id, "netscan")
    elif name == "memory_malfind":
        return await _run_vol3(image, case_id, "malfind")
    elif name == "memory_cmdline":
        return await _run_vol3(image, case_id, "cmdline", pid=pid)
    elif name == "memory_dlllist":
        return await _run_vol3(image, case_id, "dlllist", pid=pid)

    raise ValueError(f"Unknown tool: {name}")


async def _run_vol3(image: str, case_id: str, plugin: str, pid: int = None):
    image_path = Path(image)
    if not image_path.exists():
        return [TextContent(type="text", text=f"Image not found: {image}")]

    # Map short plugin name to Volatility3 fully-qualified plugin name
    # Try Windows first; fall back to Linux if Windows fails
    plugin_map = {
        "pslist":   ("windows.pslist.PsList",   "linux.pslist.PsList"),
        "netscan":  ("windows.netscan.NetScan",  None),
        "malfind":  ("windows.malfind.Malfind",  None),
        "cmdline":  ("windows.cmdline.CmdLine",  None),
        "dlllist":  ("windows.dlllist.DllList",  None),
    }

    if plugin not in plugin_map:
        return [TextContent(type="text", text=f"Unknown plugin: {plugin}")]

    win_plugin, linux_plugin = plugin_map[plugin]

    # Build vol3 command
    cmd = _build_cmd(image, win_plugin, pid)
    stdout, stderr, rc = await _run_cmd(cmd)

    # If Windows plugin failed, try Linux fallback
    if rc != 0 and linux_plugin:
        cmd = _build_cmd(image, linux_plugin, pid)
        stdout, stderr, rc = await _run_cmd(cmd)
        if rc != 0:
            return [TextContent(type="text", text=f"Volatility3 failed:\n{stderr[-2000:]}")]
    elif rc != 0:
        return [TextContent(type="text", text=f"Volatility3 failed (Windows-only plugin):\n{stderr[-2000:]}")]

    # Save output to case directory
    out_file = CASES_DIR / case_id / "analysis" / f"{plugin}.txt"
    out_file.write_text(stdout)

    # Format output
    lines = stdout.strip().split("\n")
    truncated = ""
    if len(lines) > 100:
        truncated = f"\n... ({len(lines) - 100} lines truncated — full output at {out_file})"
        lines = lines[:100]

    header = f"memory_{plugin} | image: {image_path.name} | case: {case_id} | {len(stdout.splitlines())} lines"
    return [TextContent(type="text", text=f"{header}\n{'─' * 60}\n" + "\n".join(lines) + truncated)]


VOL3_BIN = os.getenv("VOL3_BIN", "/home/sansforensics/sift-mcp-env/bin/vol")


def _build_cmd(image: str, plugin: str, pid: int = None) -> list:
    cmd = ["sudo", VOL3_BIN, "-f", image, plugin]
    if pid:
        cmd += ["--pid", str(pid)]
    return cmd


async def _run_cmd(cmd: list) -> tuple[str, str, int]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        # Memory analysis can be slow — allow 10 minutes
        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=600)
        return stdout_bytes.decode(), stderr_bytes.decode(), proc.returncode
    except asyncio.TimeoutError:
        return "", "Volatility3 timed out after 10 minutes", 1
    except FileNotFoundError:
        return "", f"volatility3 not found at {VOL3_BIN} — check VOL3_BIN in .env", 1
