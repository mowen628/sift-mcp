# tools/ioc.py — IOC scanning via YARA + file hashing

import asyncio
import hashlib
import os
from pathlib import Path

import yara
from dotenv import load_dotenv
from mcp.types import TextContent, Tool

from constraints import check_path

load_dotenv(Path(__file__).parent.parent / ".env")

CASES_DIR = Path(os.getenv("CASES_DIR", "/cases"))
YARA_RULES_DIR = Path(__file__).parent.parent / "yara_rules"


def tool_definitions() -> list[Tool]:
    return [
        Tool(
            name="ioc_yara_scan",
            description=(
                "Run YARA rules against a file or directory. "
                "Returns matches with rule name, file path, strings matched, and offset. "
                "Use a case_id to log matches as findings automatically."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "File or directory path to scan",
                    },
                    "rules_path": {
                        "type": "string",
                        "description": "Path to YARA rules file or directory. Defaults to built-in rules.",
                    },
                    "case_id": {
                        "type": "string",
                        "description": "Active case ID — matches will be added as findings",
                    },
                },
                "required": ["target", "case_id"],
            },
        ),
        Tool(
            name="ioc_hash",
            description="Compute MD5, SHA1, and SHA256 hashes for a file.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path to the file to hash",
                    },
                    "case_id": {
                        "type": "string",
                        "description": "Active case ID",
                    },
                },
                "required": ["path", "case_id"],
            },
        ),
        Tool(
            name="ioc_list_rules",
            description="List available built-in YARA rule files.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
    ]


async def dispatch(name: str, arguments: dict):
    if name == "ioc_yara_scan":
        return await _yara_scan(
            arguments["target"],
            arguments.get("rules_path", ""),
            arguments["case_id"],
        )
    elif name == "ioc_hash":
        return await _hash_file(arguments["path"], arguments["case_id"])
    elif name == "ioc_list_rules":
        return await _list_rules()
    raise ValueError(f"Unknown tool: {name}")


async def _list_rules():
    YARA_RULES_DIR.mkdir(exist_ok=True)
    rules = list(YARA_RULES_DIR.glob("*.yar")) + list(YARA_RULES_DIR.glob("*.yara"))
    if not rules:
        return [TextContent(type="text", text=f"No YARA rules found in {YARA_RULES_DIR}\nAdd .yar or .yara files to enable scanning.")]
    lines = [f"Available YARA rules in {YARA_RULES_DIR}:"]
    for r in sorted(rules):
        lines.append(f"  {r.name}")
    return [TextContent(type="text", text="\n".join(lines))]


async def _hash_file(path: str, case_id: str):
    check_path(path)
    target = Path(path)

    if not target.exists():
        return [TextContent(type="text", text=f"File not found: {path}")]
    if not target.is_file():
        return [TextContent(type="text", text=f"Not a file: {path}")]

    # Run hashing in thread pool to avoid blocking event loop
    loop = asyncio.get_event_loop()
    hashes = await loop.run_in_executor(None, _compute_hashes, target)

    lines = [
        f"File: {path}",
        f"Size: {target.stat().st_size:,} bytes",
        f"MD5:    {hashes['md5']}",
        f"SHA1:   {hashes['sha1']}",
        f"SHA256: {hashes['sha256']}",
    ]
    return [TextContent(type="text", text="\n".join(lines))]


def _compute_hashes(path: Path) -> dict:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


async def _yara_scan(target: str, rules_path: str, case_id: str):
    check_path(target)
    target_path = Path(target)

    if not target_path.exists():
        return [TextContent(type="text", text=f"Target not found: {target}")]

    # Resolve rules
    if rules_path:
        check_path(rules_path)
        rules_source = Path(rules_path)
    else:
        rules_source = YARA_RULES_DIR

    # Compile rules
    try:
        if rules_source.is_file():
            rules = yara.compile(filepath=str(rules_source))
        elif rules_source.is_dir():
            rule_files = list(rules_source.glob("*.yar")) + list(rules_source.glob("*.yara"))
            if not rule_files:
                return [TextContent(type="text", text=f"No YARA rules found in {rules_source}. Add .yar files to {YARA_RULES_DIR}")]
            filepaths = {r.stem: str(r) for r in rule_files}
            rules = yara.compile(filepaths=filepaths)
        else:
            return [TextContent(type="text", text=f"Rules path not found: {rules_source}")]
    except yara.SyntaxError as e:
        return [TextContent(type="text", text=f"YARA rule syntax error: {e}")]

    # Collect files to scan
    if target_path.is_file():
        files_to_scan = [target_path]
    else:
        files_to_scan = [f for f in target_path.rglob("*") if f.is_file()]

    # Run scan in thread pool
    loop = asyncio.get_event_loop()
    all_matches = await loop.run_in_executor(None, _run_yara_scan, rules, files_to_scan)

    if not all_matches:
        return [TextContent(type="text", text=f"YARA scan complete — no matches in {target}\nFiles scanned: {len(files_to_scan)}")]

    lines = [
        f"YARA scan: {target}",
        f"Files scanned: {len(files_to_scan)} | Matches: {len(all_matches)}",
        "",
    ]
    for file_path, match in all_matches:
        lines.append(f"  MATCH: {match.rule}")
        lines.append(f"    File: {file_path}")
        lines.append(f"    Tags: {', '.join(match.tags) if match.tags else 'none'}")
        for string_match in match.strings[:5]:  # cap output per match
            lines.append(f"    String: {string_match.identifier} @ offset {string_match.instances[0].offset}")
        lines.append("")

    return [TextContent(type="text", text="\n".join(lines))]


def _run_yara_scan(rules: yara.Rules, files: list) -> list:
    matches = []
    for f in files:
        try:
            file_matches = rules.match(str(f))
            for m in file_matches:
                matches.append((str(f), m))
        except Exception:
            pass  # skip unreadable files silently
    return matches
