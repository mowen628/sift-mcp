# tools/ioc.py — IOC scanning via YARA + hashing
# TODO: implement

from mcp.types import Tool


def tool_definitions() -> list[Tool]:
    return [
        Tool(
            name="ioc_yara_scan",
            description="Run YARA rules against a file or directory. Returns matches with rule name, file path, and offset.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "File or directory path to scan"},
                    "rules": {"type": "string", "description": "Path to YARA rules file or directory"},
                    "case_id": {"type": "string", "description": "Active case ID"},
                },
                "required": ["target", "rules", "case_id"],
            },
        ),
        Tool(
            name="ioc_hash",
            description="Compute MD5, SHA1, and SHA256 hashes for a file.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path to hash"},
                    "case_id": {"type": "string", "description": "Active case ID"},
                },
                "required": ["path", "case_id"],
            },
        ),
    ]


async def dispatch(name: str, arguments: dict):
    raise NotImplementedError(f"{name} not yet implemented")
