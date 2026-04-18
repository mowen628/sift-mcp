# tools/memory.py — memory forensics via Volatility3
# TODO: implement

from mcp.types import Tool


def tool_definitions() -> list[Tool]:
    return [
        Tool(
            name="memory_pslist",
            description="List running processes from a memory dump using Volatility3 windows.pslist or linux.pslist.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image": {"type": "string", "description": "Path to memory image file"},
                    "case_id": {"type": "string", "description": "Active case ID"},
                },
                "required": ["image", "case_id"],
            },
        ),
        Tool(
            name="memory_netscan",
            description="List network connections and sockets from a memory dump using Volatility3 netscan.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image": {"type": "string", "description": "Path to memory image file"},
                    "case_id": {"type": "string", "description": "Active case ID"},
                },
                "required": ["image", "case_id"],
            },
        ),
        Tool(
            name="memory_malfind",
            description="Identify potentially injected code regions in a memory dump using Volatility3 malfind.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image": {"type": "string", "description": "Path to memory image file"},
                    "case_id": {"type": "string", "description": "Active case ID"},
                },
                "required": ["image", "case_id"],
            },
        ),
    ]


async def dispatch(name: str, arguments: dict):
    raise NotImplementedError(f"{name} not yet implemented")
