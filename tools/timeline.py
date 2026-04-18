# tools/timeline.py — timeline generation via Plaso (log2timeline)
# TODO: implement

from mcp.types import Tool


def tool_definitions() -> list[Tool]:
    return [
        Tool(
            name="timeline_create",
            description="Run log2timeline (Plaso) on an artifact to generate a timeline. Output stored in the case directory.",
            inputSchema={
                "type": "object",
                "properties": {
                    "source": {"type": "string", "description": "Path to artifact (disk image, directory, or file)"},
                    "case_id": {"type": "string", "description": "Active case ID"},
                },
                "required": ["source", "case_id"],
            },
        ),
    ]


async def dispatch(name: str, arguments: dict):
    raise NotImplementedError(f"{name} not yet implemented")
