# tools/logs.py — Docker container log triage via SSH to 10.0.0.3
# TODO: implement

from mcp.types import Tool


def tool_definitions() -> list[Tool]:
    return [
        Tool(
            name="logs_container",
            description="Retrieve recent logs from a Docker container running on the home server (10.0.0.3). Supports keyword search and line limit.",
            inputSchema={
                "type": "object",
                "properties": {
                    "container": {"type": "string", "description": "Container name (e.g. homeassistant, adguard, mosquitto)"},
                    "lines": {"type": "integer", "description": "Number of recent lines to retrieve", "default": 100},
                    "search": {"type": "string", "description": "Optional keyword to grep for"},
                },
                "required": ["container"],
            },
        ),
    ]


async def dispatch(name: str, arguments: dict):
    raise NotImplementedError(f"{name} not yet implemented")
