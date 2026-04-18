# tools/network.py — live network triage via AdGuard Home API + nmap
# TODO: implement

from mcp.types import Tool


def tool_definitions() -> list[Tool]:
    return [
        Tool(
            name="network_dns_query",
            description="Query AdGuard Home DNS logs for a hostname or IP address. Returns recent queries, response codes, and client IPs.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Hostname or IP to search for"},
                    "limit": {"type": "integer", "description": "Max results to return", "default": 50},
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="network_device_scan",
            description="Run an nmap ping sweep of the LAN subnet and return all discovered devices with IP, MAC, and hostname. Flags devices not in the known inventory.",
            inputSchema={
                "type": "object",
                "properties": {
                    "subnet": {"type": "string", "description": "CIDR subnet to scan", "default": "10.0.0.0/24"},
                },
            },
        ),
    ]


async def dispatch(name: str, arguments: dict):
    raise NotImplementedError(f"{name} not yet implemented")
