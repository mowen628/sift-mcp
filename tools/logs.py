# tools/logs.py — Docker container log triage via SSH to 10.0.0.3

import os
from pathlib import Path

import paramiko
from dotenv import load_dotenv
from mcp.types import TextContent, Tool

load_dotenv(Path(__file__).parent.parent / ".env")

DOCKER_HOST_IP = os.getenv("DOCKER_HOST_IP", "10.0.0.3")
DOCKER_HOST_USER = os.getenv("DOCKER_HOST_USER", "matt-owen")
DOCKER_HOST_KEY = os.path.expanduser(os.getenv("DOCKER_HOST_KEY", "~/.ssh/id_ed25519"))

# Known containers on the Docker host
KNOWN_CONTAINERS = [
    "homeassistant", "esphome", "homepage", "samba", "mosquitto",
    "influxdb", "grafana", "adguard", "telegraf", "cloudflared",
    "ring-mqtt", "vaultwarden",
]


def tool_definitions() -> list[Tool]:
    return [
        Tool(
            name="logs_container",
            description=(
                "Retrieve recent logs from a Docker container running on the home server (10.0.0.3). "
                "Supports line limit and optional keyword search. "
                f"Known containers: {', '.join(KNOWN_CONTAINERS)}"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "container": {
                        "type": "string",
                        "description": f"Container name. Known: {', '.join(KNOWN_CONTAINERS)}",
                    },
                    "lines": {
                        "type": "integer",
                        "description": "Number of recent log lines to retrieve",
                        "default": 100,
                    },
                    "search": {
                        "type": "string",
                        "description": "Optional keyword to filter log lines (grep)",
                    },
                },
                "required": ["container"],
            },
        ),
        Tool(
            name="logs_list_containers",
            description="List all running Docker containers on the home server with status and uptime.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
    ]


async def dispatch(name: str, arguments: dict):
    if name == "logs_container":
        return await _logs_container(
            arguments["container"],
            arguments.get("lines", 100),
            arguments.get("search", ""),
        )
    elif name == "logs_list_containers":
        return await _list_containers()
    raise ValueError(f"Unknown tool: {name}")


def _ssh_connect() -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        DOCKER_HOST_IP,
        username=DOCKER_HOST_USER,
        key_filename=DOCKER_HOST_KEY,
        timeout=10,
    )
    return client


def _ssh_exec(client: paramiko.SSHClient, cmd: str) -> tuple[str, str]:
    _, stdout, stderr = client.exec_command(cmd)
    return stdout.read().decode(), stderr.read().decode()


async def _list_containers():
    try:
        client = _ssh_connect()
        out, err = _ssh_exec(client, "docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'")
        client.close()
    except Exception as e:
        return [TextContent(type="text", text=f"SSH connection failed: {e}")]

    if err and not out:
        return [TextContent(type="text", text=f"Error listing containers: {err}")]

    return [TextContent(type="text", text=f"Running containers on {DOCKER_HOST_IP}:\n{out}")]


async def _logs_container(container: str, lines: int, search: str):
    # Clamp lines to a safe range
    lines = max(10, min(lines, 1000))

    try:
        client = _ssh_connect()
    except Exception as e:
        return [TextContent(type="text", text=f"SSH connection failed to {DOCKER_HOST_IP}: {e}")]

    try:
        # Check container exists
        out, _ = _ssh_exec(client, f"docker ps -a --filter name=^{container}$ --format '{{{{.Names}}}}'")
        if container not in out:
            client.close()
            known = ", ".join(KNOWN_CONTAINERS)
            return [TextContent(type="text", text=f"Container '{container}' not found.\nKnown containers: {known}")]

        # Fetch logs
        log_cmd = f"docker logs --tail {lines} {container} 2>&1"
        if search:
            log_cmd += f" | grep -i '{search}'"

        out, err = _ssh_exec(client, log_cmd)
        client.close()
    except Exception as e:
        client.close()
        return [TextContent(type="text", text=f"Error fetching logs: {e}")]

    log_output = out or err or "(no output)"
    line_count = log_output.count("\n")

    header = f"Logs: {container} | last {lines} lines"
    if search:
        header += f" | filtered: '{search}'"
    header += f" | {line_count} lines returned"

    return [TextContent(type="text", text=f"{header}\n{'─' * 60}\n{log_output}")]
