# tools/network.py — live network triage via AdGuard Home API + nmap

import os
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv
from mcp.types import TextContent, Tool

from constraints import ConstraintError

load_dotenv(Path(__file__).parent.parent / ".env")

ADGUARD_URL = os.getenv("ADGUARD_URL", "http://10.0.0.3:3080")
ADGUARD_USER = os.getenv("ADGUARD_USER")
ADGUARD_PASS = os.getenv("ADGUARD_PASS")

# Known device inventory — flag anything not in this list as unknown
KNOWN_DEVICES = {
    "10.0.0.1": "gateway (R7000P)",
    "10.0.0.2": "tp-link-switch",
    "10.0.0.3": "homeserver",
    "10.0.0.4": "MoJo_WIN (wifi)",
    "10.0.0.5": "MoJo_WIN (wired)",
    "10.0.0.6": "matt-iMac (wired)",
    "10.0.0.7": "matt-iMac (wifi)",
    "10.0.0.8": "sift-workstation",
}


def tool_definitions() -> list[Tool]:
    return [
        Tool(
            name="network_dns_query",
            description="Query AdGuard Home DNS logs for a hostname or IP address. Returns recent queries, response codes, and client IPs.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Hostname or IP to search for in DNS logs"},
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
    if name == "network_dns_query":
        return await _dns_query(arguments["query"], arguments.get("limit", 50))
    elif name == "network_device_scan":
        return await _device_scan(arguments.get("subnet", "10.0.0.0/24"))
    raise ValueError(f"Unknown tool: {name}")


async def _dns_query(query: str, limit: int):
    if not ADGUARD_USER or not ADGUARD_PASS:
        raise ConstraintError("AdGuard credentials not configured in .env")

    # AdGuard querylog API
    url = f"{ADGUARD_URL}/control/querylog"
    params = {"search": query, "limit": limit}

    try:
        resp = requests.get(url, params=params, auth=(ADGUARD_USER, ADGUARD_PASS), timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        return [TextContent(type="text", text=f"AdGuard API error: {e}")]

    entries = data.get("data", [])
    if not entries:
        return [TextContent(type="text", text=f"No DNS log entries found for: {query}")]

    lines = [f"DNS query log results for '{query}' ({len(entries)} entries):"]
    for entry in entries:
        time = entry.get("time", "")[:19].replace("T", " ")
        question = entry.get("question", {})
        answer = entry.get("answer", [])
        client = entry.get("client", "unknown")
        reason = entry.get("reason", "")
        status = entry.get("status", "")

        answer_str = ", ".join(
            a.get("value", "") for a in answer if a.get("value")
        ) if answer else "NXDOMAIN"

        lines.append(
            f"  {time} | {client} → {question.get('name', '')} "
            f"[{question.get('type', '')}] → {answer_str} | {status} {reason}"
        )

    return [TextContent(type="text", text="\n".join(lines))]


async def _device_scan(subnet: str):
    # Validate subnet is within expected range
    if not subnet.startswith("10.0.0"):
        raise ConstraintError(f"Subnet {subnet} is outside the allowed LAN range (10.0.0.0/24)")

    try:
        result = subprocess.run(
            ["sudo", "nmap", "-sn", "-oX", "-", subnet],
            capture_output=True, text=True, timeout=60
        )
    except FileNotFoundError:
        return [TextContent(type="text", text="nmap not found — install with: sudo apt install nmap")]
    except subprocess.TimeoutExpired:
        return [TextContent(type="text", text="nmap scan timed out after 60s")]

    if result.returncode != 0:
        return [TextContent(type="text", text=f"nmap error: {result.stderr}")]

    # Parse XML output
    try:
        root = ET.fromstring(result.stdout)
    except Exception as e:
        return [TextContent(type="text", text=f"Failed to parse nmap output ({type(e).__name__}): {e}")]

    devices = []
    unknown = []

    for host in root.findall("host"):
        if host.find("status").get("state") != "up":
            continue

        ip = ""
        mac = ""
        vendor = ""
        hostname = ""

        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr", "")
                vendor = addr.get("vendor", "")

        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        known_name = KNOWN_DEVICES.get(ip)
        flag = "" if known_name else " *** UNKNOWN ***"
        label = known_name or hostname or "unidentified"

        entry = f"  {ip:<16} {mac:<20} {vendor:<20} {label}{flag}"
        devices.append(entry)
        if not known_name:
            unknown.append(ip)

    lines = [
        f"Network scan: {subnet} — {len(devices)} hosts up ({len(unknown)} unknown)",
        f"Scanned: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"  {'IP':<16} {'MAC':<20} {'Vendor':<20} Label",
        "  " + "-" * 72,
    ] + devices

    if unknown:
        lines += ["", f"UNKNOWN DEVICES ({len(unknown)}):"]
        for ip in unknown:
            lines.append(f"  {ip} — not in known inventory, investigate")

    return [TextContent(type="text", text="\n".join(lines))]
