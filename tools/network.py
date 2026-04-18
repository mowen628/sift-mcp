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

# Known device inventory keyed by MAC address (more reliable than IP)
# Source: DD-WRT static DHCP leases + observed devices
MAC_INVENTORY = {
    # Core infrastructure
    "3C:37:86:F7:35:95": ("10.0.0.1",  "gateway-R7000P"),
    "8C:86:DD:06:14:68": ("10.0.0.2",  "tp-link-switch"),
    "00:05:1B:DD:BB:84": ("10.0.0.3",  "homeserver"),
    "70:08:10:53:F2:14": ("10.0.0.4",  "MoJo_WIN-wifi"),
    "4C:EA:41:6A:E8:A0": ("10.0.0.5",  "MoJo_WIN-wired"),
    "AC:87:A3:2E:AE:6A": ("10.0.0.6",  "matt-iMac-wired"),
    "B8:09:8A:CA:1F:6B": ("10.0.0.7",  "matt-iMac-wifi"),
    "08:00:27:C8:E8:59": ("10.0.0.8",  "sift-workstation"),
    # People / phones / tablets
    "60:81:10:96:0F:66": ("10.0.0.11", "Jessies-iPhone"),
    "08:C7:B5:E6:8A:53": ("10.0.0.12", "Matt-iPhone"),
    "08:C7:B5:EB:15:78": ("10.0.0.13", "Ellies-iPhone"),
    "56:67:EB:6F:F3:29": ("10.0.0.17", "iPad"),
    "70:74:14:77:8C:45": ("10.0.0.19", "Android1"),
    "70:74:14:7A:F9:E7": ("10.0.0.20", "Android2"),
    "40:88:05:A1:86:1B": ("10.0.0.21", "Android3"),
    # Smart speakers / TV
    "2C:71:FF:F9:88:BD": ("10.0.0.31", "Echo-Show-LivingRoom"),
    "74:4D:BD:DB:07:44": ("10.0.0.32", "Echo1"),
    "8C:2A:85:5E:DE:47": ("10.0.0.33", "Echo2"),
    "08:12:A5:8F:44:B0": ("10.0.0.35", "Amazon-DEV"),
    # IoT / smart home
    "64:9A:63:D6:3F:F9": ("10.0.0.41", "Ring-doorbell"),
    "04:7E:4A:20:DA:3E": ("10.0.0.42", "FrontPorch-Tuya"),
    "A8:6B:AD:6E:B3:97": ("10.0.0.61", "BRWA-unknown-IoT"),
    "A8:42:A1:D0:F7:8D": ("10.0.0.114","HS103-smartplug-1"),
    "A8:42:A1:D0:E9:6C": ("10.0.0.115","HS103-smartplug-2"),
    "68:57:2D:58:48:CA": ("10.0.0.117","Irrigation-Hub-Tuya"),
    # ESPHome devices
    "80:F3:DA:AD:41:E0": ("10.0.0.43", "chameleon-cam"),
    "48:D8:90:A8:76:15": ("10.0.0.44", "MyQ-garage"),
    "38:18:2B:2F:75:18": ("10.0.0.68", "vivbot-controller"),
    "78:1C:3C:CB:68:88": ("10.0.0.69", "hvergelmir-water"),
    "00:70:07:E7:1E:9C": ("10.0.0.70", "chip-tortoise"),
    "78:1C:3C:CA:60:5C": ("10.0.0.71", "loki-controller"),
    "EC:E3:34:79:80:80": ("10.0.0.72", "bench-sandbox"),
    "0C:4E:A0:81:C5:40": ("10.0.0.73", "espressif-73"),
    "0C:4E:A0:86:15:D8": ("10.0.0.74", "espressif-74"),
    "0C:4E:A0:81:85:B8": ("10.0.0.75", "espressif-75"),
    "10:20:BA:A0:27:40": ("10.0.0.76", "Irrigation-Pump"),
    "10:20:BA:A0:2B:34": ("10.0.0.77", "espressif-77"),
    "A8:46:74:10:13:D8": ("10.0.0.78", "espressif-78"),
    "A8:46:74:29:45:C4": ("10.0.0.79", "espressif-79"),
    "A8:46:74:2E:54:54": ("10.0.0.80", "espressif-80"),
    "A8:46:74:10:F7:94": ("10.0.0.81", "espressif-81"),
    "40:F5:20:13:DF:F2": ("10.0.0.82", "ESP-82-Tuya"),
    "D8:F1:5B:A4:BF:92": ("10.0.0.83", "ESP-83-Tuya"),
    "44:1D:64:F8:D6:F8": ("10.0.0.84", "esphome-web-unprovisioned"),
    "C4:DD:57:1C:EE:2C": ("10.0.0.101","ESP-101-Tuya"),
    "C4:DD:57:25:C4:2B": ("10.0.0.102","ESP-102-Tuya"),
    "C4:DD:57:14:9B:1E": ("10.0.0.103","ESP-103-Tuya"),
    "C4:DD:57:14:B2:97": ("10.0.0.104","ESP-104-Tuya"),
    "C4:DD:57:25:50:83": ("10.0.0.105","ESP-105-Tuya"),
    "C4:DD:57:14:DF:BF": ("10.0.0.106","ESP-106-Tuya"),
    "C4:DD:57:14:A6:05": ("10.0.0.107","ESP-107-Tuya"),
    "70:03:9F:90:3C:F6": ("10.0.0.108","ESP-108-Tuya"),
    "70:03:9F:51:75:B1": ("10.0.0.109","ESP-109-Tuya"),
    "70:03:9F:51:41:9F": ("10.0.0.110","ESP-110-Tuya"),
    "70:03:9F:90:30:80": ("10.0.0.111","ESP-111-Tuya"),
    "24:62:AB:2E:03:19": ("10.0.0.112","ESP-112-Tuya"),
    "C4:82:E1:F8:03:D6": ("10.0.0.113","lwip0-ESP"),
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
    import asyncio as _asyncio
    # Validate subnet is within expected range
    if not subnet.startswith("10.0.0"):
        raise ConstraintError(f"Subnet {subnet} is outside the allowed LAN range (10.0.0.0/24)")

    try:
        proc = await _asyncio.create_subprocess_exec(
            "sudo", "nmap", "-sn", "-oX", "-", subnet,
            stdout=_asyncio.subprocess.PIPE,
            stderr=_asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await _asyncio.wait_for(proc.communicate(), timeout=60)
        stdout = stdout_bytes.decode()
        stderr = stderr_bytes.decode()
    except FileNotFoundError:
        return [TextContent(type="text", text="nmap not found — install with: sudo apt install nmap")]
    except _asyncio.TimeoutError:
        return [TextContent(type="text", text="nmap scan timed out after 60s")]

    if proc.returncode != 0:
        return [TextContent(type="text", text=f"nmap error: {stderr}")]

    # Parse XML output
    try:
        root = ET.fromstring(stdout)
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

        mac_upper = mac.upper()
        # SIFT VM doesn't see its own MAC via ARP — identify by IP
        if ip == "10.0.0.8" and not mac:
            label = "sift-workstation (self)"
            flag = ""
            entry = f"  {ip:<16} {'(self)':<20} {'':<20} {label}"
            devices.append(entry)
            continue

        inventory_entry = MAC_INVENTORY.get(mac_upper)

        if inventory_entry:
            expected_ip, name = inventory_entry
            if expected_ip != ip:
                label = f"{name} [WRONG IP: expected {expected_ip}]"
                flag = " *** IP MISMATCH ***"
            else:
                label = name
                flag = ""
        else:
            label = hostname or "unidentified"
            flag = " *** UNKNOWN ***"

        entry = f"  {ip:<16} {mac:<20} {vendor:<20} {label}{flag}"
        devices.append(entry)
        if "UNKNOWN" in flag:
            unknown.append((ip, "not in known inventory, investigate"))
        elif "MISMATCH" in flag:
            unknown.append((ip, f"known device at wrong IP — {label}"))

    lines = [
        f"Network scan: {subnet} — {len(devices)} hosts up ({len(unknown)} unknown)",
        f"Scanned: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"  {'IP':<16} {'MAC':<20} {'Vendor':<20} Label",
        "  " + "-" * 72,
    ] + devices

    if unknown:
        lines += ["", f"FLAGGED DEVICES ({len(unknown)}):"]
        for ip, reason in unknown:
            lines.append(f"  {ip} — {reason}")

    return [TextContent(type="text", text="\n".join(lines))]
