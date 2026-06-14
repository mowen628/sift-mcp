# Try It Out

End-to-end walkthrough of running `sift-mcp` against your own SIFT VM.

## Prereqs

- SANS SIFT Workstation VM (Ubuntu 24.04). Other Linux x86_64 distros work but you'll need to install Plaso + Volatility yourself.
- Python 3.12 with venv
- An InfluxDB v2 instance (a `docker run influxdb:2` is enough)
- The Claude Code CLI (`claude`)

## 1. Install

```bash
git clone https://github.com/mowen628/sift-mcp.git ~/sift-mcp
cd ~/sift-mcp
python -m venv ~/sift-mcp-env
source ~/sift-mcp-env/bin/activate
pip install -r requirements.txt
```

## 2. Configure

```bash
cp .env.example .env
$EDITOR .env
```

Fill in:

| Var | Notes |
|---|---|
| `INFLUXDB_URL` | e.g. `http://10.0.0.11:8086` |
| `INFLUXDB_TOKEN` | Bucket-scoped token for `sift-ir` (don't use admin) |
| `INFLUXDB_ORG`, `INFLUXDB_BUCKET` | `owen-homelab`, `sift-ir` for the reference install |
| `ADGUARD_URL`, `ADGUARD_USER`, `ADGUARD_PASS` | AdGuard Home web UI creds |
| `DOCKER_HOST_IP`, `DOCKER_HOST_USER`, `DOCKER_HOST_KEY` | SSH target for container log triage. User needs `docker` group membership. |
| `VOL3_BIN` | Path to `vol` in your venv (e.g. `~/sift-mcp-env/bin/vol`) |

Push the SSH pubkey at `DOCKER_HOST_KEY` to your Docker host's `authorized_keys` for whatever user you set in `DOCKER_HOST_USER`.

## 3. Generate a kernel ISF for Volatility

Volatility 3 needs an Intermediate Symbol File matching your live kernel. On SIFT:

```bash
sudo apt install linux-image-$(uname -r)-dbgsym dwarf2json
dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) \
  > ~/sift-mcp-env/lib/python3.12/site-packages/volatility3/symbols/linux/linux-$(uname -r).json
```

(If you reboot into a new kernel, you'll need a new ISF — or boot back into the matching one via `grub-reboot`.)

## 4. Capture a memory image

```bash
curl -sL https://github.com/microsoft/avml/releases/download/v0.14.0/avml -o /tmp/avml
chmod +x /tmp/avml
sudo /tmp/avml ~/sift-mcp/captures/$(hostname)-$(date +%Y%m%d).mem
```

~4 GB image takes ~90 seconds on a 4 GiB VM.

## 5. Register the MCP server

```bash
claude mcp add sift-mcp -- ~/sift-mcp-env/bin/python ~/sift-mcp/server.py
claude mcp list   # → sift-mcp: ✓ Connected
```

## 6. Run a case

In a Claude Code session:

```
Open a case called demo-2026-06-14 for "investigation of unexpected outbound
DNS traffic". Then:
1. Pull the last hour of AdGuard logs for any *.cn or *.ru lookups
2. List the running containers on the Docker host
3. Capture pslist from /home/sansforensics/sift-mcp/captures/sift-vm-20260614.mem
4. Generate the case report
```

Claude chains `case_create` → `network_dns_query` → `logs_list_containers` → `memory_pslist` → `case_add_finding` (one per discovery) → `case_report`. Findings land in `/cases/demo-2026-06-14/`, in InfluxDB, and on the Grafana dashboard.

## 7. Watch the trail

- Live audit log: `tail -f ~/sift-mcp/logs/session-*.jsonl`
- Case dir: `tree /cases/demo-2026-06-14/`
- Grafana: `http://<your-influx-host>:3030/d/adc8967/sift-ir-findings`

## Gotchas

- **Severity values:** the schema says `low|medium|high|critical`. Use exactly those — `info`/`warn` aren't accepted by `case_report`'s sort.
- **Clock skew:** a VM resumed from `aborted` state can have wildly wrong time. InfluxDB writes use the local clock, so `timedatectl set-ntp true` + `sudo date -s` before doing real work, or your findings will land in the past.
- **Bridged-adapter flakiness:** under sustained Plaso load on a VirtualBox bridged NIC the network occasionally drops. Keep timeline sources bounded (single log file, not all of `/var/log`).
