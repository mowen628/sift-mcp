# Accuracy Report

Honest accounting of what `sift-mcp` does well, what it gets wrong, and where the seams show. Tested end-to-end on the SIFT VM on 2026-06-14 (smoke-test case `smoke-test-20260614b`).

## What Works

| Tool | Verified behavior | Notes |
|---|---|---|
| `case_create` | Creates `/cases/<id>/{case.json, findings.json, reports/, exports/, analysis/}` | Idempotent — calling twice is a no-op on existing dirs |
| `case_add_finding` | Appends to `findings.json`, returns `Finding #N added` | Severity enum is **not** enforced at dispatch — see Known Issues |
| `case_report` | Writes Markdown report, ships findings to InfluxDB `sift-ir` bucket | Verified live: `ir_finding` rows visible via Flux within seconds |
| `network_dns_query` | Returns up to 50 most recent AdGuard hits for a query | Real network data, includes upstream resolver answers and filter status |
| `logs_container`, `logs_list_containers` | `docker ps` / `docker logs` over paramiko SSH | Verified against 7-container Docker LXC |
| `ioc_hash` | MD5 + SHA1 + SHA256 in one pass | Streaming hash, handles GB-scale files |
| `ioc_list_rules` | Enumerates `yara_rules/*.yar` | Used as a sanity check before `ioc_yara_scan` |
| `memory_pslist` | Vol3 `linux.pslist.PsList` returns full process tree | 226 procs recovered from 4 GB live capture; needs matching ISF |
| `timeline_create` | Plaso `log2timeline.py` builds `.plaso` storage | Bounded sources (single log file) finish in seconds; `/var/log` whole-tree took >12 min and didn't complete before we killed it |
| `timeline_query` | Plaso `psort.py -o dynamic` emits CSV, tool returns first `limit` rows | 4,361 events across 4 kB of dpkg.log parsed cleanly |

## Known Issues

### Schema enums aren't enforced at dispatch
The `case_add_finding` schema declares `severity: enum[low, medium, high, critical]`, but the dispatcher accepts any string. A bad value is silently written, and then `case_report` blows up with `ValueError("'info' is not in list")` when it tries to sort by `SEVERITY_ORDER.index(...)`. Tool should validate against the schema before write, or `case_report` should treat unknown severities as `low` instead of crashing.

### Partial `.plaso` files crash psort
If `log2timeline.py` is killed mid-write, its SQLite storage file is left open at an inconsistent state. The next `timeline_query` fails with `sqlite3.DatabaseError: database disk image is malformed`. Should detect this and offer to recreate, or always write to a temp path and rename on success.

### `logs_*` returns a misleading exit code
When the SSH connection to the Docker host fails, `logs_container` returns `[OK]` (tool returned without exception) with body `"SSH connection failed: ..."`. Caller has to read the body to know it failed. Should raise so the MCP client surfaces it as an error.

### Stale `__pycache__` masked an env reload during testing
On first run after editing `.env`, `tools/__pycache__/logs.cpython-312.pyc` had the old `DOCKER_HOST_IP` baked into a previously imported module reference. Symptom: `Network is unreachable` against the new IP even though `dotenv` loaded the new value. Fix is `rm -rf tools/__pycache__` after env changes — worth a note in `try-it-out.md`.

## Operational Caveats

- **ISF must match running kernel.** Vol3 will refuse with a banner-mismatch error if the symbol file doesn't line up with the kernel that produced the memory image. Pin a kernel via `grub-reboot` or generate a new ISF after every kernel update.
- **VirtualBox bridged NICs are not robust under sustained load.** Our SIFT VM dropped its DHCP lease and lost SSH multiple times under heavy Plaso parsing. Doesn't affect tool correctness, but does affect how long a session lasts.
- **Clock skew on resumed VMs.** A VM resumed from `aborted` state can be hours behind real time. Findings are timestamped at write — wall clock matters. Run `timedatectl set-ntp true && sudo date -s "$(date -u ...)"` after any unclean resume.
- **Bucket-scoped tokens are mandatory.** The reference install gives `sift-mcp` a token scoped to the `sift-ir` bucket only. A leaked SIFT VM should not be able to read or wipe Home Assistant's data.

## What's Not Tested

- `memory_malfind`, `memory_netscan`, `memory_cmdline`, `memory_dlllist` — all dispatch through the same Vol3 path as `memory_pslist` and inherit the ISF requirement, but only `pslist` was exercised end-to-end in the post-cutover smoke.
- `network_device_scan` — code exists and reads the static-mapping table, but no live nmap run was included in the smoke pass.
- `ioc_yara_scan` against an actual malicious sample — only `ioc_list_rules` and `ioc_hash` were exercised.

These are next on the test list, not gaps in the implementation.
