# Demo Video Script — sift-mcp

**Target runtime:** 3:00 (Devpost rewards 2–3 min screencasts; the Find Evil ≤5 min cap means 3:00 is "safe with breathing room")
**Format:** screencast + voiceover. One continuous take of the terminal where possible; cut to two pre-loaded browser tabs for B-roll. No transitions, no music, no title cards beyond a one-frame opener.
**Tooling:** OBS Studio (record), trim head/tail in OBS or Shotcut/VLC. No timeline editing needed if you stick to the script.

---

## Recording preflight (do all of this BEFORE you hit record)

| # | Setup |
|---|---|
| 1 | Resize terminal to roughly 100×35, big readable font (≥16pt). Solarized/dark, no transparency. |
| 2 | In a fresh shell on the SIFT VM, `cd ~/sift-mcp && source ~/sift-mcp-env/bin/activate && clear`. Leave this window open for the demo take. |
| 3 | Open Grafana in browser tab 1: `http://10.0.0.11:3030/d/adc8967/sift-ir-findings`. Time range = **Last 5 minutes**. Auto-refresh = 5s. Leave the panel page visible. |
| 4 | Open the case report Markdown in browser tab 2 (or a Markdown previewer): `/cases/demo-2026-06-15/reports/report-2026-06-15.md` after you've done a dry-run that creates it. (Or use whatever case_id you settle on; replace consistently below.) |
| 5 | Dry-run the Claude prompt in step §The demo, twice, to confirm Claude chains the tools you expect. If it goes sideways, narrow the prompt — sample variants are below the script. |
| 6 | Close anything noisy: Slack, email, notifications. Disable Do Not Disturb is OFF (so nothing pops mid-take). Mute system volume. |
| 7 | Mic test: record 10 sec, play back, confirm no fan/keyboard rumble. Use a directional mic if you have one. |
| 8 | OBS scenes: one "Terminal" scene (window capture of the SSH terminal), one "Browser" scene (window capture of the browser). Bind a hotkey to switch — you'll only hit it twice in the whole take. |
| 9 | Have the **voiceover script** open on a phone or second monitor at a glanceable font size. **Do not read in monotone** — pace yourself; pauses are fine. |

---

## The Script

Layout: **[TIME]** **ON SCREEN** — narration in *italics*. Each line is roughly one breath group; the slash `/` is a pause beat.

---

### 0:00 – 0:12 · Hook
**On screen:** Terminal at a fresh prompt. Type the title as a comment line so it appears on-screen:
```
$ # sift-mcp: autonomous IR for the SANS SIFT Workstation
```

*"My homelab routes about fifty devices through a single firewall. / If something on it ever went sideways, / I'd want an agent that doesn't just answer questions about incident response — / it actually performs the investigation. / That's sift-mcp."*

(≈42 words / 12 sec)

---

### 0:12 – 0:35 · What it is
**On screen:** Type and run a quick info command so something concrete is on screen — `ls tools/` and `claude mcp list` are both perfect:
```
$ ls tools/
case.py  ioc.py  logs.py  memory.py  network.py  timeline.py
$ claude mcp list
sift-mcp: ✓ Connected
```

*"It's a custom MCP server / on a SANS SIFT VM bridged onto my LAN. / Six tool modules: / live network triage, / Docker log triage, / memory forensics with Volatility 3, / IOC scanning, / Plaso timelines, / and a case manager. / Claude Code orchestrates them — / over stdio, with a Python-side guardrail layer, / and a JSONL audit trail per session."*

(≈58 words / 23 sec)

---

### 0:35 – 0:55 · Why "real data" matters
**On screen:** Stay in the terminal. Run a tiny one-liner that demonstrates the live AdGuard connection — e.g.:
```
$ curl -s -u $ADGUARD_USER:$ADGUARD_PASS \
    "$ADGUARD_URL/control/stats" | jq '.num_dns_queries'
189432
```

*"This is real network data, not a lab fixture. / AdGuard Home is currently sitting on a hundred and eighty-nine thousand DNS queries / from phones, smart bulbs, ESPs, / and whatever my five-year-old's tablet was doing this morning. / If you want to find evil, / you need a corpus where evil could actually hide."*

(≈48 words / 20 sec)

---

### 0:55 – 2:15 · THE DEMO (the part that wins the video)
**On screen:** Launch Claude Code. Paste the demo prompt **all at once** — typing it live wastes 30 seconds of viewer attention.

Prompt to paste:
```
Open a case called demo-2026-06-15 with the description
"investigation of unexpected DNS lookups". Then in order:
1. Pull the most recent AdGuard query for "github.com"
2. List running containers on the Docker host
3. Run memory_pslist against
   /home/sansforensics/sift-mcp/captures/sift-vm-20260614.mem
4. Add a low-severity finding summarizing what you saw
5. Generate the case report.
```

*[As Claude starts working]* *"I'm giving it five steps in one prompt — / open a case, / pull a DNS lookup, / inventory the Docker host, / pslist a memory image I captured earlier, / log a finding, / and write the report."*

*[As `case_create` fires — visible in Claude's tool-call output]* *"Notice it's chaining the tools itself. / Every call goes through a guardrail layer that requires a case context / and refuses any path outside the allowlist."*

*[As `network_dns_query` returns AdGuard results]* *"That's a live query against AdGuard — / real lookups, real timestamps, real upstream answers."*

*[As `logs_list_containers` runs]* *"That's an SSH'd `docker ps` against my homelab — / paramiko under the hood, bucket-scoped credentials in the .env."*

*[As `memory_pslist` runs and the process table scrolls]* *"And that's Volatility 3 / on a four-gigabyte live memory capture. / Two hundred and twenty-six processes recovered / from a real Linux kernel image. / The ISF is generated from the matching dbgsym package — / pinned to the kernel I'm actually running."*

*[As `case_add_finding` and `case_report` fire]* *"Finding logged, report generated, / and a row written to InfluxDB."*

(Pacing target: ≈190 words / 80 sec. Talk in the gaps between tool calls. Don't fight to talk OVER Claude's output — let it breathe, then narrate.)

---

### 2:15 – 2:40 · The observability payoff
**On screen:** Hotkey to the **browser** scene. Grafana dashboard fills the frame, "Last 5 minutes" range, with the finding visibly landed.

*"Findings don't just go to disk. / Every report writes to a bucket-scoped InfluxDB token / and surfaces here, on a Grafana dashboard. / Active cases, findings by severity, findings over time. / Same data my Home Assistant can page me on / when something hits high or critical."*

(≈42 words / 18 sec)

Then quick cut back to the **terminal** scene and `cat` the report:
```
$ cat /cases/demo-2026-06-15/reports/report-2026-06-15.md
```

*"And here's the human-readable report Claude generated, / with the full audit trail in `logs/session-*.jsonl` right next to it."*

(≈22 words / 7 sec)

---

### 2:40 – 3:00 · Close
**On screen:** One last terminal command to land the repo URL on screen:
```
$ echo "github.com/mowen628/sift-mcp"
```

*"Guardrails in code, not in prompts. / Bucket-scoped tokens so a SIFT compromise can't take down the homelab. / Real network, real findings, / and an accuracy report in the repo / that's honest about what doesn't work yet. / sift-mcp — / github dot com slash mowen six twenty-eight slash sift-mcp."*

(≈45 words / 20 sec)

Hold the final shot for **one full second** with the URL on screen, then stop recording.

---

## Word budget summary

| Section | Words | Seconds | Cumulative |
|---|---:|---:|---:|
| Hook | 42 | 12 | 0:12 |
| What it is | 58 | 23 | 0:35 |
| Why real data | 48 | 20 | 0:55 |
| The demo | 190 | 80 | 2:15 |
| Observability | 64 | 25 | 2:40 |
| Close | 45 | 20 | 3:00 |
| **Total** | **447** | **180** | **3:00** |

That's ≈149 wpm — relaxed, intelligible, room to breathe. If you find yourself rushing, cut the "Why real data" beat first (it's the most expendable) and you land at 2:40.

---

## Backup prompts (if Claude goes sideways during rehearsal)

If Claude doesn't reliably chain all five steps from the single prompt, narrow the prompt so the tools are explicit:

**Tighter variant:**
```
Use sift-mcp tools to do exactly this, in order:
1. case_create with case_id="demo-2026-06-15" and description="investigation of unexpected DNS lookups"
2. network_dns_query for "github.com"
3. logs_list_containers
4. memory_pslist with case_id="demo-2026-06-15" and image="/home/sansforensics/sift-mcp/captures/sift-vm-20260614.mem"
5. case_add_finding with case_id="demo-2026-06-15", title="initial triage complete", description="DNS query, container inventory, and memory pslist captured", severity="low"
6. case_report for "demo-2026-06-15"
Do not narrate, just execute.
```

That removes Claude's interpretive layer and makes the tool sequence deterministic. The voiceover script above still fits without changes.

---

## What to *avoid* (saves you from re-takes)

- **Don't read in monotone.** Punch the verbs: *"chaining"*, *"recovered"*, *"writes"*, *"refuses"*.
- **Don't say "uh", "um", "so".** Take the half-second silence instead — pauses sound confident, fillers don't.
- **Don't type the demo prompt live.** Paste it. Watching someone type for 20 seconds is death.
- **Don't pan around the Grafana dashboard.** Pick one view, hold it, move on.
- **Don't show a terminal error.** If something errors mid-take, stop recording, fix it, restart from the section break — the script is designed so each section is a clean re-entry point.
- **Don't apologize.** Even if you flub a word, keep going. Most viewers won't notice; judges definitely don't care.

---

## Post-production checklist (≤30 min if you stuck to the script)

1. Trim head: cut everything before "My homelab routes..."
2. Trim tail: cut everything after the held URL frame
3. Loudness pass: target around −16 LUFS. OBS's audio filter or a one-pass Audacity normalize is fine.
4. Export: 1080p, H.264, 60fps if your screen recording was 60fps, otherwise 30fps. MP4 container.
5. Upload to YouTube. **Mark "Not for Kids"** (COPPA), set visibility to **Unlisted** (Devpost recommends unlisted over public). Get the URL.
6. Paste the URL into the Devpost submission video field.

That's it. If you can record a clean take in two attempts, you're done in under an hour total.
