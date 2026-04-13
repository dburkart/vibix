---
name: usage
description: Report real Claude Code session-quota state — percent of the 5-hour and 7-day windows used, reset times, and status (ok/warning/rejected). Same numbers Claude Code's own statusline reports. Use when the user asks about usage, quota, rate limits, or when auto-engineer's quota gate calls `/usage`.
---

# usage

The authoritative source for session-quota state is the set of `anthropic-ratelimit-unified-*` response headers Anthropic attaches to every `/v1/messages` call. Claude Code reads them into memory and feeds them to its statusline — they are the real numbers, not an estimate.

Since that state lives only in the running Claude Code process, this skill fetches it by making a minimal 1-token probe call and parsing the headers. Result is cached for 60s at `~/.claude/cache/usage-probe.json` so repeat invocations are free.

## Primary command

```sh
bash .claude/skills/usage/probe.sh
```

(Add `--force` to bypass the 60s cache.)

Output is a single-line JSON like:

```json
{"http":200,"fetched_at":1776054016,
 "5h":{"utilization":0.38,"resets_at":1776056400,"status":"allowed"},
 "7d":{"utilization":0.33,"resets_at":1776567600,"status":"allowed"},
 "overage":{"utilization":0.0,"resets_at":1777593600,"status":"allowed"}}
```

Fields: `utilization` is 0..1+ (can exceed 1 when the window is over-consumed), `resets_at` is Unix epoch seconds, `status` is `allowed` / `allowed_warning` / `rejected`.

## Output format

Always emit these two machine-readable lines first (auto-engineer step 9 parses them):

```
remaining_pct: <max(0, 100 - 5h.utilization*100), rounded to 1 decimal>
reset_ts: <ISO-8601 of 5h.resets_at>
```

Then a short human summary: 5h %, 7d %, overage %, each window's status, time-until-reset, and a note if `status=rejected` (Claude Code is currently blocked on that limit until reset).

## Fallback

If the probe returns an error (no credentials, non-200, missing headers), fall back to ccusage:

```sh
npx -y ccusage blocks --active --token-limit max --json
```

Label fallback output clearly as **estimated** — ccusage benchmarks against the user's all-time largest block, *not* the plan's real cap, so its percentage is routinely off by 2-3× vs. the probe. Use `projection.remainingMinutes` and `endTime` from `.blocks[0]`.

## Other reports (on request)

- `ccusage daily --json` — per-day token rollup.
- `ccusage session --json -p <project>` — per-conversation rollup.
- `ccusage monthly --json` — per-month rollup.

These are token-count reports, not quota; run only when the user asks for historical breakdowns.

## Caveats

- The probe costs one tiny Haiku call (~22 in / 1 out, well under $0.001). The 60s cache keeps this negligible.
- `overage` appears only on plans where extra-usage is enabled; absent otherwise.
- If the user is fully rate-limited (`5h.status == "rejected"`), the probe itself still succeeds — Anthropic returns headers on 200s and rejects only subsequent inference calls. If it ever fails with 429, report `remaining_pct: 0` and surface the cached `reset_ts` from a prior probe if one exists.
