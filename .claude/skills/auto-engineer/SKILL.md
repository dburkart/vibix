---
name: auto-engineer
description: Autonomously drive vibix work end-to-end — pick an unblocked issue, plan it, implement, push a PR, resolve CI and review-bot feedback, merge when green, then repeat. Use when the user says "auto-engineer", "auto-pilot", "go run the loop", or invokes `/auto-engineer`.
---

# auto-engineer

Read these shared playbooks first:

- `docs/agent-playbooks/sdlc.md`
- `docs/agent-playbooks/build-run.md`
- `docs/agent-playbooks/testing.md`
- `docs/agent-playbooks/pr-review.md`
- `docs/agent-playbooks/prioritization.md`

Closes the full SDLC loop without prompting the user between steps. Each invocation runs **one cycle** (pick → plan → implement → PR → wait → merge), then reschedules itself via `ScheduleWakeup` with prompt `/auto-engineer` for the next cycle. Stops cleanly when it runs out of work or hits something it can't safely resolve.

This skill is a deliberate override of the project's default "don't merge your own PRs" rule — merging is the whole point of closing the loop. It only applies while auto-engineer is driving.

## When to invoke

- User says "run the loop", "auto-engineer", "auto-pilot the next issue", or similar.
- User types `/auto-engineer` (optionally with `#NN` to scope to a single issue for one cycle, no reschedule).
- This skill re-invokes itself at the end of each successful cycle via `ScheduleWakeup`.

## Entry flags and phase state

All persistent state lives in the wakeup prompt — `/compact` can summarize away conversation state, so nothing important should rely on being in context.

Parse these flags on every entry before doing any work:

| Flag | Meaning |
|---|---|
| `--iteration N` | Current cycle number (1-indexed). Absent → treat as 1. |
| `--phase wait` | Re-entry into the PR-wait poll loop (jump to step 6b). Requires `--pr`. |
| `--pr M` | PR number being waited on (only meaningful with `--phase wait`). |
| `#NN` | Scope to a single issue for one cycle, then stop without rescheduling. |

A bare `/auto-engineer` is iteration 1, phase "pick".

## Iteration budget

**Soft cap: 8 iterations per user-initiated run.** After the 8th merged PR, stop and wait for the user to restart. Prevents runaway loops.

The `--iteration N` flag is what enforces the cap across `/compact` boundaries — always carry it in every `ScheduleWakeup` call.

## Cycle

### 1. Pick an unblocked issue

The picking rules live in `docs/agent-playbooks/prioritization.md` — this step is the
mechanical implementation of that policy. The north star is the minimal useful kernel:
work P0s first, then P1s, and so on.

```sh
gh issue list --search 'no:assignee' --state open \
  --json number,title,labels,body,assignees
```

Filter out:
- Issues labeled `blocked`, `needs-discussion`, `question`, `wontfix`.
- Issues whose body references an unresolved dependency (e.g. "blocked on #NN" where #NN is still open).

Sort preference (apply in order — do **not** fall back to "oldest first" until you have
exhausted the priority ordering):

1. `priority:P0` before `priority:P1` before `priority:P2` before `priority:P3`. Issues with
   no `priority:*` label rank **after** `priority:P3` — they are un-triaged.
2. Within a priority bucket, prefer `track:userspace`, then `track:filesystem`, then
   `track:terminal`, then `track:posix`, then untracked.
3. Within a (priority, track) bucket, lowest-numbered first.

If the top candidate's prerequisites are still open, skip it and try the next one rather
than starting work that cannot land. If a candidate is un-triaged (no `priority:*` label),
prefer triaging it via the `file-issue` skill's label rules before working it — don't mine
the un-triaged tail for "easy" work and bypass the priority queue.

If the candidate list is empty → **stop** (see Stopping below) with message *"no unblocked issues — auto-engineer idle."*

Assign and branch per `docs/agent-playbooks/sdlc.md`:

```sh
gh issue edit <N> --add-assignee dburkart
git checkout main && git pull
git checkout -b <branch>   # m<N>-<slug> or <verb>-<slug>
```

### 2. Delegate planning to a sub-agent

Use the `Agent` tool with `subagent_type: "Plan"`. Pass the full issue body, its label list, and any linked issues you fetched. Ask for:

- Files to create / modify (absolute paths).
- Functions or structs to add / change, with signatures.
- Tests to add (host unit vs. QEMU integration vs. smoke marker).
- Risks and rollback plan.

Return format: plain markdown, ≤300 words. The parent reads the result as conversation text — **do not** enter plan mode for the sub-agent.

### 3. Auto-approve and implement

The parent proceeds directly with `Edit` / `Write` per the returned plan. No user confirmation. If the sub-agent's plan is clearly wrong (wrong file paths, contradicts code you read), re-spawn it once with a corrective prompt; if it's still wrong after that, **stop** and report.

### 4. Build + test

Run in order, following the shared build and testing playbooks:

```sh
cargo xtask build
cargo xtask test
cargo xtask smoke
```

On failure: diagnose and fix in place. **Maximum 3 fix attempts per cycle.** If the 3rd attempt still fails → **stop** with a summary of the failure and what was tried.

### 5. Commit and open PR

Per `docs/agent-playbooks/sdlc.md`:

- Coherent commits (not a single mega-commit, not micro-commits). Each with the standard `Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>` trailer.
- `git push -u origin <branch>`.
- Open the PR via `mcp__github__create_pull_request` with the standard Summary + Test plan body. **No "generated with" footer.**
- **Always include `Closes #<N>`** on its own line near the top of the PR body (where `<N>` is the issue picked in step 1). Without it, the squash-merge in step 7 won't auto-close the issue, the assignment persists, and step 1's `no:assignee` candidate set stays polluted on the next cycle.
- Record the PR number and URL for the rest of the cycle.

### 6. Wait for CI and review

Auto-engineer owns the PR-wait loop directly — do **not** delegate to the `wait-for-pr`
skill. Delegating would hand off the `ScheduleWakeup` thread and there would be no path back
into this skill when CI finishes.

The `wait-for-pr` skill is for manual invocations only.

#### 6a. First poll tick (immediately after opening the PR)

Record the PR open time. Run one poll tick (step 6b below), then either proceed or sleep.

#### 6b. Poll tick (re-entry via `--phase wait --pr M`)

1. Check CI state:
   ```sh
   gh pr checks <M> --json name,state,bucket,link
   ```
2. Count review-bot activity:
   ```sh
   gh api "repos/{owner}/{repo}/issues/<M>/comments" \
     --jq '[.[] | select(.user.login | test("coderabbitai|greptile|github-advanced-security"))] | length'
   ```
   Also fetch formal reviews via `mcp__github__get_pull_request_reviews`.

3. Evaluate "done" criteria (from `docs/agent-playbooks/pr-review.md`):
   - Every check is in a terminal state (`success`, `failure`, `skipped`, `cancelled`,
     `neutral`, `timed_out`, `stale`) — nothing `in_progress`, `queued`, or `pending`.
   - At least one review-bot comment exists **or** 30 minutes have elapsed since PR opened.

4. **If done**: proceed to step 6c.

5. **If not done**: schedule the next poll tick and end the turn — do not proceed further.
   ```
   ScheduleWakeup(
     delaySeconds=<cadence>,
     prompt="/auto-engineer --iteration N --phase wait --pr M",
     reason="auto-engineer: waiting on CI/review for PR #M (iteration N)"
   )
   ```
   Cadence (same as wait-for-pr playbook):
   | Elapsed since PR opened | delaySeconds |
   |---|---|
   | 0–10 min | 120 |
   | 10–30 min | 180 |
   | 30 min+ (bots only) | 1200 |
   Never use 300 s — it's a cache-miss with no payoff.

   If any check is `action_required` → **stop** instead (human must approve).

#### 6c. Review-response

Carry a `--fix-round R` counter (default 0) forward in the wakeup prompt when looping back
here. **Max 2 fix rounds** — if `R == 2` and findings remain, stop.

**Auto-fix CI failures** (before classifying review findings):

| Failed check pattern | Fix command | Canonical commit subject |
|---|---|---|
| `fmt` / `rustfmt` / `format` | `cargo fmt --all` | `fix: apply rustfmt` |
| `clippy` / `lint` | `cargo clippy --fix --allow-dirty --allow-staged && cargo fmt --all` | `fix: address clippy lints` |

Before applying: check `git log origin/<base>..HEAD --format='%s'` — if the canonical subject
is already there and the check still failed, do not re-apply. Flag as "auto-fix already
attempted, did not resolve" and stop.

After applying a fix: commit with the canonical subject + `Co-Authored-By:` trailer, `git push`,
then schedule another poll tick:
```
ScheduleWakeup(
  prompt="/auto-engineer --iteration N --phase wait --pr M --fix-round R",
  ...
)
```

**Classify review findings** using `docs/agent-playbooks/pr-review.md`:

- **All green, no actionable findings** → proceed to merge (step 7).
- **Actionable bugs** → apply follow-up commits (never amend), `git push`, then reschedule
  another poll tick with `--fix-round R+1`.
- **Out-of-scope nits** → reply on the PR via `mcp__github__add_issue_comment` ("deferred to
  future work"), open a follow-up issue via an `Agent()` call (see "Calling file-issue from a loop" below), then proceed to merge.

### 7. Merge

Only merge when **all** are true:
- Every CI check is `success` or `skipped` (none `failure`, `action_required`, `timed_out`, `pending`).
- No unresolved actionable review findings.
- Either ≥1 review bot posted and every actionable finding is addressed, **or** 30 min elapsed since PR open with nothing actionable.

Merge method is **always `squash`** — the repo's established convention and the only style auto-engineer uses. Don't try to infer it from recent history; the `gh pr list --json mergeCommit` field returns a SHA for every merge method, so it can't distinguish squash from merge-commit or rebase anyway.

```
mcp__github__merge_pull_request(pull_number=<N>, merge_method="squash")
```

Post-merge:

```sh
git checkout main && git pull
git branch -d <branch>
```

### 8. Capture follow-ups

Before reloading the next issue, scan for work that surfaced during this cycle but wasn't in scope. Sources to check:

- The merged diff for new `TODO`, `FIXME`, `XXX`, or `unwrap()` / `expect()` call sites added in this PR (`git show --stat main` + `git log -p -1`).
- Deferred review comments posted in step 6 ("deferred to future work") that didn't already get an issue opened.
- Build/test warnings observed during step 4 that weren't blocking but deserve follow-up.
- Anything the sub-agent's plan (step 2) explicitly listed as "out of scope" or "risks."

For each distinct follow-up, open an issue via an `Agent()` call (see "Calling file-issue
from a loop" below). Do **not** call `Skill("file-issue")` — that replaces this skill's
context and terminates the loop. Feed each Agent():

- A specific title.
- A 1–3 sentence motivation, including `discovered while merging #<PR>` so the origin is
  recoverable later.
- Concrete work items.
- Context (file paths, commit SHAs, related issue numbers).

If nothing worth filing, skip silently. **Do not file speculative or "nice-to-have" issues** — only things with concrete motivation. Over-filing clutters the backlog and degrades the `no:assignee` candidate set that step 1 depends on.

### 9. Check session quota

Before compacting and kicking off the next cycle, check quota by running the probe script
**directly** — do **not** call `Skill("usage")`, which would terminate the loop:

```sh
bash .claude/skills/usage/probe.sh
```

Parse the single-line JSON output (see `docs/agent-playbooks/skill-composition.md` for why
direct invocation is required here). Derive `remaining_pct` as
`max(0, 100 - 5h.utilization*100)` and `reset_ts` as an ISO-8601 string of `5h.resets_at`.

- **≥ 10% remaining** → proceed to step 10.
- **< 10% remaining** → don't start a new cycle; the next one could tip over mid-PR and leave an orphaned branch. Instead:
  1. Read `reset_ts` from the probe JSON output.
  2. Compute `secondsUntilReset = reset_ts - now`. Add a 60 s buffer so the wake-up lands *after* the reset, not on its edge.
  3. **Compaction decision:**
     - If `secondsUntilReset ≤ 90 min`: skip `/compact`. The wait is short enough that one or two un-compacted hops won't burn meaningful quota, and compaction itself costs tokens we want to save.
     - If `secondsUntilReset > 90 min`: run `/compact` *first*. Otherwise the un-compacted context idles through many 55-min hops and each tick pays full token cost for a large prompt — the compaction one-time cost amortizes.
  4. `ScheduleWakeup` with `delaySeconds = min(secondsUntilReset + 60, 3300)` (ScheduleWakeup is clamped to ≤ 3600; 3300 leaves headroom), `prompt = "/auto-engineer --iteration <N>"` (preserve the current iteration count), `reason = "auto-engineer: paused for quota reset at <ts>"`.
  5. End the turn.

When the wake fires, auto-engineer re-enters from step 1. If quota is still < 10% (e.g. because the reset was > 55 min out and we just slept one hop), step 9 will trip again and schedule another hop — the loop naturally chains until the reset actually happens.

### 10. Compact and re-enter

If iteration budget not exhausted and no stop condition tripped:

1. Run `/compact` to shrink the context before the next cycle. **Do not** use `/clear` — it wipes the iteration counter, the list of issues already tried this run, and any stop-reason history auto-engineer uses to avoid repeating itself. `/compact` summarizes instead, which is what we want.
2. Schedule the next cycle with the iteration counter incremented:
   ```
   ScheduleWakeup(
     delaySeconds=60,
     prompt="/auto-engineer --iteration <N+1>",
     reason="auto-engineer: next cycle (iteration N+1 of 8)"
   )
   ```
   The `--iteration` flag is what enforces the 8-cycle cap across `/compact` boundaries — don't omit it. Never carry `--phase`, `--pr`, or `--fix-round` into a fresh cycle; those are intra-cycle state that resets each iteration.
3. End the turn. The next wake-up re-enters this skill from step 1.

## Stopping

On any stop condition:

1. Leave the current branch and PR in place — do **not** delete or close anything.
2. If a PR exists for the current cycle, post one comment on it via `mcp__github__add_issue_comment` summarizing why auto-engineer paused and what it tried.
3. End the turn with a plain-text status to the user. **Do not** call `ScheduleWakeup`.

Stop conditions:

- No unblocked issues remain.
- 3 consecutive build/test fix attempts failed.
- `--fix-round` reached 2 and actionable findings remain (2 response cycles exhausted).
- Any check in `action_required` state (needs human approval).
- Any security / advisory finding from `github-advanced-security[bot]`.
- Merge conflict against `main` that isn't cleanly resolvable by `git pull --rebase`.
- Iteration budget of 8 reached.
- The issue was reassigned away from `dburkart` while auto-engineer held it.

## Calling file-issue from a loop

`Skill("file-issue")` replaces the current skill's execution context — calling it would
terminate this loop. Instead, spawn a subagent via `Agent()`:

```
Agent(
  description="File follow-up issue: <title>",
  subagent_type="general-purpose",
  prompt="""
Read .claude/skills/file-issue/SKILL.md and docs/agent-playbooks/prioritization.md.
Then file one GitHub issue against dburkart/vibix with:
  title: <title>
  motivation: <1-3 sentences, include "discovered while merging #<PR>">
  work items: <concrete sub-tasks>
  context: <file paths, SHAs, related issues>
Return the new issue number and URL.
"""
)
```

Key points:
- The Agent() call returns to this skill when done — the loop continues.
- Pass all context explicitly in the prompt; the subagent starts cold with no conversation
  history.
- One Agent() call per issue; do not batch multiple issues into one subagent call.

## Never

- Force-push, rebase pushed branches, or rewrite reviewed commits.
- Edit `main` directly.
- Merge without green CI.
- Delegate the PR-wait loop to the `wait-for-pr` skill — it would steal the `ScheduleWakeup` thread. Use the embedded poll loop in step 6 instead.
- Call `Skill("file-issue")` or `Skill("usage")` inline — use `Agent()` for file-issue and the probe script for usage. `Skill()` replaces the current context and terminates the loop.
- Continue past 8 iterations without a fresh user invocation.
- Auto-fix test or build logic in step 6c (fmt and clippy only; real fixes are follow-up commits).
- Close an issue manually — let the squash-merge do it via the PR body's `Closes #N`.
- Ask the user for input — **never use `AskUserQuestion` or pause for a response**. If information is missing, make the most defensible choice and continue; if a stop condition applies, stop and report but do not ask.
