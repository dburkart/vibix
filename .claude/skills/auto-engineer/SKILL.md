---
name: auto-engineer
description: Autonomously drive vibix work end-to-end — pick an unblocked issue, plan it, implement, push a PR, resolve CI and review-bot feedback, merge when green, then repeat. Use when the user says "auto-engineer", "auto-pilot", "go run the loop", or invokes `/auto-engineer`.
---

# auto-engineer

Closes the full SDLC loop without prompting the user between steps. Each invocation runs **one cycle** (pick → plan → implement → PR → wait → merge), then reschedules itself via `ScheduleWakeup` with prompt `/auto-engineer` for the next cycle. Stops cleanly when it runs out of work or hits something it can't safely resolve.

This skill is a deliberate override of the project's default "don't merge your own PRs" rule — merging is the whole point of closing the loop. It only applies while auto-engineer is driving.

## When to invoke

- User says "run the loop", "auto-engineer", "auto-pilot the next issue", or similar.
- User types `/auto-engineer` (optionally with `#NN` to scope to a single issue for one cycle, no reschedule).
- This skill re-invokes itself at the end of each successful cycle via `ScheduleWakeup`.

## Iteration budget

Count iterations across a single user-initiated run (stored implicitly via the repeated wake-up chain). **Soft cap: 8 iterations.** After the 8th merged PR, stop and wait for the user to restart. Prevents runaway loops.

## Cycle

### 1. Pick an unblocked issue

```sh
gh issue list --search 'no:assignee' --state open \
  --json number,title,labels,body,assignees
```

Filter out:
- Issues labeled `blocked`, `needs-discussion`, `question`, `wontfix`.
- Issues whose body references an unresolved dependency (e.g. "blocked on #NN" where #NN is still open).

Sort preference:
1. Lowest-numbered issue labeled `enhancement` or `milestone-*`.
2. Otherwise lowest-numbered `bug`.
3. Otherwise lowest-numbered remaining issue.

If the candidate list is empty → **stop** (see Stopping below) with message *"no unblocked issues — auto-engineer idle."*

Assign and branch per `sdlc`:

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

Run in order, per the `build` and `test` skills:

```sh
cargo xtask build
cargo xtask test
cargo xtask smoke
```

On failure: diagnose and fix in place. **Maximum 3 fix attempts per cycle.** If the 3rd attempt still fails → **stop** with a summary of the failure and what was tried.

### 5. Commit and open PR

Per `sdlc`:

- Coherent commits (not a single mega-commit, not micro-commits). Each with the standard `Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>` trailer.
- `git push -u origin <branch>`.
- Open the PR via `mcp__github__create_pull_request` with the standard Summary + Test plan body. **No "generated with" footer.**
- Record the PR number and URL for the rest of the cycle.

### 6. Wait for PR, respond to feedback

Invoke the `wait-for-pr` skill. It handles:
- CI polling with cache-friendly `ScheduleWakeup` cadence.
- Review-bot timing (30-min bot window).
- Auto-fix for fmt / clippy failures.

When `wait-for-pr` returns a summary:

- **All green, no actionable findings** → proceed to merge (step 7).
- **Actionable bugs or non-fmt/clippy CI failures** → auto-engineer handles them:
  1. Read each finding.
  2. Apply fixes as follow-up commits (never amend, never force-push).
  3. `git push`.
  4. Re-enter `wait-for-pr`.
- **Cycle counter: max 2 review-response passes.** If the 3rd `wait-for-pr` return still has actionable findings → **stop** and let the user take over.

For out-of-scope nits: reply on the PR with "deferred to #<issue-or-future-work>" via `mcp__github__add_issue_comment`, open the follow-up issue if one doesn't exist, then proceed.

### 7. Merge

Only merge when **all** are true:
- Every CI check is `success` or `skipped` (none `failure`, `action_required`, `timed_out`, `pending`).
- No unresolved actionable review findings.
- Either ≥1 review bot posted and every actionable finding is addressed, **or** 30 min elapsed since PR open with nothing actionable.

Determine merge method from recent history:

```sh
gh pr list --state merged --limit 5 --json number,mergeCommit,title
```

Match the dominant style (squash is the current default — confirm before each merge). Then:

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

For each distinct follow-up, before filing, **dedupe against existing issues**:

```sh
gh issue list --state open --search '<keywords>' --json number,title
```

If no match, file via `mcp__github__create_issue` per the `sdlc` "capture out-of-scope ideas" rule:
- Specific title.
- Body explaining *what* and *why* with enough context to act on cold in a week.
- Reference the merged PR (`discovered while merging #<PR>`).
- Labels that fit (`bug`, `enhancement`, `tech-debt`, `milestone-N`).

If nothing worth filing, skip silently. **Do not file speculative or "nice-to-have" issues** — only things with concrete motivation. Over-filing clutters the backlog and degrades the `no:assignee` candidate set that step 1 depends on.

### 9. Check session quota

Before compacting and kicking off the next cycle, run `/usage` and parse the session-quota remaining percentage.

- **≥ 10% remaining** → proceed to step 10.
- **< 10% remaining** → don't start a new cycle; the next one could tip over mid-PR and leave an orphaned branch. Instead:
  1. Read the quota-reset timestamp from `/usage` output.
  2. Compute `secondsUntilReset = reset_ts - now`. Add a 60 s buffer so the wake-up lands *after* the reset, not on its edge.
  3. `ScheduleWakeup` with `delaySeconds = min(secondsUntilReset + 60, 3300)` (ScheduleWakeup is clamped to ≤ 3600; 3300 leaves headroom), `prompt = "/auto-engineer"`, `reason = "auto-engineer: paused for quota reset at <ts>"`.
  4. End the turn.

When the wake fires, auto-engineer re-enters from step 1. If quota is still < 10% (e.g. because the reset was > 55 min out and we just slept one hop), step 9 will trip again and schedule another hop — the loop naturally chains until the reset actually happens.

**Do not** compact before a quota wait — compaction itself costs tokens, and we want to preserve budget for the next real cycle.

### 10. Compact and re-enter

If iteration budget not exhausted and no stop condition tripped:

1. Run `/compact` to shrink the context before the next cycle. **Do not** use `/clear` — it wipes the iteration counter, the list of issues already tried this run, and any stop-reason history auto-engineer uses to avoid repeating itself. `/compact` summarizes instead, which is what we want.
2. Schedule the next cycle:
   ```
   ScheduleWakeup(
     delaySeconds=60,
     prompt="/auto-engineer",
     reason="auto-engineer: next cycle (iteration N+1 of 8)"
   )
   ```
3. End the turn. The next wake-up re-enters this skill from step 1.

## Stopping

On any stop condition:

1. Leave the current branch and PR in place — do **not** delete or close anything.
2. If a PR exists for the current cycle, post one comment on it via `mcp__github__add_issue_comment` summarizing why auto-engineer paused and what it tried.
3. End the turn with a plain-text status to the user. **Do not** call `ScheduleWakeup`.

Stop conditions:

- No unblocked issues remain.
- 3 consecutive build/test fix attempts failed.
- 3 `wait-for-pr` returns still showed actionable findings (2 response cycles exhausted).
- Any check in `action_required` state (needs human approval).
- Any security / advisory finding from `github-advanced-security[bot]`.
- Merge conflict against `main` that isn't cleanly resolvable by `git pull --rebase`.
- Iteration budget of 8 reached.
- The issue was reassigned away from `dburkart` while auto-engineer held it.

## Never

- Force-push, rebase pushed branches, or rewrite reviewed commits.
- Edit `main` directly.
- Merge without green CI.
- Skip `wait-for-pr` — even when CI "looks fast", review bots post on their own schedule.
- Continue past 8 iterations without a fresh user invocation.
- Auto-fix test or build logic inside `wait-for-pr`'s auto-fix slot (fmt and clippy only there; real fixes belong in step 6's response pass).
- Close an issue manually — let the squash-merge do it via the PR body's `Closes #N`.
