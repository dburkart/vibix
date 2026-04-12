---
name: wait-for-pr
description: After opening a PR or pushing a fix, wait for all CI checks AND review-bot comments to report, then surface a single unified summary. Use immediately after `gh pr create` or any push that re-triggers checks on a PR.
---

# wait-for-pr

Right after a PR is opened or a new commit is pushed to its branch, don't stop at the first `gh pr checks` poll — checks take minutes and review bots (CodeRabbit, Greptile, GHAS) post later still. This skill runs the full wait loop so the user sees one consolidated report instead of prompting "are we there yet?" repeatedly.

## When to invoke

- Immediately after `gh pr create` / `mcp__github__create_pull_request` returns a PR URL.
- After pushing a follow-up commit to a PR branch (re-enter the loop to confirm green).
- When the user says "wait for CI," "check the PR," or similar.

## Identifying the PR

If the PR number isn't already known from the preceding tool call:

```sh
gh pr list --head "$(git branch --show-current)" --json number,url --jq '.[0]'
```

Record the number and URL; reuse them for every poll tick.

## What "done" means

The PR isn't ready for a summary until **all** are true:

1. Every GitHub Actions check is in a terminal state: `success`, `failure`, `skipped`, `cancelled`, `neutral`, `timed_out`, or `stale`. Nothing `in_progress`, `queued`, or `pending`.
2. No check is sitting in `action_required` waiting on manual approval (flag it and stop — the user needs to act).
3. At least one review-bot comment / review exists, **or** 30 minutes have elapsed since the PR opened (bots may not be wired up on this repo; don't block forever).

Known review-bot author logins:

- `coderabbitai` / `coderabbitai[bot]`
- `greptile-apps` / `greptile-bot`
- `github-advanced-security[bot]`

## Poll cadence

Use `ScheduleWakeup` between ticks. Tune `delaySeconds` to stay friendly to the 5-minute prompt-cache TTL:

| Elapsed since PR opened | delaySeconds |
|---|---|
| 0–10 min | 120 |
| 10–30 min | 180 (still under the 270 s cache window) |
| 30 min+ (waiting only on slow bots) | 1200 |

Never pick 300 s — it's the worst of both worlds (cache miss with no payoff). Under 10 minutes, stay ≤ 270 s.

## Each poll tick

1. Check CI state:
   ```sh
   gh pr checks <PR> --json name,state,bucket,link
   ```
   or `mcp__github__get_pull_request_status`.

2. Count review-bot activity:
   ```sh
   gh api "repos/{owner}/{repo}/issues/<PR>/comments" \
     --jq '[.[] | select(.user.login | test("coderabbitai|greptile|github-advanced-security"))] | length'
   ```
   Also fetch formal reviews via `mcp__github__get_pull_request_reviews`.

3. Evaluate the "done" criteria. If not done, call `ScheduleWakeup` with the cadence above and the skill prompt `/wait-for-pr`, then stop. The next wake re-enters this skill.

4. If done, proceed to **Auto-fix** (if anything failed) or **Summarize**.

## Auto-fix on failure

Before reporting a failure to the user, check whether it's trivially fixable:

| Failed check pattern | Fix |
|---|---|
| `fmt` / `rustfmt` / `format` | `cargo fmt --all` |
| `clippy` / `lint` | `cargo clippy --fix --allow-dirty --allow-staged` then `cargo fmt --all` |

If a fix applies:

1. Run the fix.
2. Commit with a clear subject, e.g. `fix: apply rustfmt` / `fix: address clippy lints`, plus the standard `Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>` trailer.
3. `git push`.
4. Re-enter this skill from the top to wait on the fresh run.

**Only auto-fix once per check.** If the same check fails again after a fix commit, stop and report — a second auto-fix loop means the fix didn't work and a human needs eyes on it.

Never auto-fix:

- Test failures — too risky to guess a fix.
- Build failures — need human diagnosis.
- Security checks / advisory findings.

## Summarize

When everything has reported, output one structured report:

```
## PR #<N> — <title>

### CI
- ✓ <check-name>        [success]
- ✗ <check-name>        [failure] — <short conclusion if available>
- ⊘ <check-name>        [skipped]

Overall: <ALL PASSING | N check(s) failed>

### Review findings

**Actionable bugs** (fix before merge):
- <file:line> — <description>

**In-scope nits** (cheap to fix):
- <file:line> — <description>

**Out-of-scope nits** (defer):
- <description> → reply "deferred to #<issue> / future work"

**No findings** (if the review bots posted nothing actionable)
```

Classification matches the `sdlc` skill:

- **Actionable bugs**: correctness issues, panics, unsoundness, broken invariants.
- **In-scope nits**: style / naming / minor issues on code this PR actually changed.
- **Out-of-scope nits**: suggestions about untouched code, or architectural changes that would balloon scope.

If the 30-min bot timeout hit with no comment, note it explicitly:

> Review bots did not post within 30 min — may not be configured on this repo.

## Never

- Merge the PR. Merging is always explicit per the `sdlc` skill.
- Auto-fix anything beyond fmt / clippy.
- Loop more than once on the same auto-fix.
- Block indefinitely waiting on bots — apply the 30-min timeout and move on.
