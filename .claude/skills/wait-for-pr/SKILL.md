---
name: wait-for-pr
description: After opening a PR or pushing a fix, wait for all CI checks AND review-bot comments to report, then surface a single unified summary. Use immediately after `gh pr create` or any push that re-triggers checks on a PR.
---

# wait-for-pr

Read `docs/agent-playbooks/pr-review.md` first for repo-level CI readiness and review-classification
rules.

This skill keeps only the Claude-specific wait loop and automation needed to turn those shared rules
into a single consolidated PR-status report.

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

## Shared-vs-Claude split

- The shared playbook defines what CI-ready means and how to classify review findings.
- This wrapper defines the Claude-only polling cadence, wake-up loop, and optional auto-fix behavior.
- If the repo's review policy changes, update the shared playbook first and keep this file focused on
  runtime mechanics.

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

| Failed check pattern | Fix | Canonical commit subject |
|---|---|---|
| `fmt` / `rustfmt` / `format` | `cargo fmt --all` | `fix: apply rustfmt` |
| `clippy` / `lint` | `cargo clippy --fix --allow-dirty --allow-staged` then `cargo fmt --all` | `fix: address clippy lints` |

### Detecting prior auto-fix attempts

Before running a fix, verify this branch hasn't already received one for the same check. The canonical commit subjects above are the ground-truth sentinel — a `git log` grep on the PR branch is exact and needs no external state.

Derive the base ref from the PR (don't assume `main` — PRs can target release or hotfix branches) and make sure the remote ref is current before running the check:

```sh
BASE_REF="$(gh pr view <PR> --json baseRefName --jq .baseRefName)"
git fetch origin "$BASE_REF" --quiet 2>/dev/null || true

# fmt:
git log "origin/${BASE_REF}..HEAD" --format='%s' | grep -Fxq 'fix: apply rustfmt'
# clippy:
git log "origin/${BASE_REF}..HEAD" --format='%s' | grep -Fxq 'fix: address clippy lints'
```

If the matching subject is **already present** and the same check just failed again:

- Do **not** apply a second auto-fix — the first one didn't resolve it.
- Extract the sentinel commit's short SHA for the Summarize report:
  ```sh
  git log "origin/${BASE_REF}..HEAD" --format='%h %s' \
    | grep -F 'fix: apply rustfmt' | head -1 | cut -d' ' -f1
  ```
- Skip straight to Summarize, flagging the check as `failure — auto-fix already applied in <short-sha>, did not resolve`.

If the grep finds nothing, proceed with the fix. The commit you create with that exact subject becomes the sentinel for any subsequent re-entry of this skill.

**Commit subjects are load-bearing.** Keep them byte-for-byte identical to the table above. `grep -Fxq` is whole-line and fixed-string on purpose — it prevents false positives from commits that merely mention "rustfmt" in their body or subject.

If `git fetch` fails (offline, auth issue) the `|| true` lets the check fall through to whatever state `origin/${BASE_REF}` was last known at. That's the correct degradation: false-negative "no prior fix" is the same state we'd be in on the first entry, so at worst we run one redundant `cargo fmt` — safer than falsely short-circuiting.

### Applying the fix

1. Run the fix command from the table.
2. Commit with the canonical subject from the table, plus the standard `Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>` trailer.
3. `git push`.
4. Re-enter this skill from the top to wait on the fresh run.

Never auto-fix:

- Test failures — too risky to guess a fix.
- Build failures — need human diagnosis.
- Security checks / advisory findings.

## Summarize

When everything has reported, output one structured report that follows the buckets from
`docs/agent-playbooks/pr-review.md`:

- PR number and title
- CI results grouped by pass/fail/skipped state
- Review findings grouped into actionable bugs, in-scope nits, and out-of-scope nits
- Any explicit follow-up items that were deferred

If the 30-min bot timeout hit with no comment, note it explicitly:

> Review bots did not post within 30 min — may not be configured on this repo.

## Never

- Merge the PR. Merging is always explicit per the `sdlc` skill.
- Auto-fix anything beyond fmt / clippy.
- Loop more than once on the same auto-fix.
- Block indefinitely waiting on bots — apply the 30-min timeout and move on.
