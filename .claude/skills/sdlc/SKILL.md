---
name: sdlc
description: The vibix software-delivery workflow — how changes move from idea to merged on main. Use when starting a milestone/task, committing, or opening/updating a PR.
---

# vibix SDLC

All non-trivial changes move through the same flow: **branch → commit → push → PR → review → merge**. `main` is a review-only integration branch; nothing lands there directly.

## Starting work

Before writing any code for a new milestone or task:

```sh
git checkout main && git pull
git checkout -b <topic-branch>
```

Branch naming:
- Milestones: `m<N>-<slug>` (e.g. `m3-interrupts`, `m4-paging`).
- Smaller tasks: `<verb>-<slug>` (e.g. `fix-keyboard-race`, `refactor-frame-allocator`).

One branch per logically cohesive piece of work. Don't stack unrelated changes on the same branch.

## While working

- Commit in coherent chunks — don't wait until the whole milestone is green to make the first commit, but don't micro-commit either. Aim for commits that would make sense to read individually during review.
- Each commit message: short imperative subject (<70 chars), blank line, body that explains *why*. Always include the `Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>` trailer.
- Run `cargo xtask test` + `cargo xtask smoke` before pushing (see the `test` and `build` skills). Don't push red branches.

## Opening the PR

When the branch is ready for review:

1. `git push -u origin <branch>` (first push) or `git push` (subsequent).
2. Open a PR via the GitHub MCP (`mcp__github__create_pull_request`) against `main`. Body template:

```markdown
## Summary
<2-5 bullets: what the change does and why, grouped by subsystem>

<short note on what's explicitly out of scope, if relevant>

## Test plan
- [x] <tests actually run, with results>
- [ ] <manual checks the user should do before merging>

🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

3. Keep the title short (<70 chars); details belong in the body.
4. If the MCP can't reach auth, fall back to the GitHub compare URL and let the user paste the prepared body manually — never skip the review step by merging locally.

## Responding to review

- CodeRabbit usually posts automatically. Fetch its findings with `mcp__github__get_pull_request_reviews` / `get_pull_request_comments` and classify: **actionable bugs** (fix), **nitpicks in scope** (fix if cheap), **nitpicks out of scope** (reply and defer).
- Fixes are follow-up commits on the same branch, not amend + force-push — preserves review history.
- Don't merge your own PRs; the user reviews and merges. If the user says "merge it," use `mcp__github__merge_pull_request`.

## After merge

- Delete the topic branch locally (`git branch -d <branch>`) and let GitHub delete the remote.
- Pull `main` before starting the next piece of work.

## Never

- Commit directly to `main` — not even for "trivial" changes. Every change goes through a PR.
- `git push --force` on a shared branch without explicit user approval.
- Merge a PR on the user's behalf unless asked.
- Squash or rewrite commits that have already been pushed and reviewed.
