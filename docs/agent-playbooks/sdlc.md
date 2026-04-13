# SDLC playbook

This playbook captures repo-level delivery policy that applies across agent runtimes.

## Default flow

All non-trivial changes move through the same flow:

`branch -> commit -> push -> PR -> review -> merge`

`main` is a review-only integration branch. Do not land changes there directly.

## Picking work

When work is open-ended and issue-driven, prefer unassigned issues so parallel sessions do not
collide:

```sh
gh issue list --search 'no:assignee' --state open
```

If the user names a specific issue, work that issue regardless of assignee.

## Starting work

Start each cohesive change on its own topic branch from `main`.

Suggested naming:

- Milestones: `m<N>-<slug>`
- Smaller tasks: `<verb>-<slug>`

If the runtime supports issue assignment and the branch maps to a tracked issue, assign it before
or during the work so concurrent sessions do not race on the same ticket.

## While working

- Keep commits coherent. Avoid both mega-commits and noisy micro-commits.
- Use short imperative subjects and a body that explains why the change exists.
- Run the checks that match the scope before pushing:
  - Kernel or behavior changes: `cargo xtask test` and `cargo xtask smoke`
  - Docs/process/skill-only changes: at minimum run a targeted validation step appropriate for the
    runtime; use `cargo xtask build` when you want a low-cost repo sanity check
- Do not push a knowingly red branch.

## Capturing follow-up work

If a useful follow-up comes up mid-task but is out of scope for the current branch, capture it in
the repo's issue tracker when the runtime has write access. Include enough context that someone can
act on it later without the current chat transcript.

If the runtime is read-only for issues, record the follow-up in the PR summary or final handoff.

## Opening the PR

When the branch is ready for review:

1. Push the branch.
2. Open a PR against `main`.
3. Keep the title short; put detail in the body.
4. Include a concise summary and the exact tests or checks you actually ran.

Suggested PR body structure:

```markdown
## Summary
- <what changed>
- <why it changed>

## Test plan
- [x] <exact command and result>
```

## Responding to review

- Treat correctness issues and broken invariants as must-fix items.
- Fixes should normally be follow-up commits on the same branch.
- Distinguish cheap in-scope nits from out-of-scope suggestions that should be deferred.

## After merge

- Delete the local topic branch when it is no longer needed.
- Pull `main` before starting the next cohesive change.

## Never

- Commit directly to `main`.
- Force-push a shared branch without explicit approval.
- Rewrite commits that have already been reviewed unless there is a strong, explicit reason.
