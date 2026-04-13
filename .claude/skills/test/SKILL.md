---
name: test
description: Run vibix tests — host unit tests, in-kernel QEMU integration tests, or the end-to-end serial-marker smoke check. Use when the user asks to test, verify, check, or regression-test the kernel.
---

# Testing vibix

Read `docs/agent-playbooks/testing.md` first for the repo-level test model, commands, and gotchas.

## When to use this skill

Use this skill when the task involves:

- validating kernel or boot behavior
- adding or updating host unit tests
- adding or updating QEMU integration tests
- running the smoke lane after behavior changes

## Claude-specific notes

- Choose the narrowest high-signal checks that match the change, then escalate to the full `test`
  and `smoke` flow when the risk warrants it.
- Keep the shared playbook as the source of truth for how the three test layers work; this wrapper
  only decides when to apply them.
- If a task also changes build or run behavior, read `docs/agent-playbooks/build-run.md` before
  invoking test commands so the QEMU and `xtask` assumptions stay aligned.
