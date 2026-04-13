---
name: build
description: Build the vibix kernel, assemble a bootable ISO, or run it under QEMU. Use when the user asks to build, compile, make an ISO, boot, or run the kernel.
---

# Building and running vibix

Read `docs/agent-playbooks/build-run.md` first for the repo-level build, ISO, and QEMU facts.

## When to use this skill

Use this skill when the task involves:

- compiling the kernel
- producing a bootable ISO
- booting the kernel under QEMU
- cleaning build artifacts

## Claude-specific notes

- Follow the shared playbook's `cargo xtask` rules exactly; do not improvise raw kernel build commands.
- If the task also involves validation, pair this skill with `test` so the build/run commands and the
  test commands come from the shared playbooks instead of being duplicated here.
- If you are running `cargo xtask run` in a non-interactive cloud environment, prefer a bounded
  command or a persistent session so the happy-path kernel halt does not strand the turn.
