## Cursor Cloud specific instructions

vibix is a bare-metal x86_64 hobby kernel in Rust. There are no web services, databases, or
containers; everything compiles to a bootable ISO and runs under QEMU.

## Shared playbooks

Read these repo-level playbooks before acting in the corresponding area:

- `docs/agent-playbooks/build-run.md` for build, ISO, and QEMU behavior
- `docs/agent-playbooks/testing.md` for host, QEMU, and smoke testing
- `docs/agent-playbooks/sdlc.md` for branch, commit, push, and PR policy
- `docs/agent-playbooks/pr-review.md` for CI readiness and review classification

## Cursor Cloud runtime notes

- In Cursor Cloud, prefer `timeout 6 cargo xtask run` or a tmux-backed session when booting the
  kernel manually; the happy path halts in `hlt_loop()` and does not exit on its own.
- The CI-style lint command to trust in Cloud is `cargo clippy -p xtask --all-targets -- -D warnings`.
  `cargo xtask lint` is broader and can include pre-existing kernel-target warnings.
- `rust-toolchain.toml` pins nightly. `rustup show` will install or select it when needed.
- `gh` is available for read-only GitHub inspection. Use Cursor-native tooling for write actions
  such as PR creation or updates.
