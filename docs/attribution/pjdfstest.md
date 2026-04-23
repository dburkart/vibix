# pjdfstest — vendored attribution

`tests/pjdfstest/` contains a vendored copy of the Rust rewrite of
[pjdfstest](https://github.com/saidsay-so/pjdfstest), a POSIX filesystem
conformance suite originally written in C by Paweł Jakub Dawidek (2006–2012)
and rewritten in Rust during Google Summer of Code 2022 by Sayafdine Said.

## Upstream

- Repository: <https://github.com/saidsay-so/pjdfstest>
- Vendored commit: `a53a2103ff86a1cf1643f3d075e7478725cab879` ("build: update deps (#160)")
- Vendored path: only the `rust/` subtree was imported (the top-level
  autotools-era C harness is not used).

## License

The upstream suite is distributed under the 2-clause BSD license
(see `tests/pjdfstest/LICENSE`, copied verbatim from upstream `COPYING`).
The vendored tree preserves that notice; downstream vibix contributions under
`tests/pjdfstest/` are offered under the same 2-clause BSD terms so the
directory remains license-consistent with upstream.

## Scope of local modifications

This commit strips test ops whose syscalls vibix does not implement, so the
suite compiles cleanly on the Linux host even though the vibix userspace
target is narrower than FreeBSD/Linux.

Removed test modules (see `tests/pjdfstest/src/tests/mod.rs` and
`tests/pjdfstest/src/tests/errors.rs`):

| Removed                                | Reason                                                |
| -------------------------------------- | ----------------------------------------------------- |
| `src/tests/chflags.rs`                 | BSD-only `chflags(2)`; vibix has no file-flag syscall |
| `src/tests/mkfifo.rs`                  | vibix has no FIFO support                             |
| `src/tests/mknod.rs`                   | vibix has no userspace device-node creation          |
| `src/tests/nfsv4acl/`                  | vibix has no ACL support                              |
| `src/tests/posix_fallocate.rs`         | vibix has no `fallocate` / `posix_fallocate`          |
| `src/tests/errors/etxtbsy.rs`          | vibix does not enforce ETXTBSY on running binaries    |

Call-sites that previously imported the stripped helpers
(`src/tests/open.rs`, `src/tests/truncate.rs`) are commented out with a
pointer back to this file. BSD-gated code paths (`chflags`, `lchflags`,
`nfsv4acl` in `src/context.rs` / `src/utils.rs`) were left in place because
they are already `cfg`-gated off on Linux and will be needed if we ever
re-port the suite to a BSD-flavored vibix target.

The upstream workspace (`tests/pjdfstest/Cargo.toml`) is intentionally kept
out of the top-level Rust workspace via `exclude = ["tests/pjdfstest"]` in the
repo-root `Cargo.toml`. Wiring into xtask and CI is tracked by #581 and #582.
