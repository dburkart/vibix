# vibix-ext2-fuzz

Host-side fuzz harness for the vibix ext2 driver.

Tracks issue [#677][issue-677] and pairs with [#389][issue-389].

[issue-677]: https://github.com/dburkart/vibix/issues/677
[issue-389]: https://github.com/dburkart/vibix/issues/389

## What this fuzzes

The `fuzz_one` driver in `src/lib.rs` walks an attacker-controlled
byte slice as if it were a virtual block device and replays the ext2
mount + read-root path:

1. Decode the on-disk superblock (`Ext2SuperBlock::decode`); validate
   magic, block size, group count, feature bits.
2. Decode the BGDT and validate every per-group metadata pointer.
3. Decode the root inode (ino 2); walk its direct blocks and the
   single-indirect / double-indirect block pointers.
4. Iterate each directory data block with `dir::DirEntryIter`,
   checking `rec_len` / `name_len` / `file_type` / reserved-ino rules.
5. Pretend-read every regular file entry by walking its block
   pointers, bounded by hard iteration caps.

Failures **must** drop to a clean `FuzzExit::Bad*` reject. The driver
is contract-bound never to panic, OOB-read, or hang on any input.

The on-disk decoders (`fs::ext2::disk`) and the per-block dir iterator
(`fs::ext2::dir`) are re-included verbatim from the kernel source via
`#[path = ...]` so the harness drifts together with the production
code on every change.

## Workspace layout

`kernel/fuzz` is **excluded from the parent workspace** and declares
its own empty `[workspace]`. The kernel target builds with
`-Z build-std` for `x86_64-unknown-none`; the fuzz harness builds for
the host (`x86_64-unknown-linux-gnu`) with the standard sysroot, and
mixing the two would force every host build to also resolve the
no-`std` graph. Same pattern as `tests/pjdfstest`.

## Running the smoke runner (CI lane)

The CI-friendly path is a plain `cargo run` binary that walks the
corpus + a deterministic mutation budget. **No `cargo-fuzz` install
needed**:

```sh
cargo xtask fuzz ext2
```

That eventually invokes:

```sh
cargo run --manifest-path kernel/fuzz/Cargo.toml --bin ext2_fuzz_runner --release -- \
    kernel/fuzz/corpus/ext2_mount --iters=2000
```

The runner:

1. Reads every file under the corpus directory and runs `fuzz_one`
   on it verbatim. Reports the per-seed verdict.
2. Synthesizes the malformed-image scenarios called out in the issue
   body (zeroed superblock, bad magic, inflated `s_blocks_count`,
   BGDT free-count overflow, dir record `rec_len` overrun, indirect
   self-loop, indirect OOB, bad `s_log_block_size`) and runs each
   through the harness too.
3. Runs N (default 1000, CI uses 2000) byte-flip / byte-store /
   4-byte-splat mutations of each on-disk seed.

Exit code is 0 on success, non-zero only if `fuzz_one` panicked
(which is itself a finding).

## Running cargo-fuzz (long-form)

For a real coverage-guided fuzzing campaign, use the libFuzzer
harness in `fuzz_targets/`:

```sh
rustup install nightly                   # already pinned via rust-toolchain.toml
cargo install cargo-fuzz                 # one-time
cd kernel/fuzz
cargo +nightly fuzz run ext2_mount       # ^C to stop
```

cargo-fuzz drops new-coverage seeds into `corpus/ext2_mount/` and
crash repros into `artifacts/`; commit any seed worth keeping, file
the crash repros as bugs.

## Seed corpus

`corpus/ext2_mount/golden.img` is the same 64 KiB `mkfs.ext2` image
shipped under `kernel/src/fs/ext2/fixtures/golden.img` (issue #558's
mount-test fixture). It's the only on-disk seed; the malformed
scenarios are synthesized at runtime by the smoke runner. Cargo-fuzz
will discover and persist additional seeds into this directory if you
run a long-form campaign.
