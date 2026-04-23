//! ext2 filesystem driver.
//!
//! RFC 0004 (`docs/RFC/0004-ext2-filesystem-driver.md`) is the normative
//! spec. This module is the umbrella for Workstream D/E.
//!
//! [`disk`] carries the on-disk layout (superblock, group descriptor,
//! inode slot, directory record) and the read-modify-write discipline
//! the rest of the driver must uphold. It is **always** compiled — the
//! on-disk types are cheap, pure-data, and have host unit tests that
//! should keep passing on every change.
//!
//! [`fs`] (gated behind the `ext2` Cargo feature, default off) carries
//! the driver proper: `Ext2Fs` (the factory), `Ext2Super` (the
//! per-mount instance), and the [`FileSystem`](crate::fs::vfs::ops::FileSystem)
//! / [`SuperOps`](crate::fs::vfs::ops::SuperOps) trait impls. The
//! feature is off by default so partially-landed Workstream D/E waves
//! can't accidentally get exercised through the boot mount path; the
//! integration tests flip it on explicitly.

#![allow(dead_code)]

pub mod disk;
pub mod symlink;

// Directory iterator (RFC 0004 §Directory operations). The per-block
// iterator and its validators are pure logic and host-testable, so the
// module is always compiled. The `lookup` / `getdents64` entry points
// that walk a whole directory live inside a `#[cfg(all(feature =
// "ext2", target_os = "none"))]` block inside `dir.rs` itself — they
// need `Ext2Super` and the buffer cache, which are gated on the same
// envelope.
pub mod dir;

// The indirect-block walker is gated on the same `any(test, target_os =
// "none")` envelope the rest of the block-backed code uses: it depends on
// [`crate::block::cache::BlockCache`], which in turn is only compiled for
// `target_os = "none"` or host unit tests. The walker itself is pure
// logic over the `BlockCache` surface — no VFS-layer dependencies — so
// it can live outside the `ext2` feature gate; the driver proper (below)
// is still the one that exercises it in production.
#[cfg(any(test, target_os = "none"))]
pub mod indirect;

// The driver proper needs the VFS layer (`FileSystem`/`SuperOps`
// traits) and the block-cache surface, both of which are gated on
// `target_os = "none"`. Host unit tests for pure logic in this module
// live in `fs.rs::tests` behind `#[cfg(test)]` inside the `fs` module,
// which is reachable either with the kernel target or with
// `--target x86_64-unknown-none` under a test binary. Either way the
// feature gate keeps accidentally-enabled tests from picking up this
// half-built surface.
#[cfg(all(feature = "ext2", target_os = "none"))]
pub mod fs;

// The inode / iget / inode cache / orphan list surface. Same feature
// gate as `fs` because it consumes `Ext2Super`; host unit tests for
// pure functions inside live under `#[cfg(test)]` and run under the
// kernel target alongside `fs`'s tests.
#[cfg(all(feature = "ext2", target_os = "none"))]
pub mod inode;

// Regular-file `FileOps::read` path (#561). Same gate as `inode` — it
// consumes `Ext2Super` + `Ext2Inode`. The `read_file_at` free function
// exported here is also the integration-test entry point so tests
// don't need to route through an `OpenFile` just to assert on a slice
// of file bytes.
#[cfg(all(feature = "ext2", target_os = "none"))]
pub mod file;

// Mount-time orphan-chain validation (#564). Same feature gate as
// `fs` / `inode`: it consumes `Ext2Super` and uses the BlockCache to
// read inode-table blocks. Host unit tests for pure helpers inside
// live behind `#[cfg(test)]`.
#[cfg(all(feature = "ext2", target_os = "none"))]
pub mod orphan;

// Block bitmap allocator (#565). Same gate as `fs` / `inode` — it
// mutates `Ext2Super::bgdt` + `Ext2Super::sb_disk` through the buffer
// cache, both of which are gated on `target_os = "none"`. The pure
// bit-manipulation and metadata-bounds helpers inside have host unit
// tests that run under `cargo test --lib`; the full `alloc_block` /
// `free_block` surface is exercised by the QEMU integration test
// `kernel/tests/ext2_block_alloc.rs`.
#[cfg(any(all(feature = "ext2", target_os = "none"), test))]
pub mod balloc;

#[cfg(all(feature = "ext2", target_os = "none"))]
pub use fs::{Ext2Fs, Ext2MountFlags, Ext2Super, SUPERBLOCK_BYTE_OFFSET};

#[cfg(all(feature = "ext2", target_os = "none"))]
pub use inode::{iget, iget_root, Ext2FileOps, Ext2Inode, Ext2InodeMeta};

#[cfg(all(feature = "ext2", target_os = "none"))]
pub use file::{read_file_at, write_file_at};

#[cfg(all(feature = "ext2", target_os = "none"))]
pub use orphan::{validate_orphan_chain, ForceRo};

#[cfg(all(feature = "ext2", target_os = "none"))]
pub use balloc::{alloc_block, free_block};

// Inode-bitmap allocator (#566). Same feature gate as `fs` / `inode`
// because it consumes `Ext2Super` and drives the buffer cache. The
// public surface is two free functions: `alloc_inode` / `free_inode`.
#[cfg(all(feature = "ext2", target_os = "none"))]
pub mod ialloc;

#[cfg(all(feature = "ext2", target_os = "none"))]
pub use ialloc::{alloc_inode, free_inode};

// Unlink / rmdir path (#569). Same feature gate as `fs` / `inode` —
// it consumes `Ext2Super` + `Ext2Inode` + the buffer cache. Pure
// helpers inside have host unit tests; the full surface is exercised
// by `kernel/tests/ext2_unlink.rs`.
#[cfg(all(feature = "ext2", target_os = "none"))]
pub mod unlink;

// `InodeOps::setattr` — truncate / chmod / chown / utimensat persisted
// through the buffer cache (#572). Same feature gate as the rest of
// the write-path modules.
#[cfg(all(feature = "ext2", target_os = "none"))]
pub mod setattr;

// Inode create/mkdir/mknod surface (#568). Same feature gate as the rest
// of the driver; the module implements RFC 0004 §Write Ordering
// (bitmap -> inode -> dirent) and exports free-function entry points the
// `InodeOps` impls on `Ext2Inode` dispatch to.
#[cfg(all(feature = "ext2", target_os = "none"))]
pub mod create;

#[cfg(all(feature = "ext2", target_os = "none"))]
pub use create::{create_dir, create_file, mknod};

// InodeOps::link + InodeOps::symlink (#570). Same feature gate — the
// module reuses create.rs's `add_link` / `write_new_inode` /
// `read_inode_slot` helpers and touches the buffer cache directly for
// slow-symlink target writes.
#[cfg(all(feature = "ext2", target_os = "none"))]
pub mod link;

#[cfg(all(feature = "ext2", target_os = "none"))]
pub use link::{link, symlink};

// Orphan-list final-close sequence (#573). Runs the four-step
// truncate → free_inode → unchain → unpin pipeline for an unlinked-
// but-closed inode. Same feature gate as the rest of the write-path
// modules; the integration test lives in `kernel/tests/ext2_orphan_finalize.rs`.
#[cfg(all(feature = "ext2", target_os = "none"))]
pub mod orphan_finalize;

#[cfg(all(feature = "ext2", target_os = "none"))]
pub use orphan_finalize::finalize as finalize_orphan;

// Rename path (#571). Same feature gate as the rest of the write-path
// modules; implements RFC 0004 §Rename ordering (link-count-first) and
// §Cross-directory loop check.
#[cfg(all(feature = "ext2", target_os = "none"))]
pub mod rename;
