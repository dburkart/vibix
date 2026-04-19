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

#[cfg(all(feature = "ext2", target_os = "none"))]
pub use fs::{Ext2Fs, Ext2MountFlags, Ext2Super, SUPERBLOCK_BYTE_OFFSET};

#[cfg(all(feature = "ext2", target_os = "none"))]
pub use inode::{iget, iget_root, Ext2FileOps, Ext2Inode, Ext2InodeMeta};

#[cfg(all(feature = "ext2", target_os = "none"))]
pub use file::read_file_at;

#[cfg(all(feature = "ext2", target_os = "none"))]
pub use orphan::{validate_orphan_chain, ForceRo};
