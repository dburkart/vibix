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

#[cfg(all(feature = "ext2", target_os = "none"))]
pub use fs::{Ext2Fs, Ext2MountFlags, Ext2Super, SUPERBLOCK_BYTE_OFFSET};
