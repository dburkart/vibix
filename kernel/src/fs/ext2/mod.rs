//! ext2 filesystem driver.
//!
//! RFC 0004 (`docs/RFC/0004-ext2-filesystem-driver.md`) is the normative
//! spec. This module is the umbrella for Workstream D/E; today it only
//! carries the on-disk type submodule. Trait impls (`FileSystem`,
//! `SuperOps`, `InodeOps`, `FileOps`), the mount path, the indirect-
//! block walker, and the allocator land in sibling modules per the
//! Workstream D/E task list.
//!
//! See [`disk`] for the on-disk layout (superblock, group descriptor,
//! inode slot, directory record) and the read-modify-write discipline
//! the rest of the driver must uphold.

#![allow(dead_code)]

pub mod disk;
