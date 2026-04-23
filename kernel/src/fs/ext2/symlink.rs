//! ext2 symlink read path — fast (inline) and slow (indirect walker).
//!
//! RFC 0004 (`docs/RFC/0004-ext2-filesystem-driver.md`), Workstream D
//! wave 2, issue #563. ext2 stores the target of a symbolic link in one
//! of two places depending on length:
//!
//! * **Fast symlink** (target ≤ 60 bytes): the NUL-less target bytes
//!   live inline in the 15-entry `i_block[]` array of the inode itself
//!   (15 × `u32` == 60 bytes). `i_blocks` (512-byte sector count) is
//!   zero — no data block is allocated.
//! * **Slow symlink** (target > 60 bytes, up to `PATH_MAX == 4095` by
//!   RFC §Kernel-Userspace Interface): the target lives in the inode's
//!   data blocks, reached through the normal direct/indirect walker.
//!
//! The fast-symlink gate is all three of `S_ISLNK(i_mode) && i_blocks
//! == 0 && i_size <= 60` — see RFC 0004 §Security "Fast-symlink path
//! confusion". Missing any leg lets a crafted image leak up to 60 bytes
//! of inode-table memory to userspace through `readlink`. The copy is
//! always clamped to `min(i_size, 60, user_buflen)` on the fast path
//! and `min(i_size, user_buflen)` on the slow path (with `i_size`
//! itself bounded by `EXT2_SYMLINK_READ_MAX`).
//!
//! `readlink(2)` is **not** NUL-terminated — POSIX mandates that
//! callers use the return value as the byte count. This module returns
//! the byte count; callers (`InodeOps::readlink`) must never append a
//! trailing zero.
//!
//! # Slow-symlink read path
//!
//! Targets > 60 bytes live in the inode's data blocks. The reader
//! walks the block chain through [`super::indirect::resolve_block`] —
//! the same routine that backs regular-file reads (see
//! [`super::file::read_file_at`]) — and concatenates each block into
//! the caller buffer. `PATH_MAX` (4096 including the implicit NUL,
//! i.e. `EXT2_SYMLINK_TARGET_MAX == 4095` bytes) bounds the walk, so a
//! legal symlink never chases past single-indirect even on a 1 KiB-
//! block filesystem (4 × 1 KiB direct + 1 KiB indirect would already
//! exceed the cap). An `i_size` above the cap surfaces as
//! `ENAMETOOLONG` — image corruption rather than an honest POSIX
//! symlink. Sparse holes inside a symlink body are structurally
//! impossible; if [`resolve_block`] surfaces `Ok(None)` the image is
//! treated as corrupt and the read returns `EIO`.

#![allow(dead_code)]

use super::disk::{Ext2Inode, EXT2_N_BLOCKS};

/// Upper bound on a legal symlink target's `i_size`. POSIX caps a path
/// at 4096 bytes including the trailing NUL; the on-disk symlink stores
/// the target **without** a NUL, so the largest honest `i_size` is
/// 4095. An `i_size` above this is image corruption — either a hostile
/// image trying to spill the reader past a single allocated block, or
/// a filesystem writer that didn't clamp. Matches
/// [`super::link::EXT2_SYMLINK_TARGET_MAX`] on the write side.
pub const EXT2_SYMLINK_READ_MAX: u32 = 4095;

/// ext2 `i_mode` file-type mask. Matches the POSIX `S_IFMT` bitmask
/// (top 4 bits of the 16-bit mode word).
pub const EXT2_S_IFMT: u16 = 0o170000;

/// ext2 `i_mode` file-type value for a symbolic link. Same bit
/// pattern as POSIX `S_IFLNK` (`0o120000`).
pub const EXT2_S_IFLNK: u16 = 0o120000;

/// Maximum bytes of a fast (inline) symlink target. 15 pointers × 4
/// bytes each = 60 bytes. The target does **not** include a trailing
/// NUL — the length is carried by `i_size`.
pub const EXT2_FAST_SYMLINK_MAX: u32 = (EXT2_N_BLOCKS * 4) as u32;

/// `true` iff `inode` is a symbolic link per the `S_IFMT` bits of its
/// mode.
#[inline]
pub fn is_symlink(inode: &Ext2Inode) -> bool {
    (inode.i_mode & EXT2_S_IFMT) == EXT2_S_IFLNK
}

/// Fast-symlink gate per RFC 0004 §Security: all three legs required.
///
/// `i_blocks` is in 512-byte sector units (RFC 0004 §On-disk types);
/// `i_blocks == 0` means "no data block allocated." A symlink with
/// `i_size <= 60` **and** zero blocks definitionally has its target
/// inline in `i_block[]`. Relying on any two of the three legs lets a
/// crafted image point non-symlink bytes at the inline path or leak up
/// to 60 bytes of adjacent inode memory when `i_size` is huge.
#[inline]
pub fn is_fast_symlink(inode: &Ext2Inode) -> bool {
    is_symlink(inode) && inode.i_blocks == 0 && inode.i_size <= EXT2_FAST_SYMLINK_MAX
}

/// Reconstitute the 60-byte inline symlink target region from the
/// parsed `i_block[]` array.
///
/// On disk the 15 block pointers occupy a 60-byte little-endian region
/// starting at inode-slot offset 40. A fast symlink stores the target
/// as the first `i_size` bytes of that region — Linux reads them as
/// `(char *)inode->i_block`, which on a little-endian host is exactly
/// the concatenation of each `u32`'s LE representation. We reconstruct
/// those bytes here rather than re-reading the raw slot: `Ext2Inode`
/// has already parsed it, and the round-trip is byte-exact (the
/// `encode_to_slot` path in `disk.rs` writes the same bytes back).
#[inline]
fn inline_bytes(inode: &Ext2Inode) -> [u8; 60] {
    let mut out = [0u8; 60];
    for (i, &w) in inode.i_block.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// Copy the fast-symlink target into `buf`, returning the number of
/// bytes written.
///
/// The copy length is `min(i_size, 60, buf.len())` — the three-way
/// clamp from RFC 0004 §Security. Does **not** NUL-terminate. Returns
/// `Err(EINVAL)` if `inode` is not a fast symlink (the caller should
/// dispatch through [`read_symlink`] which checks for that).
pub fn read_fast_symlink(inode: &Ext2Inode, buf: &mut [u8]) -> Result<usize, i64> {
    if !is_fast_symlink(inode) {
        return Err(crate::fs::EINVAL);
    }
    let inline = inline_bytes(inode);
    let n = core::cmp::min(inode.i_size as usize, EXT2_FAST_SYMLINK_MAX as usize);
    let n = core::cmp::min(n, buf.len());
    buf[..n].copy_from_slice(&inline[..n]);
    Ok(n)
}

/// Copy a slow-symlink target into `buf` via the indirect-block
/// walker, returning the number of bytes written.
///
/// Walks logical blocks `0..ceil(i_size / block_size)` through
/// [`super::indirect::resolve_block`] — the same routine that backs
/// regular-file reads — concatenating each block's contents into
/// `buf`. The copy is clamped to `min(i_size, buf.len())`; on an
/// attacker-forged image with `i_size > EXT2_SYMLINK_READ_MAX` the
/// read surfaces `ENAMETOOLONG` before any `bread`, so a crafted
/// inode cannot coax the reader into stitching together arbitrary
/// amounts of disk content.
///
/// A zero pointer anywhere along the walk — including a sparse hole
/// that [`resolve_block`] would normally report as `Ok(None)` — maps
/// to `EIO`. A symlink is either wholly allocated or doesn't exist;
/// a partially-allocated body is image corruption.
///
/// Callers must have checked `is_symlink(inode) == true` and
/// `is_fast_symlink(inode) == false` before entering. The dispatcher
/// [`read_symlink`] already enforces this.
#[cfg(all(feature = "ext2", target_os = "none"))]
pub fn read_slow_symlink(
    inode: &Ext2Inode,
    super_: &alloc::sync::Arc<super::fs::Ext2Super>,
    buf: &mut [u8],
) -> Result<usize, i64> {
    use super::indirect::{resolve_block, Geometry, WalkError};
    use crate::fs::{EINVAL, EIO, ENAMETOOLONG};

    if !is_symlink(inode) {
        return Err(EINVAL);
    }
    if is_fast_symlink(inode) {
        // Caller confusion: this entry point is the slow path only.
        return Err(EINVAL);
    }
    // PATH_MAX guard. A legal POSIX symlink target is ≤ 4095 bytes
    // (4096 including the implicit trailing NUL that userspace appends,
    // which we do not store on disk). `i_size` above this is either
    // corruption or a hostile image trying to spill the reader past
    // the allocated extent; refuse loudly. Note the write path
    // (`link::symlink`) clamps to the same cap before allocation, so
    // no honest vibix-written symlink ever trips this.
    if inode.i_size > EXT2_SYMLINK_READ_MAX {
        return Err(ENAMETOOLONG);
    }

    let block_size = super_.block_size as u64;
    debug_assert!(block_size > 0, "mount validated block_size != 0");

    let (s_first_data_block, s_blocks_count) = {
        let sb = super_.sb_disk.lock();
        (sb.s_first_data_block, sb.s_blocks_count)
    };
    let geom = Geometry::new(super_.block_size, s_first_data_block, s_blocks_count).ok_or(EIO)?;
    let md = super::file::build_metadata_map(super_);

    let total = core::cmp::min(inode.i_size as usize, buf.len());
    if total == 0 {
        return Ok(0);
    }

    let mut copied = 0usize;
    while copied < total {
        let logical = (copied as u64 / block_size) as u32;
        let in_block = copied % block_size as usize;
        let remaining_in_block = block_size as usize - in_block;
        let chunk = core::cmp::min(remaining_in_block, total - copied);

        match resolve_block(
            &super_.cache,
            super_.device_id,
            &geom,
            &md,
            &inode.i_block,
            logical,
            None,
        ) {
            Ok(Some(abs)) => {
                let bh = super_
                    .cache
                    .bread(super_.device_id, abs as u64)
                    .map_err(|_| EIO)?;
                let data = bh.data.read();
                debug_assert!(in_block + chunk <= data.len());
                buf[copied..copied + chunk].copy_from_slice(&data[in_block..in_block + chunk]);
            }
            // A symlink body with a hole is corruption — see module
            // docs. `write_slow_symlink_target` allocates every
            // logical block before publishing the inode, so a hole
            // means the image is lying to us.
            Ok(None) => return Err(EIO),
            Err(WalkError::Io) => return Err(EIO),
            Err(WalkError::Corrupt) => return Err(EIO),
        }
        copied += chunk;
    }

    Ok(copied)
}

/// Dispatch entry point: copy a symlink's target into `buf`, returning
/// the number of bytes copied. This is the function `InodeOps::readlink`
/// wires to for ext2 inodes (#559 wires the `InodeOps` impl itself).
///
/// * Fast symlinks (target ≤ 60 bytes, stored inline) always succeed.
/// * Slow symlinks walk the inode's data-block chain through the
///   indirect walker ([`read_slow_symlink`]); `i_size >
///   EXT2_SYMLINK_READ_MAX` surfaces as `ENAMETOOLONG`.
/// * Non-symlink inodes return `EINVAL` — the POSIX errno for
///   `readlink` on a non-link.
#[cfg(all(feature = "ext2", target_os = "none"))]
pub fn read_symlink(
    inode: &Ext2Inode,
    super_: &alloc::sync::Arc<super::fs::Ext2Super>,
    buf: &mut [u8],
) -> Result<usize, i64> {
    if !is_symlink(inode) {
        return Err(crate::fs::EINVAL);
    }
    if is_fast_symlink(inode) {
        read_fast_symlink(inode, buf)
    } else {
        read_slow_symlink(inode, super_, buf)
    }
}

#[cfg(test)]
mod tests {
    //! Host-side tests for the fast-symlink path and the gate
    //! predicates. The slow path touches the buffer cache and is
    //! exercised by the QEMU integration test
    //! `kernel/tests/ext2_symlink.rs` (Workstream D wave 2) once #559
    //! lands the `InodeOps::readlink` wiring.
    use super::*;
    use crate::fs::ext2::disk::{Ext2Inode, EXT2_INODE_SIZE_V0, EXT2_N_BLOCKS};

    /// Build a synthetic `Ext2Inode` decoded from a hand-crafted
    /// 128-byte slot. `mode` goes into `i_mode`, `size` into `i_size`,
    /// `blocks` into `i_blocks`, and `inline` is copied into the
    /// 60-byte `i_block[]` region (offset 40..100) byte-for-byte.
    fn make_inode(mode: u16, size: u32, blocks: u32, inline: &[u8]) -> Ext2Inode {
        let mut slot = [0u8; EXT2_INODE_SIZE_V0];
        slot[0..2].copy_from_slice(&mode.to_le_bytes());
        slot[4..8].copy_from_slice(&size.to_le_bytes());
        slot[28..32].copy_from_slice(&blocks.to_le_bytes());
        let n = core::cmp::min(inline.len(), 60);
        slot[40..40 + n].copy_from_slice(&inline[..n]);
        Ext2Inode::decode(&slot)
    }

    #[test]
    fn constants_match_rfc() {
        // 15 block pointers × 4 bytes = 60.
        assert_eq!(EXT2_FAST_SYMLINK_MAX, 60);
        assert_eq!(EXT2_N_BLOCKS * 4, 60);
        // Linux `S_IFLNK` value, for cross-check.
        assert_eq!(EXT2_S_IFLNK, 0o120000);
        assert_eq!(EXT2_S_IFMT, 0o170000);
    }

    #[test]
    fn is_symlink_checks_mode_bits() {
        let link = make_inode(EXT2_S_IFLNK | 0o777, 3, 0, b"bin");
        assert!(is_symlink(&link));
        let reg = make_inode(0o100644, 3, 0, b"bin");
        assert!(!is_symlink(&reg));
        let dir = make_inode(0o040755, 0, 2, &[]);
        assert!(!is_symlink(&dir));
    }

    #[test]
    fn fast_symlink_gate_requires_all_three_legs() {
        // Canonical fast symlink: link mode, zero blocks, size ≤ 60.
        let good = make_inode(EXT2_S_IFLNK | 0o777, 3, 0, b"bin");
        assert!(is_fast_symlink(&good));

        // Missing leg: not a symlink.
        let not_link = make_inode(0o100644, 3, 0, b"bin");
        assert!(!is_fast_symlink(&not_link));

        // Missing leg: i_blocks != 0 — a "slow" symlink that happens
        // to have i_size <= 60 (possible if the FS writer used the
        // slow path unconditionally; Linux never does, but a crafted
        // image could).
        let slow_short = make_inode(EXT2_S_IFLNK | 0o777, 3, 2, b"bin");
        assert!(!is_fast_symlink(&slow_short));

        // Missing leg: i_size > 60 — the RFC gate's most critical
        // check. Without it, a hostile image with oversize i_size and
        // zero i_blocks would leak adjacent inode bytes through
        // readlink.
        let oversize = make_inode(EXT2_S_IFLNK | 0o777, 200, 0, b"bin");
        assert!(!is_fast_symlink(&oversize));
    }

    #[test]
    fn fast_symlink_copies_inline_target_byte_for_byte() {
        let target = b"/usr/bin/env";
        let link = make_inode(EXT2_S_IFLNK | 0o777, target.len() as u32, 0, target);

        // Prefill with a sentinel so the "no NUL terminator" check
        // actually catches an accidental terminator write — a
        // zero-initialised buffer would pass even if the reader did
        // append a NUL.
        let mut buf = [0xffu8; 128];
        let n = read_fast_symlink(&link, &mut buf).expect("fast-symlink read");
        assert_eq!(n, target.len());
        assert_eq!(&buf[..n], target);
        // No trailing NUL — POSIX `readlink` contract. Byte after
        // the copied range must still be the sentinel.
        assert_eq!(buf[n], 0xff);
    }

    #[test]
    fn fast_symlink_at_60_byte_boundary() {
        // Exactly 60 bytes fills `i_block[]` completely.
        let target: [u8; 60] = core::array::from_fn(|i| b'a' + (i % 26) as u8);
        let link = make_inode(EXT2_S_IFLNK | 0o777, 60, 0, &target);
        assert!(is_fast_symlink(&link));

        let mut buf = [0u8; 60];
        let n = read_fast_symlink(&link, &mut buf).expect("read");
        assert_eq!(n, 60);
        assert_eq!(buf, target);
    }

    #[test]
    fn fast_symlink_clamps_to_i_size_not_trailing_garbage() {
        // Stamp all 60 bytes with a recognisable pattern but set
        // `i_size = 3` — the reader must return only the first 3
        // bytes. Otherwise trailing bytes of `i_block[]` (which on a
        // real image might hold stale pointers from a previous
        // allocation) would leak to userspace.
        let mut inline = [0u8; 60];
        for (i, b) in inline.iter_mut().enumerate() {
            *b = 0x80 | (i as u8);
        }
        let link = make_inode(EXT2_S_IFLNK | 0o777, 3, 0, &inline);

        let mut buf = [0u8; 60];
        let n = read_fast_symlink(&link, &mut buf).expect("read");
        assert_eq!(n, 3);
        assert_eq!(&buf[..3], &inline[..3]);
        // Bytes past the clamp remain zero in the user buffer.
        for &b in &buf[3..] {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn fast_symlink_clamps_to_user_buflen() {
        let target = b"/usr/bin/env";
        let link = make_inode(EXT2_S_IFLNK | 0o777, target.len() as u32, 0, target);

        // Short buffer: truncation, no error.
        let mut buf = [0u8; 5];
        let n = read_fast_symlink(&link, &mut buf).expect("read");
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], &target[..5]);
    }

    #[test]
    fn fast_symlink_zero_length_target_is_empty() {
        // A zero-length symlink target is legal-but-useless; readlink
        // returns 0 without touching the buffer.
        let link = make_inode(EXT2_S_IFLNK | 0o777, 0, 0, &[]);
        assert!(is_fast_symlink(&link));

        let mut buf = [0xffu8; 8];
        let n = read_fast_symlink(&link, &mut buf).expect("read");
        assert_eq!(n, 0);
        // Unwritten bytes untouched.
        for &b in &buf {
            assert_eq!(b, 0xff);
        }
    }

    #[test]
    fn fast_symlink_rejects_non_symlinks() {
        let reg = make_inode(0o100644, 3, 0, b"foo");
        let mut buf = [0u8; 16];
        assert_eq!(read_fast_symlink(&reg, &mut buf), Err(crate::fs::EINVAL));
    }

    #[test]
    fn fast_symlink_rejects_slow_symlink() {
        // A symlink with `i_blocks > 0` is by definition slow even if
        // its size is ≤ 60; the fast entry point refuses it (the
        // dispatcher will route to the slow path instead).
        let link = make_inode(EXT2_S_IFLNK | 0o777, 3, 2, b"bin");
        let mut buf = [0u8; 16];
        assert_eq!(read_fast_symlink(&link, &mut buf), Err(crate::fs::EINVAL));
    }

    #[test]
    fn inline_bytes_roundtrip_through_decode_encode() {
        // Every byte of a fast-symlink target must survive decode →
        // inline_bytes. This is the load-bearing invariant for the
        // fast path: we reconstruct the on-disk bytes from the parsed
        // u32 array rather than keeping the raw slot around.
        let target: [u8; 60] = core::array::from_fn(|i| (0x10 + i as u8).wrapping_mul(3));
        let link = make_inode(EXT2_S_IFLNK | 0o777, 60, 0, &target);
        let bytes = inline_bytes(&link);
        assert_eq!(bytes, target);
    }
}
