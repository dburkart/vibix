//! ext2 directory iteration — `lookup` + `getdents64`.
//!
//! RFC 0004 (`docs/RFC/0004-ext2-filesystem-driver.md`) §Directory
//! operations and §Security (dirent validation) are the normative spec.
//! This module is Workstream D wave 2, issue #562.
//!
//! A directory on ext2 is a plain file whose data blocks carry a
//! sequence of variable-length `ext2_dir_entry_2` records. Each record
//! is 4-byte aligned, carries `{ inode, rec_len, name_len, file_type }`
//! followed by `name[name_len]` bytes, and must not straddle a block
//! boundary. The driver walks the directory's logical data blocks
//! through [`super::indirect::resolve_block`] (the shared direct /
//! indirect / double-indirect / triple-indirect walker) and parses each
//! block in turn.
//!
//! # Shape
//!
//! - [`DirEntryIter`] — pure iterator over the records of a single
//!   directory block. Validates `rec_len` / `name_len` / `file_type`
//!   per RFC 0004 §Security. Yields [`DirEntryView`] values that borrow
//!   the name bytes out of the underlying block; the caller copies them
//!   out before advancing. Host-testable (no `BlockCache` dependency).
//! - [`lookup`] — `(super, dir, name)` → ino. Walks the directory's
//!   data blocks, scans each for an exact name match, returns the ino.
//! - [`getdents64`] — emits Linux `struct linux_dirent64` records into
//!   a caller-supplied buffer. Matches the format used by
//!   [`FileOps::getdents`](crate::fs::vfs::ops::FileOps::getdents)
//!   elsewhere (ramfs, devfs, tarfs); the userspace shim is the same.
//!
//! # What this wave does *not* wire
//!
//! Per #562's scope, this module provides the primitives. The
//! `InodeOps::lookup` and `FileOps::getdents` trait impls on
//! [`super::inode::Ext2Inode`] / [`super::inode::Ext2FileOps`] still
//! return `ENOENT` / `ENOTDIR` respectively; a follow-up PR swaps the
//! stubs for calls into this module (touching `inode.rs` is reserved
//! for that integration step — this wave must not collide with
//! parallel work on the read path in #561).
//!
//! # Security — what we validate
//!
//! Directory blocks are attacker-controlled (a hostile image can stamp
//! any bytes there). The walker enforces, per RFC 0004 §Security:
//!
//! 1. `rec_len >= 8 + name_len` — header + name fits in the record.
//! 2. `rec_len % 4 == 0` — on-disk alignment.
//! 3. `cursor + rec_len <= block_end` — no straddling.
//! 4. `inode == 0` is a tombstone — never yielded by the iterator.
//! 5. `name_len > 0` on live records — a live record with a zero-length
//!    name is corruption.
//! 6. `file_type` is one of the known `EXT2_FT_*` values when the FS
//!    has `INCOMPAT_FILETYPE` set; otherwise the byte is ignored
//!    (pre-rev-1 layout puts the high byte of `name_len` there).
//! 7. `inode` is not in the reserved range `[1, EXT2_GOOD_OLD_FIRST_INO)`
//!    except `EXT2_ROOT_INO` (2). The other reserved inos
//!    (`s_last_orphan`'s 1, journal 8, etc.) must never appear in a
//!    live directory record.
//!
//! Any violation surfaces as [`DirError::Corrupt`], which callers map
//! to `EIO`. The walker never panics on a bad block.

#![allow(dead_code)]

use super::disk::{
    align4_rec_len, Ext2DirEntry2, EXT2_DIR_REC_HEADER_LEN, EXT2_FT_BLKDEV, EXT2_FT_CHRDEV,
    EXT2_FT_DIR, EXT2_FT_FIFO, EXT2_FT_REG_FILE, EXT2_FT_SOCK, EXT2_FT_SYMLINK, EXT2_FT_UNKNOWN,
    EXT2_GOOD_OLD_FIRST_INO, EXT2_ROOT_INO, INCOMPAT_FILETYPE,
};

/// Error out of the directory walker.
///
/// `Io` is a buffer-cache read failure; the caller maps it to `EIO`.
/// `Corrupt` is a structural violation inside a directory block; the
/// caller also maps it to `EIO` and *should* consider forcing the mount
/// read-only (RFC 0004 §Security — continuing to mutate a directory
/// whose records don't agree with their block geometry is how
/// confused-deputy escalations happen).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DirError {
    Io,
    Corrupt,
}

/// A borrowed view of one live directory record. The `name` slice
/// points into the owning block buffer — the caller must copy before
/// advancing past this record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirEntryView<'a> {
    pub inode: u32,
    /// Validated against the superblock's `INCOMPAT_FILETYPE` bit by
    /// the caller; [`dt_from_file_type`] maps this to a POSIX `DT_*`
    /// value for getdents emission.
    pub file_type: u8,
    pub name: &'a [u8],
}

/// Iterator over the records of a single directory block.
///
/// Construct with [`DirEntryIter::new`] and call `next()` until it
/// yields `None` (end of block) or an error. Tombstoned records
/// (`inode == 0`) are skipped silently — they are legal on disk but
/// must never leak to callers (RFC 0004 §Directory operations).
///
/// The iterator carries no allocation and no outside-facing state
/// beyond the block it borrows; it's deliberately cheap so a lookup
/// can rebuild a fresh iterator for each block it walks without
/// incurring per-block overhead.
pub struct DirEntryIter<'a> {
    block: &'a [u8],
    cursor: usize,
    /// When true (`INCOMPAT_FILETYPE` is set on the superblock), the
    /// 8th byte of each record is `file_type`. When false, the 8th
    /// byte is the high byte of `name_len` on pre-rev-1 images and the
    /// iterator ignores it. Kept explicit so callers don't misinterpret
    /// a pre-rev-1 record as a `DT_UNKNOWN` entry.
    filetype_valid: bool,
}

impl<'a> DirEntryIter<'a> {
    /// Build an iterator over `block`. The block must be the exact
    /// per-block payload (typically the buffer-cache block's full
    /// length == fs block size); a shorter slice is accepted but
    /// produces a shorter walk.
    pub fn new(block: &'a [u8], filetype_valid: bool) -> Self {
        Self {
            block,
            cursor: 0,
            filetype_valid,
        }
    }
}

impl<'a> Iterator for DirEntryIter<'a> {
    type Item = Result<DirEntryView<'a>, DirError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // End of block reached exactly — done.
            if self.cursor >= self.block.len() {
                return None;
            }
            // Header must fit in what remains of the block. If it
            // doesn't, the prior record's `rec_len` was lying — treat
            // as corruption.
            let remain = self.block.len() - self.cursor;
            if remain < EXT2_DIR_REC_HEADER_LEN {
                return Some(Err(DirError::Corrupt));
            }

            let hdr_slot = &self.block[self.cursor..self.cursor + EXT2_DIR_REC_HEADER_LEN];
            let hdr = Ext2DirEntry2::decode_header(hdr_slot);

            let rec_len = hdr.rec_len as usize;
            let name_len = hdr.name_len as usize;

            // rec_len validation: must be at least a bare header, must
            // be 4-byte aligned, must fit inside the block. A record
            // that straddles the block end is corruption.
            if rec_len < EXT2_DIR_REC_HEADER_LEN || rec_len % 4 != 0 || rec_len > remain {
                return Some(Err(DirError::Corrupt));
            }
            // Minimum rec_len including the name must match the 4-byte
            // aligned (header + name) length.
            let minimal = match align4_rec_len(EXT2_DIR_REC_HEADER_LEN + name_len) {
                Some(v) => v,
                None => return Some(Err(DirError::Corrupt)),
            };
            if rec_len < minimal {
                return Some(Err(DirError::Corrupt));
            }

            // Tombstone: advance past the record silently. A zero-ino
            // record is legitimate on disk (e.g. after unlink) but
            // must not surface to lookup or getdents.
            if hdr.inode == 0 {
                self.cursor += rec_len;
                continue;
            }

            // Reserved-range check. ino 1 is historically "bad blocks
            // inode"; ino 3..=10 are reserved per rev-0. The root ino
            // (2) is the only one that legitimately appears in a live
            // directory record from that range (for "." in the root
            // directory).
            if hdr.inode < EXT2_GOOD_OLD_FIRST_INO && hdr.inode != EXT2_ROOT_INO {
                return Some(Err(DirError::Corrupt));
            }

            // A live record must have a name.
            if name_len == 0 {
                return Some(Err(DirError::Corrupt));
            }

            // file_type validation (only when INCOMPAT_FILETYPE is
            // enabled — otherwise the byte is the high byte of
            // name_len and we must not interpret it).
            if self.filetype_valid && !is_known_file_type(hdr.file_type) {
                return Some(Err(DirError::Corrupt));
            }

            // Slice the name out.
            let name_start = self.cursor + EXT2_DIR_REC_HEADER_LEN;
            let name_end = name_start + name_len;
            // Bounds: minimal rec_len check above already guarantees
            // this, but double-check to keep the indexing obviously
            // safe.
            if name_end > self.block.len() {
                return Some(Err(DirError::Corrupt));
            }
            let name = &self.block[name_start..name_end];

            // file_type byte: on pre-rev-1 images we return
            // EXT2_FT_UNKNOWN so the getdents emitter produces
            // DT_UNKNOWN and lookup doesn't lean on the byte.
            let file_type = if self.filetype_valid {
                hdr.file_type
            } else {
                EXT2_FT_UNKNOWN
            };

            let view = DirEntryView {
                inode: hdr.inode,
                file_type,
                name,
            };

            self.cursor += rec_len;
            return Some(Ok(view));
        }
    }
}

/// `true` iff `ft` is one of the ext2 file-type codes — including
/// `EXT2_FT_UNKNOWN`, which is a legal on-disk value meaning "type not
/// recorded."
#[inline]
fn is_known_file_type(ft: u8) -> bool {
    matches!(
        ft,
        EXT2_FT_UNKNOWN
            | EXT2_FT_REG_FILE
            | EXT2_FT_DIR
            | EXT2_FT_CHRDEV
            | EXT2_FT_BLKDEV
            | EXT2_FT_FIFO
            | EXT2_FT_SOCK
            | EXT2_FT_SYMLINK
    )
}

/// Map an `EXT2_FT_*` code to the POSIX `DT_*` value userspace
/// `linux_dirent64` readers expect. Unknown / missing maps to
/// `DT_UNKNOWN` (0).
#[inline]
pub fn dt_from_file_type(ft: u8) -> u8 {
    // POSIX DT_* values from sys/dirent.h.
    match ft {
        EXT2_FT_REG_FILE => 8, // DT_REG
        EXT2_FT_DIR => 4,      // DT_DIR
        EXT2_FT_CHRDEV => 2,   // DT_CHR
        EXT2_FT_BLKDEV => 6,   // DT_BLK
        EXT2_FT_FIFO => 1,     // DT_FIFO
        EXT2_FT_SOCK => 12,    // DT_SOCK
        EXT2_FT_SYMLINK => 10, // DT_LNK
        _ => 0,                // DT_UNKNOWN
    }
}

/// `true` iff the superblock's incompat-feature set says the `file_type`
/// byte is valid (vs. pre-rev-1, where it's the high byte of `name_len`).
#[inline]
pub fn filetype_valid_from_incompat(s_feature_incompat: u32) -> bool {
    (s_feature_incompat & INCOMPAT_FILETYPE) != 0
}

/// Emit one `linux_dirent64` record at `buf[offset..]`. Returns the
/// number of bytes written, or 0 if the buffer has no room for the
/// record.
///
/// Matches the byte-for-byte layout in
/// [`crate::fs::vfs::ramfs::emit_dirent`] — see RFC 0002
/// (`docs/RFC/0002-virtual-filesystem.md`) §getdents64.
///
/// ```text
/// u64 d_ino    offset 0
/// i64 d_off    offset 8
/// u16 d_reclen offset 16
/// u8  d_type   offset 18
/// char d_name  offset 19  (NUL-terminated, padded to 8-byte alignment)
/// ```
pub fn emit_linux_dirent64(
    buf: &mut [u8],
    offset: usize,
    d_ino: u64,
    d_off: u64,
    d_type: u8,
    name: &[u8],
) -> usize {
    let header = 19usize;
    let raw = header + name.len() + 1; // +1 for NUL
    let reclen = (raw + 7) & !7;

    let dest = match buf.get_mut(offset..offset + reclen) {
        Some(s) => s,
        None => return 0,
    };

    dest.fill(0);
    dest[0..8].copy_from_slice(&d_ino.to_ne_bytes());
    dest[8..16].copy_from_slice(&d_off.to_ne_bytes());
    dest[16..18].copy_from_slice(&(reclen as u16).to_ne_bytes());
    dest[18] = d_type;
    dest[19..19 + name.len()].copy_from_slice(name);
    reclen
}

// ---------------------------------------------------------------------------
// Block-backed lookup + getdents64. Feature-gated because they need
// `Ext2Super` + the buffer cache, neither of which compile off the
// kernel target. Host unit tests for the iterator above don't need any
// of this.
// ---------------------------------------------------------------------------

#[cfg(all(feature = "ext2", target_os = "none"))]
pub use block_backed::*;

#[cfg(all(feature = "ext2", target_os = "none"))]
mod block_backed {
    use super::{
        dt_from_file_type, emit_linux_dirent64, filetype_valid_from_incompat, DirEntryIter,
        DirError,
    };

    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;

    use super::super::indirect::{resolve_block, Geometry, MetadataMap, WalkError};
    use super::super::inode::Ext2Inode;
    use super::super::Ext2Super;
    use crate::fs::{EIO, ENOENT};

    /// Walk `dir`'s data blocks and return the ino of the entry whose
    /// name equals `name` byte-for-byte. `ENOENT` if no live record
    /// matches.
    ///
    /// The walk is linear — one pass over the directory's data blocks,
    /// one pass over each block's records. ext2 `dir_index` (HTree)
    /// acceleration is explicitly out of scope (RFC 0004 §Out of scope).
    ///
    /// # Errors
    ///
    /// - `ENOENT` — no matching name.
    /// - `EIO` — a data block could not be read, a pointer was out of
    ///   range or aimed at metadata, or a record inside a block
    ///   violated the on-disk format (see module docs §Security).
    pub fn lookup(super_ref: &Arc<Ext2Super>, dir: &Ext2Inode, name: &[u8]) -> Result<u32, i64> {
        // An empty name never matches a valid record.
        if name.is_empty() {
            return Err(ENOENT);
        }

        let block_size = super_ref.block_size;
        let geom = Geometry::new(
            block_size,
            super_ref.sb_disk.s_first_data_block,
            super_ref.sb_disk.s_blocks_count,
        )
        .ok_or(EIO)?;
        let md = MetadataMap::empty();
        let filetype_valid = filetype_valid_from_incompat(super_ref.sb_disk.s_feature_incompat);

        let meta = dir.meta.read();
        let size = meta.size;
        let i_block = meta.i_block;
        drop(meta);

        let block_count = size.div_ceil(block_size as u64);
        for logical in 0..block_count {
            let logical_u32: u32 = match logical.try_into() {
                Ok(v) => v,
                Err(_) => return Err(EIO),
            };
            let abs = match resolve_block(
                &super_ref.cache,
                super_ref.device_id,
                &geom,
                &md,
                &i_block,
                logical_u32,
                None,
            ) {
                Ok(Some(a)) => a,
                // A hole in a directory is spec-illegal but the walker
                // returns Ok(None); skip rather than crash. The iter
                // over subsequent records will still find matches.
                Ok(None) => continue,
                Err(WalkError::Io) => return Err(EIO),
                Err(WalkError::Corrupt) => return Err(EIO),
            };

            let bh = super_ref
                .cache
                .bread(super_ref.device_id, abs as u64)
                .map_err(|_| EIO)?;
            let data = bh.data.read();
            let end = core::cmp::min(data.len(), block_size as usize);
            for rec in DirEntryIter::new(&data[..end], filetype_valid) {
                match rec {
                    Err(DirError::Corrupt) | Err(DirError::Io) => return Err(EIO),
                    Ok(view) => {
                        if view.name == name {
                            return Ok(view.inode);
                        }
                    }
                }
            }
        }
        Err(ENOENT)
    }

    /// Emit `linux_dirent64` records for `dir`'s entries into `buf`,
    /// advancing `cookie` so a subsequent call continues where this one
    /// stopped. Returns the number of bytes written; 0 at end-of-dir.
    ///
    /// The cookie is the count of live records already emitted across
    /// all prior calls. That's a linear scan: `getdents64` over the
    /// whole directory costs O(n²) records, same as ramfs / devfs.
    /// ext2 `dir_index` is out of scope (RFC 0004 §Out of scope); a
    /// later wave can replace the cookie with a block-offset pair if
    /// the cost matters.
    ///
    /// # Errors
    ///
    /// - `EIO` — a data block could not be read or carried a corrupt
    ///   record.
    pub fn getdents64(
        super_ref: &Arc<Ext2Super>,
        dir: &Ext2Inode,
        buf: &mut [u8],
        cookie: &mut u64,
    ) -> Result<usize, i64> {
        let block_size = super_ref.block_size;
        let geom = Geometry::new(
            block_size,
            super_ref.sb_disk.s_first_data_block,
            super_ref.sb_disk.s_blocks_count,
        )
        .ok_or(EIO)?;
        let md = MetadataMap::empty();
        let filetype_valid = filetype_valid_from_incompat(super_ref.sb_disk.s_feature_incompat);

        let meta = dir.meta.read();
        let size = meta.size;
        let i_block = meta.i_block;
        drop(meta);

        let mut written = 0usize;
        let mut idx: u64 = 0;
        let start = *cookie;

        let block_count = size.div_ceil(block_size as u64);
        // Reused block buffer: the buffer cache holds the data slot
        // under a read lock; we copy the record payload out before
        // running the emitter so the lock's lifetime matches the
        // block's iteration, not the whole call.
        let mut block_buf: Vec<u8> = vec![0u8; block_size as usize];
        for logical in 0..block_count {
            let logical_u32: u32 = match logical.try_into() {
                Ok(v) => v,
                Err(_) => return Err(EIO),
            };
            let abs = match resolve_block(
                &super_ref.cache,
                super_ref.device_id,
                &geom,
                &md,
                &i_block,
                logical_u32,
                None,
            ) {
                Ok(Some(a)) => a,
                Ok(None) => continue,
                Err(WalkError::Io) => return Err(EIO),
                Err(WalkError::Corrupt) => return Err(EIO),
            };

            let bh = super_ref
                .cache
                .bread(super_ref.device_id, abs as u64)
                .map_err(|_| EIO)?;
            {
                let data = bh.data.read();
                let end = core::cmp::min(data.len(), block_size as usize);
                block_buf[..end].copy_from_slice(&data[..end]);
                if end < block_buf.len() {
                    // Anything past the disk block's extent is zeros;
                    // the iterator will stop once rec_len overruns
                    // the valid prefix.
                    for b in &mut block_buf[end..] {
                        *b = 0;
                    }
                }
            }

            let valid_end = core::cmp::min(block_buf.len(), block_size as usize);
            for rec in DirEntryIter::new(&block_buf[..valid_end], filetype_valid) {
                let view = match rec {
                    Err(DirError::Corrupt) | Err(DirError::Io) => return Err(EIO),
                    Ok(v) => v,
                };
                if idx < start {
                    idx += 1;
                    continue;
                }
                let d_type = dt_from_file_type(view.file_type);
                let consumed = emit_linux_dirent64(
                    buf,
                    written,
                    view.inode as u64,
                    idx + 1,
                    d_type,
                    view.name,
                );
                if consumed == 0 {
                    // Buffer full. Stop — don't advance the cookie
                    // past this record so the next call re-emits it.
                    *cookie = idx;
                    return Ok(written);
                }
                written += consumed;
                idx += 1;
            }
        }

        *cookie = idx;
        Ok(written)
    }
}

// ---------------------------------------------------------------------------
// Host unit tests — the iterator is pure and deserves a sharp fixture.
// The golden 64-byte root-dir block from `fixtures/golden_root_dir.bin`
// is re-used from disk.rs's tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::disk::{EXT2_FT_DIR, EXT2_FT_REG_FILE};
    use super::*;

    /// 64 bytes of the root directory's first block on the golden
    /// image: `.` (12), `..` (12), `lost+found` (rec_len 1000 — the
    /// rest of the 1 KiB block). We only check the first two live
    /// records; the third's rec_len is 1000, which overflows a 64-byte
    /// slice, so we truncate validation to the first 24 bytes for the
    /// "two complete records" test.
    const GOLDEN_ROOT_DIR: &[u8; 64] = include_bytes!("fixtures/golden_root_dir.bin");

    #[test]
    fn iter_yields_dot_and_dotdot() {
        // Only expose the first 24 bytes (two 12-byte records) so the
        // iterator stops cleanly; the third record's rec_len=1000
        // wouldn't fit in a 64-byte synthetic slice and would surface
        // as corrupt.
        let it = DirEntryIter::new(&GOLDEN_ROOT_DIR[..24], true);
        let entries: Vec<_> = it.map(|r| r.expect("valid record")).collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].inode, 2);
        assert_eq!(entries[0].name, b".");
        assert_eq!(entries[0].file_type, EXT2_FT_DIR);
        assert_eq!(entries[1].inode, 2);
        assert_eq!(entries[1].name, b"..");
        assert_eq!(entries[1].file_type, EXT2_FT_DIR);
    }

    #[test]
    fn iter_yields_all_three_on_full_block() {
        // Synthesize a 1 KiB block: copy the three records from the
        // golden fixture into a full-sized buffer. The third record
        // declares rec_len = 1000; at the right block size this walks
        // to exactly the end.
        let mut block = [0u8; 1024];
        block[..64].copy_from_slice(GOLDEN_ROOT_DIR);
        let it = DirEntryIter::new(&block, true);
        let entries: Vec<_> = it.map(|r| r.expect("valid record")).collect();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].inode, 11);
        assert_eq!(entries[2].name, b"lost+found");
    }

    fn build_record(ino: u32, name: &[u8], file_type: u8, rec_len: u16) -> Vec<u8> {
        let mut out = alloc::vec![0u8; rec_len as usize];
        out[0..4].copy_from_slice(&ino.to_le_bytes());
        out[4..6].copy_from_slice(&rec_len.to_le_bytes());
        out[6] = name.len() as u8;
        out[7] = file_type;
        out[8..8 + name.len()].copy_from_slice(name);
        out
    }

    #[test]
    fn tombstone_is_skipped() {
        // Record 0: ino 0 ("deleted"), rec_len 12. Record 1: ino 42,
        // name "a", file_type REG. Expected: iterator yields only
        // record 1.
        let mut block = Vec::new();
        block.extend_from_slice(&build_record(0, b".", EXT2_FT_DIR, 12));
        block.extend_from_slice(&build_record(42, b"a", EXT2_FT_REG_FILE, 12));
        let it = DirEntryIter::new(&block, true);
        let entries: Vec<_> = it.map(|r| r.expect("record")).collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].inode, 42);
        assert_eq!(entries[0].name, b"a");
    }

    #[test]
    fn rec_len_overrun_is_corruption() {
        // Record declares rec_len = 16 in a 12-byte block. Must
        // surface as DirError::Corrupt, not panic or read OOB.
        let mut block = build_record(42, b"a", EXT2_FT_REG_FILE, 16);
        block.truncate(12);
        let mut it = DirEntryIter::new(&block, true);
        match it.next() {
            Some(Err(DirError::Corrupt)) => {}
            other => panic!("expected Corrupt, got {:?}", other),
        }
    }

    #[test]
    fn rec_len_unaligned_is_corruption() {
        // rec_len = 13 is not 4-byte aligned. Corruption.
        let mut block = build_record(42, b"a", EXT2_FT_REG_FILE, 16);
        // Stomp rec_len to 13 (still within the 16-byte allocated
        // buffer, so the "fits in block" check passes — isolates the
        // alignment check).
        block[4..6].copy_from_slice(&13u16.to_le_bytes());
        let mut it = DirEntryIter::new(&block, true);
        assert_eq!(it.next(), Some(Err(DirError::Corrupt)));
    }

    #[test]
    fn rec_len_smaller_than_header_is_corruption() {
        // rec_len = 4 < header (8). Corruption.
        let mut block = alloc::vec![0u8; 16];
        block[0..4].copy_from_slice(&42u32.to_le_bytes());
        block[4..6].copy_from_slice(&4u16.to_le_bytes());
        block[6] = 1;
        block[7] = EXT2_FT_REG_FILE;
        let mut it = DirEntryIter::new(&block, true);
        assert_eq!(it.next(), Some(Err(DirError::Corrupt)));
    }

    #[test]
    fn rec_len_too_small_for_name_is_corruption() {
        // name_len 10 but rec_len 12. 8 + 10 = 18, 4-byte aligned to
        // 20; rec_len 12 is short. Corruption.
        let mut block = alloc::vec![0u8; 12];
        block[0..4].copy_from_slice(&42u32.to_le_bytes());
        block[4..6].copy_from_slice(&12u16.to_le_bytes());
        block[6] = 10;
        block[7] = EXT2_FT_REG_FILE;
        let mut it = DirEntryIter::new(&block, true);
        assert_eq!(it.next(), Some(Err(DirError::Corrupt)));
    }

    #[test]
    fn live_zero_name_len_is_corruption() {
        // ino 42, name_len 0. On a live record this is invalid.
        let block = build_record(42, b"", EXT2_FT_REG_FILE, 8);
        let mut it = DirEntryIter::new(&block, true);
        assert_eq!(it.next(), Some(Err(DirError::Corrupt)));
    }

    #[test]
    fn reserved_inode_range_rejected_except_root() {
        // ino 1 (bad-blocks inode) — reject.
        let block = build_record(1, b"x", EXT2_FT_REG_FILE, 12);
        let mut it = DirEntryIter::new(&block, true);
        assert_eq!(it.next(), Some(Err(DirError::Corrupt)));

        // ino 2 (root) — accepted (this is "." in the root dir).
        let block = build_record(2, b".", EXT2_FT_DIR, 12);
        let mut it = DirEntryIter::new(&block, true);
        let e = it.next().expect("entry").expect("valid");
        assert_eq!(e.inode, 2);

        // ino 10 — reject (journal / other reserved).
        let block = build_record(10, b"y", EXT2_FT_REG_FILE, 12);
        let mut it = DirEntryIter::new(&block, true);
        assert_eq!(it.next(), Some(Err(DirError::Corrupt)));

        // ino 11 (lost+found / first user ino) — accept.
        let block = build_record(11, b"l", EXT2_FT_DIR, 12);
        let mut it = DirEntryIter::new(&block, true);
        let e = it.next().expect("entry").expect("valid");
        assert_eq!(e.inode, 11);
    }

    #[test]
    fn unknown_file_type_rejected_when_filetype_is_valid() {
        // file_type byte = 99 with INCOMPAT_FILETYPE on → corruption.
        let block = build_record(42, b"a", 99, 12);
        let mut it = DirEntryIter::new(&block, true);
        assert_eq!(it.next(), Some(Err(DirError::Corrupt)));
    }

    #[test]
    fn unknown_file_type_accepted_when_filetype_invalid() {
        // Pre-rev-1 layout: the 8th byte is the high byte of name_len.
        // The iterator must not reject on that byte.
        let block = build_record(42, b"a", 99, 12);
        let it = DirEntryIter::new(&block, false);
        let entries: Vec<_> = it.map(|r| r.expect("valid")).collect();
        assert_eq!(entries.len(), 1);
        // Pre-rev-1: file_type surfaces as UNKNOWN so downstream
        // emitters produce DT_UNKNOWN.
        assert_eq!(entries[0].file_type, EXT2_FT_UNKNOWN);
    }

    #[test]
    fn dt_mapping_covers_posix() {
        assert_eq!(dt_from_file_type(EXT2_FT_REG_FILE), 8);
        assert_eq!(dt_from_file_type(EXT2_FT_DIR), 4);
        assert_eq!(dt_from_file_type(EXT2_FT_CHRDEV), 2);
        assert_eq!(dt_from_file_type(EXT2_FT_BLKDEV), 6);
        assert_eq!(dt_from_file_type(EXT2_FT_FIFO), 1);
        assert_eq!(dt_from_file_type(EXT2_FT_SOCK), 12);
        assert_eq!(dt_from_file_type(EXT2_FT_SYMLINK), 10);
        assert_eq!(dt_from_file_type(EXT2_FT_UNKNOWN), 0);
        // Out-of-range falls back to UNKNOWN rather than panicking.
        assert_eq!(dt_from_file_type(99), 0);
    }

    #[test]
    fn emit_dirent_round_trip() {
        let mut buf = [0u8; 64];
        let w = emit_linux_dirent64(&mut buf, 0, 42, 1, 8, b"alpha");
        // header 19 + name 5 + NUL 1 = 25; aligned to 32.
        assert_eq!(w, 32);
        let d_ino = u64::from_ne_bytes(buf[0..8].try_into().unwrap());
        let d_off = u64::from_ne_bytes(buf[8..16].try_into().unwrap());
        let reclen = u16::from_ne_bytes(buf[16..18].try_into().unwrap());
        let d_type = buf[18];
        assert_eq!(d_ino, 42);
        assert_eq!(d_off, 1);
        assert_eq!(reclen as usize, w);
        assert_eq!(d_type, 8);
        assert_eq!(&buf[19..24], b"alpha");
        assert_eq!(buf[24], 0); // NUL terminator
    }

    #[test]
    fn emit_dirent_short_buffer_returns_zero() {
        let mut buf = [0u8; 8];
        let w = emit_linux_dirent64(&mut buf, 0, 42, 1, 8, b"hello-world");
        assert_eq!(w, 0);
    }

    #[test]
    fn incompat_filetype_predicate() {
        assert!(!filetype_valid_from_incompat(0));
        assert!(filetype_valid_from_incompat(INCOMPAT_FILETYPE));
        assert!(filetype_valid_from_incompat(INCOMPAT_FILETYPE | 0x10));
    }
}
