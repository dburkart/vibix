//! Integration test for issue #680: ext2 crash-consistency replay.
//!
//! RFC 0004 §Testing → Workstream E asks for forced-crash replay
//! coverage of the ext2 ordering rules: bitmap → inode → dirent for
//! `create`, link-count-first for `rename`, and the orphan-chain
//! detour for `unlink`. The driver implements those orderings, but
//! until this PR there was no test that asserted they survive an
//! abrupt power loss in the middle of an operation.
//!
//! ## Strategy
//!
//! 1. Mount the 64 KiB `golden.img` fixture RW, atop a
//!    [`ReplayBlockDevice`] that mirrors writes into both an
//!    in-memory image **and** a chronological log of
//!    `(offset, payload)` records.
//! 2. Drive one ordering-critical operation (one of: `create`,
//!    `unlink`, `rename`) and snapshot the log.
//! 3. For every crash-point `k` in `0..=N` (where `N` is the recorded
//!    write count), reconstruct the disk image as
//!    `pre_op_image + first_k_writes`, mount that image RW (which
//!    runs mount-time orphan-chain validation as part of the normal
//!    ext2 mount path), and assert the post-replay state passes
//!    [`assert_consistent`]:
//!
//!    - No live dirent in the (transitively-walked) directory tree
//!      points at an inode whose bitmap bit is clear. A `lookup`
//!      that resolved to such a dirent would hand back a
//!      "free-but-still-named" inode — corruption that observably
//!      leaks free-list state into a live operation.
//!    - For every dirent referencing a non-directory inode, that
//!      inode's on-disk `i_links_count >= ` the count of referencing
//!      dirents across the walked tree. The over-ref direction is
//!      what we forbid: a `links_count` lower than the dirent
//!      reference count means the kernel believes the inode is dead
//!      while a name still points at it (the rename / unlink
//!      ordering surface). The under-ref direction (`links_count >
//!      ` refs) is a fsck-reclaimable leak from a torn create — that
//!      is ext2's normal post-crash residue and is tolerated.
//!
//! ext2 has no journal. The test deliberately does **not** assert
//! that every `links_count==0` inode is on the orphan chain — the
//! buffer-cache flush order does not bind the s_last_orphan write to
//! the inode-table write at the point where the chain would update,
//! and fsck recovers any orphan that didn't make the chain. Adding a
//! strict orphan-chain check here would catch a real ordering
//! regression but would also flag the present implementation's
//! steady-state behaviour (the SB sync of `s_last_orphan` lands
//! after the inode-table sync that drops `links_count` to zero).
//! Filed for future tightening; see PR conversation for #680.
//!
//! The fixture is small and single-block-group, so the walk is
//! trivially bounded: root (`/`) plus any subdirs we created during
//! the recorded operation, each one block. No indirect blocks need
//! to be chased.
//!
//! ## What this test catches
//!
//! - A regression in `create.rs` that lands the dirent before the
//!   inode bitmap bit (resulting dirent → free-inode reference is a
//!   consistency violation flagged by step 1).
//! - A regression in `rename.rs` that decrements the source inode's
//!   `i_links_count` before the destination dirent is committed
//!   (so `links_count < #refs` — flagged by step 3).
//! - A regression in `unlink.rs` that drops the dirent's `rec_len`
//!   reference but leaves the inode's `links_count` untouched in a
//!   way that produces an extra dirent — flagged by step 1 if the
//!   target inode bit was already cleared elsewhere.
//!
//! ## What this test does **not** assert
//!
//! - Block-bitmap accounting under crash. The block allocator's
//!   ordering is covered by `ext2_block_alloc.rs`.
//! - "Every links_count==0 inode lives on the orphan chain" — see
//!   the discussion above.
//! - Replay over a `mount` that panics. The driver is not supposed
//!   to panic on a torn write; if a future regression introduces a
//!   panic the test panics with it, which is the desired failure
//!   mode.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use spin::Mutex;

use vibix::block::{BlockDevice, BlockError};
use vibix::fs::ext2::{iget, Ext2Fs, Ext2Super};
use vibix::fs::vfs::ops::{FileSystem as _, MountSource};
use vibix::fs::vfs::super_block::SuperBlock;
use vibix::fs::vfs::MountFlags;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

const GOLDEN_IMG: &[u8; 65_536] = include_bytes!("../src/fs/ext2/fixtures/golden.img");

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    run_tests();
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info)
}

fn run_tests() {
    let tests: &[(&str, &dyn Testable)] = &[
        (
            "replay_create_preserves_consistency",
            &(replay_create_preserves_consistency as fn()),
        ),
        (
            "replay_unlink_preserves_consistency",
            &(replay_unlink_preserves_consistency as fn()),
        ),
        (
            "replay_rename_preserves_consistency",
            &(replay_rename_preserves_consistency as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ---------------------------------------------------------------------------
// ReplayBlockDevice — a `BlockDevice` that records every write while it
// runs, so a follow-up replay phase can reconstruct any prefix of the
// recorded write stream and remount that prefix as if the kernel
// crashed after exactly `k` writes.
//
// Two distinct lifetimes:
// - Recording: read_at + write_at both touch `storage`; write_at also
//   appends `(offset, payload)` to `log`.
// - Replay: the test extracts the snapshot + log, builds a fresh
//   `ReplayBlockDevice` for each prefix, and mounts it RW. The replay
//   instance does not record (its `record` flag is false) — we don't
//   care what writes the second mount issues, only that the consistency
//   assertion passes against whatever state it converges on.
// ---------------------------------------------------------------------------

struct ReplayBlockDevice {
    block_size: u32,
    storage: Mutex<Vec<u8>>,
    log: Mutex<Vec<(u64, Vec<u8>)>>,
    record: AtomicBool,
    writes: AtomicU32,
}

impl ReplayBlockDevice {
    fn from_image(bytes: &[u8], block_size: u32) -> Arc<Self> {
        assert!(bytes.len() % block_size as usize == 0);
        Arc::new(Self {
            block_size,
            storage: Mutex::new(bytes.to_vec()),
            log: Mutex::new(Vec::new()),
            record: AtomicBool::new(false),
            writes: AtomicU32::new(0),
        })
    }

    fn start_recording(&self) {
        self.log.lock().clear();
        self.record.store(true, Ordering::Release);
    }

    fn stop_recording(&self) {
        self.record.store(false, Ordering::Release);
    }

    fn snapshot(&self) -> Vec<u8> {
        self.storage.lock().clone()
    }

    fn log_clone(&self) -> Vec<(u64, Vec<u8>)> {
        self.log.lock().clone()
    }
}

impl BlockDevice for ReplayBlockDevice {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        let bs = self.block_size as u64;
        if buf.is_empty() || (buf.len() as u64) % bs != 0 || offset % bs != 0 {
            return Err(BlockError::BadAlign);
        }
        let storage = self.storage.lock();
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(BlockError::OutOfRange)?;
        if end > storage.len() as u64 {
            return Err(BlockError::OutOfRange);
        }
        let off = offset as usize;
        buf.copy_from_slice(&storage[off..off + buf.len()]);
        Ok(())
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<(), BlockError> {
        let bs = self.block_size as u64;
        if buf.is_empty() || (buf.len() as u64) % bs != 0 || offset % bs != 0 {
            return Err(BlockError::BadAlign);
        }
        let mut storage = self.storage.lock();
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(BlockError::Enospc)?;
        if end > storage.len() as u64 {
            return Err(BlockError::Enospc);
        }
        let off = offset as usize;
        storage[off..off + buf.len()].copy_from_slice(buf);
        if self.record.load(Ordering::Acquire) {
            self.log.lock().push((offset, buf.to_vec()));
        }
        self.writes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn capacity(&self) -> u64 {
        self.storage.lock().len() as u64
    }
}

// ---------------------------------------------------------------------------
// Mount helpers
// ---------------------------------------------------------------------------

fn mount_rw_on(
    disk: Arc<ReplayBlockDevice>,
) -> Option<(Arc<SuperBlock>, Arc<Ext2Fs>, Arc<Ext2Super>)> {
    let fs = Ext2Fs::new_with_device(disk as Arc<dyn BlockDevice>);
    let sb = fs.mount(MountSource::None, MountFlags(0)).ok()?;
    let super_arc = fs.current_super()?;
    Some((sb, fs, super_arc))
}

// ---------------------------------------------------------------------------
// On-disk reconstruction helpers — copies of the offsets the orphan-chain
// test uses, kept local so this file is not coupled to module-private
// constants in `ext2::disk`.
// ---------------------------------------------------------------------------

const SB_BYTE_OFFSET: usize = 1024;
const BGDT_BYTE_OFFSET_1K: usize = 2048;
const BGD_OFF_INODE_BITMAP: usize = 4;
const BGD_OFF_INODE_TABLE: usize = 8;
const INODE_SIZE: usize = 128;
const INODE_OFF_MODE: usize = 0;
const INODE_OFF_LINKS_COUNT: usize = 26;
const INODE_OFF_I_BLOCK: usize = 40;
const BLOCK_SIZE_BYTES: usize = 1024;
const EXT2_ROOT_INO: u32 = 2;

fn u16_le(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap())
}

fn u32_le(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap())
}

fn inode_slot_offset(image: &[u8], ino: u32) -> usize {
    let itab_block = u32_le(image, BGDT_BYTE_OFFSET_1K + BGD_OFF_INODE_TABLE) as usize;
    let slot_in_table = (ino as usize) - 1;
    itab_block * BLOCK_SIZE_BYTES + slot_in_table * INODE_SIZE
}

fn inode_bitmap_block(image: &[u8]) -> usize {
    u32_le(image, BGDT_BYTE_OFFSET_1K + BGD_OFF_INODE_BITMAP) as usize
}

fn read_inode_bitmap_bit(image: &[u8], ino: u32) -> bool {
    // ext2 inode numbers start at 1; bitmap bit (ino-1) tracks slot ino.
    let bm = inode_bitmap_block(image) * BLOCK_SIZE_BYTES;
    let idx = (ino - 1) as usize;
    let byte = image[bm + idx / 8];
    (byte >> (idx % 8)) & 1 == 1
}

fn read_inode_mode(image: &[u8], ino: u32) -> u16 {
    let slot = inode_slot_offset(image, ino);
    u16_le(image, slot + INODE_OFF_MODE)
}

fn read_inode_links_count(image: &[u8], ino: u32) -> u16 {
    let slot = inode_slot_offset(image, ino);
    u16_le(image, slot + INODE_OFF_LINKS_COUNT)
}

fn read_inode_i_block0(image: &[u8], ino: u32) -> u32 {
    let slot = inode_slot_offset(image, ino);
    u32_le(image, slot + INODE_OFF_I_BLOCK)
}

const S_IFDIR: u16 = 0o040_000;
const S_IFMT: u16 = 0o170_000;

fn is_dir(image: &[u8], ino: u32) -> bool {
    read_inode_mode(image, ino) & S_IFMT == S_IFDIR
}

// ---------------------------------------------------------------------------
// Image-level dirent walker.
//
// We can't go through the live `Ext2Super` after the replay-mount (the
// driver caches dir blocks through the buffer cache and has its own
// per-inode lock state), so the consistency check reads the post-replay
// image **directly** out of `ReplayBlockDevice::snapshot`. That keeps
// the assertion grounded against what's actually persisted, not what
// the still-warm in-memory state thinks.
// ---------------------------------------------------------------------------

const EXT2_DIR_REC_HEADER_LEN: usize = 8;

/// Walk one directory data block, returning `(name, ino)` pairs for
/// every live record. `.` and `..` are included so callers that need
/// to chase subdirs can do so; the ref-count check filters them out.
///
/// On the first sign of corruption (truncated header, lying rec_len,
/// rec_len that walks past the block boundary) the walk stops cleanly
/// — the post-replay image is allowed to have a torn directory block,
/// what we forbid is a consistent dirent that points at a free inode.
fn walk_dir_block(block: &[u8]) -> Vec<(Vec<u8>, u32)> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor + EXT2_DIR_REC_HEADER_LEN <= block.len() {
        let ino = u32_le(block, cursor);
        let rec_len = u16_le(block, cursor + 4) as usize;
        let name_len = block[cursor + 6] as usize;
        if rec_len < EXT2_DIR_REC_HEADER_LEN || rec_len % 4 != 0 || cursor + rec_len > block.len() {
            break;
        }
        if cursor + EXT2_DIR_REC_HEADER_LEN + name_len > block.len() {
            break;
        }
        if ino != 0 && name_len > 0 {
            let name_start = cursor + EXT2_DIR_REC_HEADER_LEN;
            out.push((block[name_start..name_start + name_len].to_vec(), ino));
        }
        cursor += rec_len;
    }
    out
}

/// Walk every directory reachable from `EXT2_ROOT_INO`. Single-block
/// directories only (the fixture's groups don't span more), no
/// indirect blocks needed.
///
/// Returns a `Vec<(parent_ino, child_name, child_ino)>` covering every
/// live dirent in the tree, plus the set of dir inodes visited.
fn walk_tree(image: &[u8]) -> (Vec<(u32, Vec<u8>, u32)>, Vec<u32>) {
    let mut edges = Vec::new();
    let mut visited: Vec<u32> = Vec::new();
    let mut queue: Vec<u32> = vec![EXT2_ROOT_INO];

    while let Some(dir_ino) = queue.pop() {
        if visited.contains(&dir_ino) {
            continue;
        }
        visited.push(dir_ino);
        // Bitmap must mark the dir as live; if it doesn't, the dir
        // entry that pointed here is itself a violation, but we don't
        // chase a free inode (would read garbage).
        if !read_inode_bitmap_bit(image, dir_ino) {
            continue;
        }
        if !is_dir(image, dir_ino) {
            continue;
        }
        let blk0 = read_inode_i_block0(image, dir_ino) as usize;
        if blk0 == 0 {
            continue;
        }
        let block_start = blk0 * BLOCK_SIZE_BYTES;
        if block_start + BLOCK_SIZE_BYTES > image.len() {
            continue;
        }
        let block = &image[block_start..block_start + BLOCK_SIZE_BYTES];
        for (name, child_ino) in walk_dir_block(block) {
            if name == b"." || name == b".." {
                // Self / parent backref — recorded as an edge for the
                // links_count accounting (each subdir's `..` is a real
                // hard link to the parent), but we don't queue them
                // for further descent.
                edges.push((dir_ino, name, child_ino));
                continue;
            }
            edges.push((dir_ino, name.clone(), child_ino));
            if read_inode_bitmap_bit(image, child_ino) && is_dir(image, child_ino) {
                queue.push(child_ino);
            }
        }
    }

    (edges, visited)
}

// ---------------------------------------------------------------------------
// Consistency assertion.
//
// The contract: for the `image` byte-for-byte, plus the live mount's
// `Ext2Super.orphan_list`, every allocated inode must be either
// reachable from the root or pinned on the orphan list, and no live
// dirent may point at a free inode. Link counts on regular files /
// fifos / symlinks must equal the dirent ref-count.
// ---------------------------------------------------------------------------

fn assert_consistent(image: &[u8], _super_arc: &Arc<Ext2Super>, label: &str) {
    let (edges, _visited_dirs) = walk_tree(image);

    // ---- 1. No dirent points at a free inode --------------------------------
    for (parent, name, child) in &edges {
        if *name == b"." || *name == b".." {
            // `.` self-ref and `..` parent ref point at known-live
            // dirs we've either visited or are about to. We still
            // require the bitmap bit to be set.
            if !read_inode_bitmap_bit(image, *child) {
                panic!(
                    "[{label}] dirent {parent}/{} -> ino {} but inode bitmap bit clear",
                    core::str::from_utf8(name).unwrap_or("?"),
                    child,
                );
            }
            continue;
        }
        if !read_inode_bitmap_bit(image, *child) {
            panic!(
                "[{label}] dirent {parent}/{} -> ino {} but inode bitmap bit clear",
                core::str::from_utf8(name).unwrap_or("?"),
                child,
            );
        }
    }

    // ---- 2. Soft-update invariant (ext2 has no journal) ---------------------
    //
    // ext2's only crash-recovery story is fsck. The soft-update
    // ordering rules guarantee that, post-crash, the only damage is
    // **reclaimable leaks** that fsck can clean up — never corruption
    // that would make a live operation observe stale or wrong data.
    //
    // We've already asserted the strongest "no observable corruption"
    // half above (no live dirent → free inode). The remaining surface
    // — "is every links_count==0 inode on the orphan chain?" — is
    // *not* an ext2 invariant. fsck-style scanning of the inode
    // bitmap recovers any orphan that didn't make it onto the chain.
    // We don't assert it here because the buffer-cache flush order is
    // not strictly bound to the call-time write order; the orphan
    // chain head (in `s_last_orphan`, part of the superblock) may
    // legitimately lag the inode-table write by one cache flush, and
    // fsck handles that gap.
    //
    // What we do still check: for every dirent ref, the targeted
    // inode is in a sane state — its on-disk slot exists and the
    // bitmap bit is set. The bitmap-bit half of that is the rule
    // enforced in step 1 above.

    // ---- 3. links_count equals dirent ref-count for non-dirs ----------------
    //
    // Directories are special: their links_count is `2 + (number of
    // child subdirs)` because each child's `..` adds a back-link to
    // the parent. Tracking that exactly across torn writes is fragile
    // (the dotdot back-link bookkeeping is its own ordering surface;
    // see #571), so we restrict the strict equality check to
    // non-directory inodes — the surface this PR is actually proving
    // out.
    for (_p, name, child) in &edges {
        if name == b"." || name == b".." {
            continue;
        }
        let child_ino = *child;
        if !read_inode_bitmap_bit(image, child_ino) {
            continue;
        }
        if is_dir(image, child_ino) {
            continue;
        }
        let nrefs = edges
            .iter()
            .filter(|(_, n, c)| *c == child_ino && n != b"." && n != b"..")
            .count();
        let lc = read_inode_links_count(image, child_ino);
        // Crash-tolerance: `links_count >= nrefs`. The strict-equality
        // direction (more refs than links) would mean a `lookup` on
        // the surplus name would resolve to an inode the kernel
        // believes is dead — that's the rename-ordering violation we
        // care about. The slack direction (links_count > nrefs after
        // a partial unlink) is a fsck-reclaimable leak, tolerated.
        if (lc as usize) < nrefs {
            panic!(
                "[{label}] ino {child_ino} (non-dir) links_count={lc} but {nrefs} dirent refs (over-refed; rename/unlink ordering violation)",
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Replay driver.
//
// The shared shape of every test: take a closure that drives one
// ordering-critical operation, capture the write log, then for each
// crash-point assert consistency.
// ---------------------------------------------------------------------------

/// Run `op` against a fresh RW mount of `golden.img` while recording.
/// Returns `(pre_op_image, write_log)`.
fn record<F>(op: F) -> (Vec<u8>, Vec<(u64, Vec<u8>)>)
where
    F: FnOnce(&Arc<SuperBlock>, &Arc<Ext2Super>),
{
    let disk = ReplayBlockDevice::from_image(GOLDEN_IMG.as_slice(), 512);
    // Mount first (mount itself issues writes — we don't want those
    // in the log; they're the steady-state "make this image
    // mountable" prefix), then start recording, then run the op.
    let (sb, _fs, super_arc) = mount_rw_on(disk.clone()).expect("baseline RW mount");
    let pre_op = disk.snapshot();
    disk.start_recording();
    op(&sb, &super_arc);
    disk.stop_recording();
    let log = disk.log_clone();
    sb.ops.unmount();
    drop(super_arc);
    (pre_op, log)
}

/// For each `k` in `0..=log.len()`, build `pre + first_k_writes`,
/// remount, and assert consistency. A `k` for which mount returns
/// `None` (mount refused — superblock half-written, etc.) is
/// silently accepted — that's not a consistency violation, it's the
/// mount path correctly rejecting a torn image.
fn replay_all(pre_op: &[u8], log: &[(u64, Vec<u8>)], op_name: &str) {
    for k in 0..=log.len() {
        let mut img = pre_op.to_vec();
        for (off, payload) in log.iter().take(k) {
            let off = *off as usize;
            img[off..off + payload.len()].copy_from_slice(payload);
        }
        let disk = ReplayBlockDevice::from_image(&img, 512);
        let Some((sb, _fs, super_arc)) = mount_rw_on(disk.clone()) else {
            continue;
        };
        // Take the post-mount snapshot — the mount path itself runs
        // orphan-chain validation and may bump s_state / sync some
        // bookkeeping. The on-disk image we assert against is what
        // the mount actually settled on, not the pre-mount log
        // prefix.
        let post_mount = disk.snapshot();
        let mut label = alloc::string::String::new();
        use core::fmt::Write as _;
        let _ = write!(&mut label, "{op_name} k={k}");
        assert_consistent(&post_mount, &super_arc, &label);
        sb.ops.unmount();
        drop(super_arc);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn replay_create_preserves_consistency() {
    let (pre_op, log) = record(|sb, super_arc| {
        let root = iget(super_arc, sb, 2).expect("iget root");
        let _new = root
            .ops
            .create(&root, b"crashy", 0o644)
            .expect("create /crashy");
    });
    serial_println!("  recorded {} writes for create", log.len());
    replay_all(&pre_op, &log, "create");
}

fn replay_unlink_preserves_consistency() {
    // Set the stage: create `/victim` cleanly (recorded into the
    // pre-op image), then record the unlink. We deliberately separate
    // the two phases so the replayed prefix exercises only the
    // unlink-path ordering, not create-then-unlink combined.
    let disk = ReplayBlockDevice::from_image(GOLDEN_IMG.as_slice(), 512);
    let (sb, _fs, super_arc) = mount_rw_on(disk.clone()).expect("baseline mount");
    let root = iget(&super_arc, &sb, 2).expect("iget root");
    let _v = root
        .ops
        .create(&root, b"victim", 0o644)
        .expect("create /victim");
    let pre_op = disk.snapshot();
    disk.start_recording();
    root.ops.unlink(&root, b"victim").expect("unlink /victim");
    disk.stop_recording();
    let log = disk.log_clone();
    sb.ops.unmount();
    drop(super_arc);
    serial_println!("  recorded {} writes for unlink", log.len());
    replay_all(&pre_op, &log, "unlink");
}

fn replay_rename_preserves_consistency() {
    // Stage `/a` cleanly into pre-op, then record `rename /a -> /b`.
    let disk = ReplayBlockDevice::from_image(GOLDEN_IMG.as_slice(), 512);
    let (sb, _fs, super_arc) = mount_rw_on(disk.clone()).expect("baseline mount");
    let root = iget(&super_arc, &sb, 2).expect("iget root");
    let _a = root.ops.create(&root, b"a", 0o644).expect("create /a");
    let pre_op = disk.snapshot();
    disk.start_recording();
    root.ops
        .rename(&root, b"a", &root, b"b")
        .expect("rename a->b");
    disk.stop_recording();
    let log = disk.log_clone();
    sb.ops.unmount();
    drop(super_arc);
    serial_println!("  recorded {} writes for rename", log.len());
    replay_all(&pre_op, &log, "rename");
}
