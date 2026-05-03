//! Integration test for issue #753: ext2 [`FileOps::mmap`] returning an
//! `Arc<FileObject>` against the inode's lazily-constructed
//! `PageCache`.
//!
//! Mounts the existing `read_test.img` fixture (small / large /
//! sparse pre-populated inodes — see
//! `kernel/src/fs/ext2/fixtures/README.md`) and drives the mmap hook
//! end-to-end:
//!
//! - **MAP_PRIVATE smoke** — `FileOps::mmap` on a regular file inode
//!   returns an `Arc<dyn VmObject>` bound to the inode's installed
//!   `PageCache`. The lazy-construct path is exercised on the very
//!   first call (no prior `mapping` install), then a second call
//!   returns a `FileObject` against the **same** `Arc<PageCache>`
//!   (RFC 0007 §Inode-binding rule).
//! - **MAP_PRIVATE read fault → readpage** — a `Read` fault on the
//!   returned object's offset 0 walks through `Ext2Aops::readpage`,
//!   loads page 0 of `small.bin` into the cache, and returns the
//!   physical frame the resolver would install. Subsequent
//!   `frame_at(0)` reflects the same frame; the cache has the page
//!   resident (`lookup(0).is_some()`).
//! - **`open_mode` snapshot** — RFC 0007 §FileObject `open_mode`
//!   snapshot. The `OpenFile.flags & O_ACCMODE` value is captured
//!   verbatim into the returned `FileObject` and is observable via
//!   the `FileObject::open_mode` accessor (closing Security B1's
//!   TOCTOU surface).
//! - **`file_offset_pages` window** — when the caller asks for a
//!   non-zero file offset, the returned object's faults route through
//!   the matching cache page index (not page 0).
//! - **Non-regular kinds reject** — `FileOps::mmap` on a directory
//!   inode (root, ino 2) returns `ENODEV` per the trait default
//!   contract for non-mmappable file types.
//!
//! `MAP_SHARED` writeback (`Ext2Aops::writepage`) is gated on issue
//! #750, in flight in a sibling PR; this test sticks to MAP_PRIVATE
//! reads, which exercise every code path on the cache-fill side
//! without depending on that work.
//!
//! The test mounts RO so the fixture stays byte-identical across
//! runs.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;

use vibix::block::BlockDevice;
use vibix::fs::ext2::{iget, Ext2Fs, Ext2Super};
use vibix::fs::vfs::dentry::Dentry;
use vibix::fs::vfs::open_file::OpenFile;
use vibix::fs::vfs::ops::{FileSystem as _, MountSource};
use vibix::fs::vfs::super_block::{SbActiveGuard, SuperBlock};
use vibix::fs::vfs::MountFlags;
use vibix::fs::{flags as fs_flags, ENODEV};
use vibix::mem::file_object::FileObject;
use vibix::mem::vmatree::Share;
use vibix::mem::vmobject::{Access, VmObject};
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

const READ_IMG: &[u8; 1_048_576] = include_bytes!("../src/fs/ext2/fixtures/read_test.img");

// Inos pre-assigned by the deterministic `mkfs.ext2` invocation that
// generates `read_test.img` — see `fixtures/README.md` and the
// matching constants in `ext2_readpage.rs` / `ext2_file_read.rs`.
const INO_SMALL: u32 = 12;

// `small.bin` is 26 bytes — fits in page 0. The byte content itself
// is asserted by the readpage integration test (`ext2_readpage.rs`);
// here we only need the size + the inode number.

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
            "mmap_returns_file_object_against_lazy_page_cache",
            &(mmap_returns_file_object_against_lazy_page_cache as fn()),
        ),
        (
            "mmap_read_fault_routes_through_readpage",
            &(mmap_read_fault_routes_through_readpage as fn()),
        ),
        (
            "mmap_snapshots_open_mode_into_file_object",
            &(mmap_snapshots_open_mode_into_file_object as fn()),
        ),
        (
            "mmap_file_offset_pages_window_is_honoured",
            &(mmap_file_offset_pages_window_is_honoured as fn()),
        ),
        (
            "mmap_on_directory_returns_enodev",
            &(mmap_on_directory_returns_enodev as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// Shared `RamDisk` — see kernel/tests/common/ext2_ramdisk.rs (issues
// #627, #658).
#[path = "common/ext2_ramdisk.rs"]
mod ext2_ramdisk;
use ext2_ramdisk::RamDisk;

/// Mount `read_test.img` RO. Returns the `SuperBlock`, the `Ext2Fs`
/// factory (kept alive so the per-mount state isn't torn down between
/// the mount and the test body), and the per-mount `Ext2Super`.
fn mount_ro() -> (Arc<SuperBlock>, Arc<Ext2Fs>, Arc<Ext2Super>) {
    let disk = RamDisk::from_image(READ_IMG.as_slice(), 512);
    let fs = Ext2Fs::new_with_device(disk as Arc<dyn BlockDevice>);
    let sb = fs
        .mount(MountSource::None, MountFlags::RDONLY)
        .expect("RO mount of read_test.img must succeed");
    let super_arc = fs
        .current_super()
        .expect("current_super must upgrade after mount");
    (sb, fs, super_arc)
}

/// Build an `Arc<OpenFile>` against `inode` with the given access-mode
/// flags. Mirrors the construction sites in `ext2_orphan_open_close.rs`
/// and the `vfs_hello` test — `Dentry::new_root` for the root
/// dentry hand-off, `SbActiveGuard::try_acquire` for the syscall-scope
/// pin that `OpenFile::new` migrates into `dentry_pin_count`.
fn build_open_file(
    sb: &Arc<SuperBlock>,
    inode: &Arc<vibix::fs::vfs::inode::Inode>,
    flags: u32,
) -> Arc<OpenFile> {
    let dentry = Dentry::new_root(inode.clone());
    let guard = SbActiveGuard::try_acquire(sb).expect("SbActiveGuard");
    OpenFile::new(
        dentry,
        inode.clone(),
        inode.file_ops.clone(),
        sb.clone(),
        flags,
        guard,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// First-call `FileOps::mmap` on a regular file lazily constructs the
/// inode's `PageCache` and binds it into the returned `FileObject`. A
/// second call observes the **same** `Arc<PageCache>` (install-once
/// invariant per RFC 0007 §Inode-binding rule).
fn mmap_returns_file_object_against_lazy_page_cache() {
    let (sb, _fs, super_arc) = mount_ro();
    let inode = iget(&super_arc, &sb, INO_SMALL).expect("iget small.bin");
    // Pre-condition: the page cache has not been instantiated yet.
    assert!(
        inode.mapping.read().is_none(),
        "fresh iget must not pre-instantiate the page cache",
    );

    let of = build_open_file(&sb, &inode, fs_flags::O_RDONLY);

    // First mmap call: lazy-constructs the cache.
    let obj1 = of
        .ops
        .mmap(&of, 0, 1, Share::Private, 0)
        .expect("mmap MAP_PRIVATE 1 page must succeed");
    assert!(
        inode.mapping.read().is_some(),
        "FileOps::mmap must install the inode's PageCache on first call",
    );
    let cache_first = inode
        .mapping
        .read()
        .as_ref()
        .map(Arc::clone)
        .expect("mapping populated after mmap");

    // Second mmap call: must reuse the same cache.
    let obj2 = of
        .ops
        .mmap(&of, 0, 1, Share::Private, 0)
        .expect("second mmap call must succeed");
    let cache_second = inode
        .mapping
        .read()
        .as_ref()
        .map(Arc::clone)
        .expect("mapping populated");
    assert!(
        Arc::ptr_eq(&cache_first, &cache_second),
        "Inode-binding rule: mapping is install-once per inode",
    );

    // Both returned objects expose the same single-page window.
    assert_eq!(obj1.len_pages(), Some(1));
    assert_eq!(obj2.len_pages(), Some(1));

    drop(of);
    drop(inode);
    sb.ops.unmount();
    drop(super_arc);
}

/// A `Read` fault on the returned `FileObject` walks through
/// `Ext2Aops::readpage` (workstream-C #749 surface) and lands the
/// requested file page in the inode's cache. Smoke MAP_PRIVATE + read
/// is the gate test #753 specifies.
fn mmap_read_fault_routes_through_readpage() {
    let (sb, _fs, super_arc) = mount_ro();
    let inode = iget(&super_arc, &sb, INO_SMALL).expect("iget small.bin");
    let of = build_open_file(&sb, &inode, fs_flags::O_RDONLY);

    let obj = of
        .ops
        .mmap(&of, 0, 1, Share::Private, 0)
        .expect("mmap small.bin page 0 MAP_PRIVATE");

    // Pre-fault: cache is empty for pgoff 0.
    let cache = inode
        .mapping
        .read()
        .as_ref()
        .map(Arc::clone)
        .expect("mapping installed by mmap");
    assert!(
        cache.lookup(0).is_none(),
        "cache must be empty before the first fault",
    );

    // Drive a Read fault at VMA-local offset 0. The slow path enters
    // `Ext2Aops::readpage`, which copies the file's first 26 bytes
    // followed by tail-zero padding into the freshly allocated frame
    // and publishes PG_UPTODATE.
    let phys = obj
        .fault(0, Access::Read)
        .expect("Read fault on page 0 must resolve through readpage");
    assert!(phys != 0, "resolved frame must be non-zero");

    // Cache now has the page resident. `frame_at(0)` mirrors the
    // resolver's view: same `phys`, page is UPTODATE.
    let resident = cache.lookup(0).expect("page 0 must be resident post-fault");
    assert_eq!(resident.phys, phys);
    assert_eq!(obj.frame_at(0), Some(phys));

    // Tail-zero invariant from RFC 0007 §Tail-page zeroing — assert
    // that the cache page actually contains the small.bin bytes
    // followed by tail zero. We can't peek inside the frame portably
    // here (host vs target divergence), so the readpage `ext2_readpage`
    // test pins those byte values; this test gates the dispatch.

    // A second Read fault on the same page is a fast-path cache hit
    // and resolves to the same physical frame.
    let phys2 = obj
        .fault(0, Access::Read)
        .expect("second Read fault must hit fast path");
    assert_eq!(phys, phys2, "fast-path hit returns the same frame");

    drop(obj);
    drop(of);
    drop(inode);
    sb.ops.unmount();
    drop(super_arc);
}

/// RFC 0007 §FileObject `open_mode` snapshot — the FileObject's
/// `open_mode` accessor reflects the OpenFile's `flags & O_ACCMODE` at
/// the moment of mmap. Closes Security B1's TOCTOU surface (a future
/// `mprotect` call consults the snapshot, not the live OpenFile).
fn mmap_snapshots_open_mode_into_file_object() {
    let (sb, _fs, super_arc) = mount_ro();
    let inode = iget(&super_arc, &sb, INO_SMALL).expect("iget small.bin");

    // O_RDONLY (0) snapshot.
    let of_ro = build_open_file(&sb, &inode, fs_flags::O_RDONLY);
    let obj_ro = of_ro
        .ops
        .mmap(&of_ro, 0, 1, Share::Private, 0)
        .expect("mmap RDONLY");
    let fo_ro = downcast_to_file_object(&obj_ro);
    assert_eq!(
        fo_ro.open_mode(),
        fs_flags::O_RDONLY,
        "RDONLY OpenFile snapshots open_mode = O_RDONLY"
    );

    // O_RDWR (2) snapshot — even on an RO mount the access-mode bits
    // are echoed verbatim; sys_mmap is the layer that vetoes
    // RDWR-against-RO before the hook fires (#746).
    let of_rw = build_open_file(&sb, &inode, fs_flags::O_RDWR);
    let obj_rw = of_rw
        .ops
        .mmap(&of_rw, 0, 1, Share::Private, 0)
        .expect("mmap RDWR snapshot");
    let fo_rw = downcast_to_file_object(&obj_rw);
    assert_eq!(
        fo_rw.open_mode(),
        fs_flags::O_RDWR,
        "RDWR OpenFile snapshots open_mode = O_RDWR"
    );

    // O_WRONLY (1) snapshot.
    let of_wo = build_open_file(&sb, &inode, fs_flags::O_WRONLY);
    let obj_wo = of_wo
        .ops
        .mmap(&of_wo, 0, 1, Share::Private, 0)
        .expect("mmap WRONLY snapshot");
    let fo_wo = downcast_to_file_object(&obj_wo);
    assert_eq!(
        fo_wo.open_mode(),
        fs_flags::O_WRONLY,
        "WRONLY OpenFile snapshots open_mode = O_WRONLY"
    );

    // The snapshot is masked with O_ACCMODE — auxiliary bits like
    // O_CLOEXEC / O_APPEND must not bleed through.
    let extra = fs_flags::O_RDWR | fs_flags::O_CLOEXEC | fs_flags::O_APPEND;
    let of_extra = build_open_file(&sb, &inode, extra);
    let obj_extra = of_extra
        .ops
        .mmap(&of_extra, 0, 1, Share::Private, 0)
        .expect("mmap with auxiliary flags");
    let fo_extra = downcast_to_file_object(&obj_extra);
    assert_eq!(
        fo_extra.open_mode(),
        fs_flags::O_RDWR,
        "auxiliary OpenFile flags must be masked off the snapshot",
    );

    drop(obj_ro);
    drop(obj_rw);
    drop(obj_wo);
    drop(obj_extra);
    drop(of_ro);
    drop(of_rw);
    drop(of_wo);
    drop(of_extra);
    drop(inode);
    sb.ops.unmount();
    drop(super_arc);
}

/// A non-zero `file_offset` is honoured: the returned FileObject
/// dispatches faults to `pgoff = file_offset/4096 + vma_local_idx`,
/// not page 0. We exercise this against the indirect-page boundary
/// (page 3 of `large.bin`); fault-at-vma-local-0 must drive readpage
/// for pgoff 3, not 0.
fn mmap_file_offset_pages_window_is_honoured() {
    // INO_LARGE = 13 (large.bin, see `read_test.img`).
    const INO_LARGE: u32 = 13;
    let (sb, _fs, super_arc) = mount_ro();
    let inode = iget(&super_arc, &sb, INO_LARGE).expect("iget large.bin");
    let of = build_open_file(&sb, &inode, fs_flags::O_RDONLY);

    let obj = of
        .ops
        .mmap(
            &of,
            3 * 4096, /* file_offset = page 3 in bytes */
            1,        /* one page */
            Share::Private,
            0,
        )
        .expect("mmap page 3 of large.bin");

    let cache = inode
        .mapping
        .read()
        .as_ref()
        .map(Arc::clone)
        .expect("mapping installed by mmap");
    // VMA-local offset 0 must map to file pgoff 3 — not pgoff 0.
    let _ = obj
        .fault(0, Access::Read)
        .expect("Read fault on VMA-local offset 0 must resolve");
    assert!(
        cache.lookup(3).is_some(),
        "fault at VMA-local 0 with file_offset=3 must populate pgoff 3",
    );
    assert!(
        cache.lookup(0).is_none(),
        "pgoff 0 must remain absent — the window starts at file_offset_pages=3",
    );

    drop(obj);
    drop(of);
    drop(inode);
    sb.ops.unmount();
    drop(super_arc);
}

/// `FileOps::mmap` on a directory inode returns `ENODEV` (the same
/// errno the trait default produces for non-mmappable file types). The
/// driver's impl rejects every kind that isn't `Reg` up-front so the
/// page cache is not lazily instantiated for a non-mappable inode.
fn mmap_on_directory_returns_enodev() {
    let (sb, _fs, super_arc) = mount_ro();
    // ino 2 = root directory on every ext2 image.
    let dir = iget(&super_arc, &sb, 2).expect("iget root dir");
    let of = build_open_file(&sb, &dir, fs_flags::O_RDONLY);

    let r = of.ops.mmap(&of, 0, 1, Share::Private, 0);
    assert_eq!(
        r.err(),
        Some(ENODEV),
        "mmap on directory must return ENODEV"
    );
    // The directory's mapping slot must not have been instantiated.
    assert!(
        dir.mapping.read().is_none(),
        "ENODEV path must not lazily build a PageCache for non-Reg inodes",
    );

    drop(of);
    drop(dir);
    sb.ops.unmount();
    drop(super_arc);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Recover an `&FileObject` from the `Arc<dyn VmObject>` the mmap hook
/// returns. The trait object's vtable does not expose `open_mode`, so
/// this test reaches under by `Arc::as_ptr` and a static cast — we
/// know the concrete type is `FileObject` because that is the only
/// type the ext2 mmap impl ever constructs.
fn downcast_to_file_object<'a>(obj: &'a Arc<dyn VmObject>) -> &'a FileObject {
    // SAFETY: the ext2 `FileOps::mmap` impl constructs exactly one
    // concrete type — `Arc<FileObject>` — and casts it to
    // `Arc<dyn VmObject>` at the return statement. Reversing that
    // erasure is sound here because the test owns the construction
    // site too: only this test can build the Arc, and only this
    // helper unwraps it. The lifetime is tied to `obj` so the
    // concrete reference cannot outlive the Arc.
    let ptr = Arc::as_ptr(obj) as *const FileObject;
    unsafe { &*ptr }
}
