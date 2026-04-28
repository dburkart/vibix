//! Integration test for issue #559: `Ext2Inode` + `iget` + inode cache.
//!
//! Runs the real kernel under QEMU, in-process: builds an in-memory
//! `BlockDevice` (a `RamDisk` wrapping the 64 KiB `mkfs.ext2` golden
//! image), mounts it through `Ext2Fs::new_with_device`, and drives
//! `iget` against:
//!
//! - **ino 2** — the root directory. Decoded `Stat` carries `S_IFDIR`
//!   (`st_mode & S_IFMT == 0o40000`), `st_nlink == 3` (matches
//!   `mkfs.ext2`'s `. + .. + lost+found/..` count), `st_size ==
//!   block_size`, and `st_blocks == 2` (one 1 KiB data block).
//! - **ino 11** — `lost+found`, the only other live inode on the
//!   fresh image. Decoded `Stat` carries `S_IFDIR` too; the real
//!   regression the test pins is "iget of a non-root inode works"
//!   (catches an off-by-one in the per-group arithmetic).
//! - **Cache identity**: two `iget(ino=2)` calls return `Arc<Inode>`
//!   pointing at the same allocation (`Arc::ptr_eq`). A third call
//!   after the first two Arcs drop also returns an Arc, though not
//!   necessarily `ptr_eq` with the earlier one — the `Weak` in the
//!   cache upgrades to `None` once every `Arc<Inode>` is gone, and
//!   the next `iget` reads fresh from disk.
//! - **Bounds**: `iget(0)` → `EINVAL`; `iget(u32::MAX)` → `EINVAL`.
//! - **Orphan list is empty** at mount time (no unlinked-but-open
//!   inodes on a just-mounted image). Catches a regression where the
//!   field was leaked from a prior mount (the `Arc<Ext2Super>` is
//!   fresh per mount, but a sloppy constructor could share static state).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;

use vibix::block::BlockDevice;
use vibix::fs::ext2::{iget, Ext2Fs};
use vibix::fs::vfs::ops::{FileSystem as _, MountSource, Stat};
use vibix::fs::vfs::MountFlags;
use vibix::fs::EINVAL;
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
            "iget_root_inode_populates_stat",
            &(iget_root_populates_stat as fn()),
        ),
        ("iget_lost_found_inode", &(iget_lost_found_inode as fn())),
        (
            "iget_cache_returns_same_arc",
            &(iget_cache_returns_same_arc as fn()),
        ),
        (
            "iget_rejects_zero_and_out_of_range",
            &(iget_rejects_zero_and_out_of_range as fn()),
        ),
        (
            "orphan_list_empty_at_mount",
            &(orphan_list_empty_at_mount as fn()),
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

/// Mount the golden image RO and hand back `(Arc<SuperBlock>, Arc<Ext2Super>)`.
/// RO mount because the tests only exercise the read path and don't
/// want the side-effect of `s_state := ERROR_FS` on the shared fixture.
fn mount_golden_ro() -> (
    Arc<vibix::fs::vfs::super_block::SuperBlock>,
    Arc<vibix::fs::ext2::Ext2Fs>,
    Arc<vibix::fs::ext2::Ext2Super>,
) {
    let disk = RamDisk::from_image(GOLDEN_IMG.as_slice(), 512);
    let fs = Ext2Fs::new_with_device(disk as Arc<dyn BlockDevice>);
    let sb = fs
        .mount(MountSource::None, MountFlags::RDONLY)
        .expect("RO mount must succeed");
    let super_arc = fs
        .current_super()
        .expect("Ext2Fs::current_super must upgrade after a successful mount");
    (sb, fs, super_arc)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn iget_root_populates_stat() {
    let (sb, _fs, super_arc) = mount_golden_ro();

    // The root inode is populated by `mount` via `iget_root`.
    let root = sb
        .root
        .get()
        .expect("root inode must be populated at mount");
    assert_eq!(root.ino, 2);

    let mut st = Stat::default();
    root.ops
        .getattr(&root, &mut st)
        .expect("getattr on root inode must succeed");

    // S_IFDIR + rwxr-xr-x = 0o40755 on mkfs.ext2's root.
    assert_eq!(
        st.st_mode & 0o170_000,
        0o040_000,
        "root must be a directory"
    );
    assert_eq!(st.st_mode & 0o7_777, 0o755, "mkfs.ext2 stamps 755 on root");
    assert_eq!(st.st_uid, 0);
    assert_eq!(st.st_gid, 0);
    assert_eq!(st.st_ino, 2);
    assert_eq!(st.st_size, 1024, "root dir block on 1 KiB fs");
    // i_blocks = 2 (one 1 KiB data block, 512-byte units).
    assert_eq!(st.st_blocks, 2);
    // nlink: 3 on the 64 KiB fixture (., .., and the ..-from-lost+found).
    assert_eq!(st.st_nlink, 3);
    assert_eq!(st.st_blksize, 1024);

    sb.ops.unmount();
    drop(super_arc);
}

fn iget_lost_found_inode() {
    let (sb, _fs, super_arc) = mount_golden_ro();

    // ino 11 = lost+found on a fresh mkfs.ext2 image. Non-root ino
    // exercises the per-group + block-in-table arithmetic.
    let lf = iget(&super_arc, &sb, 11).expect("iget(lost+found) must succeed");
    assert_eq!(lf.ino, 11);

    let mut st = Stat::default();
    lf.ops
        .getattr(&lf, &mut st)
        .expect("getattr(lost+found) must succeed");
    assert_eq!(st.st_mode & 0o170_000, 0o040_000, "lost+found is a dir");
    assert_eq!(st.st_ino, 11);
    // nlink: lost+found has `.` + back-ref from root → 2 on mkfs.
    assert_eq!(st.st_nlink, 2);

    sb.ops.unmount();
    drop(super_arc);
}

fn iget_cache_returns_same_arc() {
    let (sb, _fs, super_arc) = mount_golden_ro();

    // Two iget calls with the Arc<Inode> still live must return the
    // same allocation — the `Weak` in the cache upgrades through the
    // first strong ref.
    let a = iget(&super_arc, &sb, 2).expect("first iget(root)");
    let b = iget(&super_arc, &sb, 2).expect("second iget(root)");
    assert!(
        Arc::ptr_eq(&a, &b),
        "iget of the same ino must return the same Arc while one is live",
    );
    // Distinct inos → distinct Arcs.
    let lf = iget(&super_arc, &sb, 11).expect("iget(11)");
    assert!(!Arc::ptr_eq(&a, &lf));

    drop(a);
    drop(b);
    drop(lf);

    sb.ops.unmount();
    drop(super_arc);
}

fn iget_rejects_zero_and_out_of_range() {
    let (sb, _fs, super_arc) = mount_golden_ro();

    assert_eq!(
        iget(&super_arc, &sb, 0).err(),
        Some(EINVAL),
        "ino 0 is the tombstone sentinel and must be refused",
    );
    // 64 KiB image with `-N 16` → s_inodes_count = 16. Anything above
    // that is out of range.
    assert_eq!(
        iget(&super_arc, &sb, u32::MAX).err(),
        Some(EINVAL),
        "ino > s_inodes_count must be refused",
    );
    assert_eq!(
        iget(&super_arc, &sb, 1_000).err(),
        Some(EINVAL),
        "ino beyond s_inodes_count (16) must be EINVAL",
    );

    sb.ops.unmount();
    drop(super_arc);
}

fn orphan_list_empty_at_mount() {
    let (sb, _fs, super_arc) = mount_golden_ro();
    // A freshly-mounted, cleanly-unmounted image has no orphans on
    // `s_last_orphan`. Wave 2 constructs the list empty; the on-mount
    // replay (#564) populates it, and wave 2 omits that pass.
    assert!(
        super_arc.orphan_list.lock().is_empty(),
        "fresh mount must have empty orphan_list",
    );
    sb.ops.unmount();
    drop(super_arc);
}
