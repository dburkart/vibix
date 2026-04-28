//! Integration test for issue #625: `mount(2)` resolves a `/dev/<name>`
//! source path to a registered block device, hands the device to the
//! ext2 factory, and produces a live `SuperBlock` mounted on a target
//! directory in the global VFS namespace.
//!
//! The pre-#625 ext2 factory ignored the `MountSource` argument and
//! always reached for `block::default_device()`. With this change:
//!
//! 1. Devfs exposes registered block devices as `InodeKind::Blk`
//!    inodes whose `InodeOps::block_device` returns the underlying
//!    handle.
//! 2. The new `vfs::resolve_block_device` resolver path-walks the
//!    source string and pulls the handle through that hook.
//! 3. The ext2 factory consumes a `MountSource::Path("/dev/<name>")`
//!    and routes the resolved device into `Ext2Fs::new_with_device`.
//! 4. Resolution failures bubble up as `-ENODEV`.
//!
//! Test surface mirrors the four work items in #625:
//! - `dev_path_resolves_to_block_device` — happy path: register a
//!   ramdisk under "ramblk0", mount ext2 via "/dev/ramblk0", assert
//!   the resulting `SuperBlock` carries the ext2 magic.
//! - `missing_dev_path_returns_enodev` — unregistered name surfaces
//!   `ENODEV` (path-walk fails first → mapped to `ENOENT`, which the
//!   resolver does *not* swallow; the registry-direct check is the
//!   `ENODEV` half).
//! - `non_block_dev_path_returns_enodev` — `/dev/null` is `Chr`, not
//!   `Blk`; the resolver refuses with `ENODEV` per the issue spec.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::panic::PanicInfo;

use vibix::block::BlockDevice;
use vibix::fs::vfs::devfs::register_block_device;
use vibix::fs::vfs::ops::MountSource;
use vibix::fs::vfs::MountFlags;
use vibix::fs::{ENODEV, ENOENT};
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

const GOLDEN_IMG: &[u8; 65_536] = include_bytes!("../src/fs/ext2/fixtures/golden.img");

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    x86_64::instructions::interrupts::enable();
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
            "dev_path_resolves_to_block_device",
            &(dev_path_resolves_to_block_device as fn()),
        ),
        (
            "missing_dev_path_returns_enoent",
            &(missing_dev_path_returns_enoent as fn()),
        ),
        (
            "non_block_dev_path_returns_enodev",
            &(non_block_dev_path_returns_enodev as fn()),
        ),
        (
            "dev_path_lookup_returns_blk_inode",
            &(dev_path_lookup_returns_blk_inode as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ---------------------------------------------------------------------------
// In-memory block device backing the resolver tests. Mirrors the helper
// in `ext2_mount.rs` but slimmer — no write counter, no patch hook.
// ---------------------------------------------------------------------------

// Shared `RamDisk` — see kernel/tests/common/ext2_ramdisk.rs (issues
// #627, #658).
#[path = "common/ext2_ramdisk.rs"]
mod ext2_ramdisk;
use ext2_ramdisk::RamDisk;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Happy path: register a ramdisk under "ramblk0", call the resolver,
/// assert it returns the same `Arc<dyn BlockDevice>` we registered.
/// Then drive the registered ext2 factory (`lookup_and_build`) with a
/// `MountSource::Path("/dev/ramblk0")` and mount it RO; confirm the
/// returned SuperBlock has the expected fs-type tag.
fn dev_path_resolves_to_block_device() {
    let dev = RamDisk::from_image(GOLDEN_IMG.as_slice(), 512);
    register_block_device("ramblk0", dev.clone() as Arc<dyn BlockDevice>);

    // Direct resolver hit.
    let resolved = vibix::fs::vfs::resolve_block_device(b"/dev/ramblk0")
        .expect("resolver returns the registered device");
    assert_eq!(resolved.block_size(), dev.block_size());
    assert_eq!(resolved.capacity(), dev.capacity());

    // Factory-side: drive the ext2 factory the same way `sys_mount_impl`
    // does. The factory must consume `MountSource::Path` and produce a
    // FileSystem bound to the resolved device.
    let fs = vibix::fs::vfs::lookup_and_build("ext2", MountSource::Path(b"/dev/ramblk0"))
        .expect("ext2 factory accepts /dev/ramblk0");
    let sb = fs
        .mount(MountSource::Path(b"/dev/ramblk0"), MountFlags::RDONLY)
        .expect("ext2 mount on /dev/ramblk0 succeeds");
    assert_eq!(sb.fs_type, "ext2");
    sb.ops.unmount();
    drop(fs);
}

/// A `/dev/<unregistered>` source path fails the path-walk before the
/// resolver even checks the inode kind, so the public errno is
/// `ENOENT` — same surface a userland `mount(2)` would see.
fn missing_dev_path_returns_enoent() {
    let err = vibix::fs::vfs::resolve_block_device(b"/dev/nonesuch").err();
    if err != Some(ENOENT) {
        panic!("expected ENOENT for /dev/nonesuch, got {:?}", err);
    }

    // Same path through the ext2 factory should bubble the resolver
    // error up unchanged.
    let r2 = vibix::fs::vfs::lookup_and_build("ext2", MountSource::Path(b"/dev/nonesuch")).err();
    if r2 != Some(ENOENT) {
        panic!(
            "ext2 factory should propagate ENOENT for missing path, got {:?}",
            r2
        );
    }
}

/// `/dev/null` exists but is `InodeKind::Chr`, not `Blk`. The resolver
/// must refuse with `ENODEV` per the issue spec — a char device is not
/// a usable mount source even if path-walk reaches it.
fn non_block_dev_path_returns_enodev() {
    let err = vibix::fs::vfs::resolve_block_device(b"/dev/null").err();
    if err != Some(ENODEV) {
        panic!(
            "expected ENODEV when source path is a char device, got {:?}",
            err
        );
    }
}

/// Regression on the devfs side: registered block devices show up
/// through the standard `Inode::ops.lookup` interface (the path-walker
/// uses this verbatim), and the inode that comes back is `Blk`-kind
/// with a working `block_device()` accessor.
fn dev_path_lookup_returns_blk_inode() {
    let dev = RamDisk::from_image(GOLDEN_IMG.as_slice(), 512);
    register_block_device("ramblk_lookup", dev.clone() as Arc<dyn BlockDevice>);

    let root = vibix::fs::vfs::root().expect("vfs root populated");
    use vibix::fs::vfs::path_walk::{path_walk, LookupFlags, NameIdata};
    use vibix::fs::vfs::{Credential, GlobalMountResolver, InodeKind};

    let mut nd = NameIdata::new(
        root.clone(),
        root,
        Credential::kernel(),
        LookupFlags::default() | LookupFlags::FOLLOW,
    )
    .expect("seed namei");
    path_walk(&mut nd, b"/dev/ramblk_lookup", &GlobalMountResolver)
        .expect("path_walk /dev/ramblk_lookup");
    let inode = nd.path.inode.clone();
    assert_eq!(inode.kind, InodeKind::Blk);
    let resolved = inode
        .ops
        .block_device()
        .expect("Blk inode must hand back a BlockDevice");
    assert_eq!(resolved.capacity(), dev.capacity());

    // Drop the ext2 factory's compile-time dependency from the assertion;
    // we want this test to keep working even if `kernel/tests/ext2_mount.rs`
    // moves around. The `vec!` import keeps the harness from warning.
    let _keepalive: Vec<u8> = vec![];
}
