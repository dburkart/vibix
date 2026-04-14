//! Integration test for issue #287: verify that the boot-time tarfs mount at `/`
//! is backed by the Limine ramdisk module and that known paths resolve correctly.
//!
//! After `vibix::init()`, `vfs::init::root()` should point to a TarFs root
//! populated from the `rootfs.tar` module declared in `limine.conf`. This test
//! walks `/etc` through the global VFS namespace and verifies it resolves to a
//! directory, exercising the full
//!
//!   boot module → TarFs::mount (MountSource::RamdiskModule) → SuperBlock
//!     → path_walk("/etc") → Inode (Dir)
//!
//! chain end-to-end. The initrd produced by `cargo xtask initrd` contains
//! `etc/` as a directory stub (no files inside), so we assert directory kind
//! rather than reading file content.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use vibix::fs::vfs::path_walk::{path_walk, LookupFlags, NameIdata};
use vibix::fs::vfs::{Credential, GlobalMountResolver, InodeKind};
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

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
    let tests: &[(&str, &dyn Testable)] = &[(
        "rootfs_etc_is_directory",
        &(rootfs_etc_is_directory as fn()),
    )];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

fn rootfs_etc_is_directory() {
    let root =
        vibix::fs::vfs::root().expect("rootfs_module: vfs root not populated after vibix::init()");

    let mut nd = NameIdata::new(
        root.clone(),
        root,
        Credential::kernel(),
        LookupFlags::default(),
    )
    .expect("rootfs_module: seed namei");

    path_walk(&mut nd, b"/etc", &GlobalMountResolver).expect("rootfs_module: path_walk /etc");

    let etc_inode = nd.path.inode.clone();
    if etc_inode.kind != InodeKind::Dir {
        panic!(
            "rootfs_module: /etc must be a directory, got kind={:?}",
            etc_inode.kind
        );
    }
}
