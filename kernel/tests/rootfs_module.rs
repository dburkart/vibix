//! Integration test for issue #287: verify that the boot-time tarfs mount at `/`
//! is backed by the Limine ramdisk module and that known paths resolve correctly.
//!
//! After `vibix::init()`, `vfs::init::root()` should point to a TarFs root
//! populated from the `rootfs.tar` module declared in `limine.conf`. This test
//! walks `/etc` through the global VFS namespace and verifies it resolves to a
//! directory, then opens `/etc/hostname` and reads back the payload bytes —
//! proving the tar file content survives end-to-end through the full
//!
//!   boot module → TarFs::mount (MountSource::RamdiskModule) → SuperBlock
//!     → path_walk("/etc/hostname") → Inode (Reg) → FileOps::read → bytes
//!
//! chain.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use vibix::fs::vfs::open_file::OpenFile;
use vibix::fs::vfs::path_walk::{path_walk, LookupFlags, NameIdata};
use vibix::fs::vfs::super_block::SbActiveGuard;
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
    let tests: &[(&str, &dyn Testable)] = &[
        (
            "rootfs_etc_is_directory",
            &(rootfs_etc_is_directory as fn()),
        ),
        (
            "rootfs_etc_hostname_content",
            &(rootfs_etc_hostname_content as fn()),
        ),
    ];
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

fn rootfs_etc_hostname_content() {
    let root =
        vibix::fs::vfs::root().expect("rootfs_module: vfs root not populated after vibix::init()");

    let mut nd = NameIdata::new(
        root.clone(),
        root,
        Credential::kernel(),
        LookupFlags::default(),
    )
    .expect("rootfs_module: seed namei");

    path_walk(&mut nd, b"/etc/hostname", &GlobalMountResolver)
        .expect("rootfs_module: path_walk /etc/hostname");

    let hostname_dentry = nd.path.dentry.clone();
    let hostname_inode = nd.path.inode.clone();
    if hostname_inode.kind != InodeKind::Reg {
        panic!(
            "rootfs_module: /etc/hostname must be a regular file, got kind={:?}",
            hostname_inode.kind
        );
    }

    let sb = hostname_inode
        .sb
        .upgrade()
        .expect("rootfs_module: /etc/hostname superblock still live");
    let guard = SbActiveGuard::try_acquire(&sb).expect("rootfs_module: sb_active guard");
    let of = OpenFile::new(
        hostname_dentry,
        hostname_inode.clone(),
        hostname_inode.file_ops.clone(),
        sb.clone(),
        0,
        guard,
    );

    const EXPECTED: &[u8] = b"vibix\n";
    let mut buf = [0u8; 16];
    let n = hostname_inode
        .file_ops
        .read(&of, &mut buf, 0)
        .expect("rootfs_module: FileOps::read /etc/hostname");
    if n != EXPECTED.len() || &buf[..n] != EXPECTED {
        panic!(
            "rootfs_module: /etc/hostname content mismatch; expected {:?} got n={n} bytes={:?}",
            EXPECTED,
            &buf[..core::cmp::min(n, buf.len())]
        );
    }
}
