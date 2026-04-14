//! Integration test for issue #241: end-to-end read of `/hello`
//! through the VFS.
//!
//! Proves the full read-path works under QEMU:
//!
//!   TarFs::mount → SuperBlock → root Dentry → path_walk("/hello")
//!     → Inode (Reg) → FileOps::read → bytes
//!
//! The archive is synthesised in the test (~40 LOC) and mounted via
//! `MountSource::Static`, which exercises the same parse / Inode /
//! Dentry / FileOps chain as the production `MountSource::RamdiskModule`
//! path — the latter differs only in where the byte pointer comes
//! from and is covered by the boot-time mount in `vfs::init` (#240).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::panic::PanicInfo;

use vibix::fs::vfs::dentry::Dentry;
use vibix::fs::vfs::open_file::OpenFile;
use vibix::fs::vfs::ops::{FileSystem, MountSource};
use vibix::fs::vfs::path_walk::{path_walk, LookupFlags, NameIdata, NullMountResolver};
use vibix::fs::vfs::super_block::SbActiveGuard;
use vibix::fs::vfs::{Credential, MountFlags, TarFs};
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
    let tests: &[(&str, &dyn Testable)] =
        &[("hello_read_through_vfs", &(hello_read_through_vfs as fn()))];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ---------------------------------------------------------------------------
// USTAR archive builder — minimal subset sufficient for one regular file.
// ---------------------------------------------------------------------------

const BLOCK: usize = 512;

fn write_octal(out: &mut [u8], mut v: u64, digits: usize) {
    for i in (0..digits).rev() {
        out[i] = b'0' + (v & 0o7) as u8;
        v >>= 3;
    }
    if out.len() > digits {
        out[digits] = 0;
    }
}

/// Build a single-entry USTAR header for a regular file named `name`
/// of size `size` bytes.
fn make_header(name: &[u8], size: u64) -> [u8; BLOCK] {
    let mut h = [0u8; BLOCK];
    let n = core::cmp::min(name.len(), 100);
    h[..n].copy_from_slice(&name[..n]);
    write_octal(&mut h[100..108], 0o644, 7);
    write_octal(&mut h[108..116], 0, 7);
    write_octal(&mut h[116..124], 0, 7);
    write_octal(&mut h[124..136], size, 11);
    write_octal(&mut h[136..148], 0, 11);
    h[156] = b'0';
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");

    h[148..156].copy_from_slice(b"        ");
    let sum: u64 = h.iter().map(|&b| b as u64).sum();
    write_octal(&mut h[148..155], sum, 6);
    h[155] = 0;
    h
}

fn pad_block(data: &[u8]) -> Vec<u8> {
    let mut v = Vec::from(data);
    let pad = (BLOCK - (v.len() % BLOCK)) % BLOCK;
    v.extend(core::iter::repeat(0).take(pad));
    v
}

/// Build a USTAR archive with a single regular file `hello` containing
/// `"Hello\n"`. Returned as a boxed slice so it can be leaked into a
/// `&'static [u8]` for `MountSource::Static`.
fn build_hello_archive() -> Vec<u8> {
    let payload = b"Hello\n";
    let mut archive: Vec<u8> = Vec::new();
    archive.extend_from_slice(&make_header(b"hello", payload.len() as u64));
    archive.extend_from_slice(&pad_block(payload));
    archive.extend_from_slice(&[0u8; BLOCK * 2]);
    archive
}

// ---------------------------------------------------------------------------
// The actual test
// ---------------------------------------------------------------------------

fn hello_read_through_vfs() {
    // Leak the archive so it lives for the rest of the test process —
    // `MountSource::Static` takes a `&'static [u8]`.
    let archive: &'static [u8] = alloc::boxed::Box::leak(build_hello_archive().into_boxed_slice());

    let fs = TarFs::new_arc();
    let sb = fs
        .mount(MountSource::Static(archive), MountFlags::default())
        .expect("tarfs mount of /hello archive");

    let root_inode = sb
        .root
        .get()
        .cloned()
        .expect("tarfs publishes a root inode at mount");
    let root_dentry = Dentry::new_root(root_inode.clone());

    // Walk "/hello" through the real path_walk, exercising the VFS
    // lookup path rather than a direct InodeOps::lookup.
    let mut nd = NameIdata::new(
        root_dentry.clone(),
        root_dentry,
        Credential::kernel(),
        LookupFlags::default(),
    )
    .expect("seed namei");
    path_walk(&mut nd, b"/hello", &NullMountResolver).expect("path_walk /hello");

    let hello_dentry = nd.path.dentry.clone();
    let hello_inode = nd.path.inode.clone();
    assert_eq!(
        hello_inode.kind,
        vibix::fs::vfs::InodeKind::Reg,
        "/hello must resolve to a regular file"
    );

    let guard = SbActiveGuard::try_acquire(&sb).expect("sb_active guard");
    let of = OpenFile::new(
        hello_dentry,
        hello_inode.clone(),
        hello_inode.file_ops.clone(),
        sb.clone(),
        0,
        guard,
    );

    let mut buf = [0u8; 16];
    let n = hello_inode
        .file_ops
        .read(&of, &mut buf, 0)
        .expect("FileOps::read /hello");
    assert_eq!(n, 6, "must read exactly 6 bytes");
    assert_eq!(&buf[..6], b"Hello\n", "contents must match");

    // Keep Arc chain alive through the end of the test.
    drop(fs);
}
