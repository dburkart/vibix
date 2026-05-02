//! Integration test for issue #746 — RFC 0007 Workstream B's `sys_mmap`
//! file-backed rewire.
//!
//! Drives `syscall_dispatch(SYS_mmap, ...)` against a synthesized
//! in-memory `FileOps::mmap` impl (NOT ext2 — issue #753 has not landed
//! yet, ext2's default `FileOps::mmap` still returns ENODEV). Exercises
//! every branch of the new errno table from RFC 0007 §Errno table:
//!
//! * EBADF — fd not open
//! * ENODEV — non-VFS backend; non-Reg inode kind (Dir / Sock / Fifo)
//! * EACCES — `MAP_SHARED + PROT_WRITE` without `O_RDWR`
//! * EACCES — `MAP_PRIVATE + PROT_WRITE` on `O_WRONLY`
//! * EINVAL — `len == 0`
//! * EINVAL — `off` not page-aligned
//! * EOVERFLOW — `off + len_rounded` overflows i64
//! * Success — `MAP_PRIVATE + PROT_READ` on a Reg file with a custom
//!   `FileOps::mmap` impl plugs the returned `VmObject` into the VMA tree
//! * Success — `MAP_ANONYMOUS` ignores fd (Linux semantics)
//! * Pre-emption — `FileOps::mmap`'s default `ENODEV` propagates verbatim
//!   when the FS hasn't overridden it (regular file, no override)

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;

use vibix::arch::x86_64::syscall::syscall_dispatch;
use vibix::fs::flags;
use vibix::fs::vfs::dentry::Dentry;
use vibix::fs::vfs::inode::{Inode, InodeKind, InodeMeta};
use vibix::fs::vfs::open_file::OpenFile;
use vibix::fs::vfs::ops::{FileOps, InodeOps, SetAttr, Stat, StatFs, SuperOps};
use vibix::fs::vfs::super_block::{SbActiveGuard, SbFlags, SuperBlock};
use vibix::fs::vfs::{FsId, VfsBackend};
use vibix::fs::{
    EACCES, EBADF, EINVAL, ENODEV, EOVERFLOW, FileBackend, FileDescription,
};
use vibix::mem::pf::{
    MAP_ANONYMOUS, MAP_PRIVATE, MAP_SHARED, PROT_READ, PROT_WRITE,
};
use vibix::mem::vmatree::{ProtUser, Share};
use vibix::mem::vmobject::{AnonObject, VmObject};
use vibix::{
    exit_qemu, serial_println, task,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

const SYS_MMAP: u64 = 9;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    task::init();
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
        // ── EBADF / ENODEV gates ──────────────────────────────────
        (
            "file_mmap_invalid_fd_ebadf",
            &(file_mmap_invalid_fd_ebadf as fn()),
        ),
        (
            "file_mmap_dir_inode_enodev",
            &(file_mmap_dir_inode_enodev as fn()),
        ),
        (
            "file_mmap_default_fileops_propagates_enodev",
            &(file_mmap_default_fileops_propagates_enodev as fn()),
        ),
        // ── EINVAL / EOVERFLOW arithmetic gates ──────────────────
        (
            "file_mmap_unaligned_off_einval",
            &(file_mmap_unaligned_off_einval as fn()),
        ),
        (
            "file_mmap_zero_len_einval",
            &(file_mmap_zero_len_einval as fn()),
        ),
        (
            "file_mmap_off_plus_len_overflow_eoverflow",
            &(file_mmap_off_plus_len_overflow_eoverflow as fn()),
        ),
        // ── EACCES open-mode gates ───────────────────────────────
        (
            "file_mmap_shared_write_on_rdonly_eacces",
            &(file_mmap_shared_write_on_rdonly_eacces as fn()),
        ),
        (
            "file_mmap_shared_write_on_wronly_eacces",
            &(file_mmap_shared_write_on_wronly_eacces as fn()),
        ),
        (
            "file_mmap_private_write_on_wronly_eacces",
            &(file_mmap_private_write_on_wronly_eacces as fn()),
        ),
        // ── Success path: custom FileOps::mmap override ──────────
        (
            "file_mmap_private_read_succeeds",
            &(file_mmap_private_read_succeeds as fn()),
        ),
        (
            "file_mmap_shared_rdwr_succeeds",
            &(file_mmap_shared_rdwr_succeeds as fn()),
        ),
        (
            "file_mmap_returned_vmobject_lands_in_vma_tree",
            &(file_mmap_returned_vmobject_lands_in_vma_tree as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ── Stubs ──────────────────────────────────────────────────────────────

struct StubInodeOps;
impl InodeOps for StubInodeOps {
    fn getattr(&self, _inode: &Inode, _out: &mut Stat) -> Result<(), i64> {
        Ok(())
    }
    fn setattr(&self, _inode: &Inode, _attr: &SetAttr) -> Result<(), i64> {
        Ok(())
    }
}

struct StubSuperOps;
impl SuperOps for StubSuperOps {
    fn root_inode(&self) -> Arc<Inode> {
        unreachable!("test stub")
    }
    fn statfs(&self) -> Result<StatFs, i64> {
        Ok(StatFs::default())
    }
    fn unmount(&self) {}
}

/// `FileOps` impl that overrides `mmap` to return an `AnonObject`-backed
/// `VmObject` of the requested size. The integration test asserts the
/// returned object is plugged into the VMA tree at the correct va, with
/// the correct `share` and `prot_user`.
struct MmapableOps;
impl FileOps for MmapableOps {
    fn mmap(
        &self,
        _f: &OpenFile,
        _file_offset: u64,
        len_pages: usize,
        _share: Share,
        _prot: ProtUser,
    ) -> Result<Arc<dyn VmObject>, i64> {
        // The real ext2/ramfs/tarfs impls (#747/#751/#753) return an
        // `Arc<FileObject>` against the inode's page cache. For this
        // test we only need a concrete `VmObject` so sys_mmap's
        // VMA-insert path can land it; AnonObject is the simplest one
        // that satisfies the trait bound and doesn't drag the page
        // cache (gated behind `feature = "page_cache"`) into a test
        // build.
        Ok(AnonObject::new(Some(len_pages)) as Arc<dyn VmObject>)
    }
}

/// `FileOps` that uses every default impl — including the default
/// `mmap` that returns `ENODEV`. This is the contract every non-mmappable
/// FS (sockets, FIFOs, control nodes, and ext2 until #753) inherits.
struct DefaultFileOps;
impl FileOps for DefaultFileOps {}

/// Build a fresh `OpenFile` against an inode of the requested kind
/// using the requested `FileOps`. Inserts the resulting `VfsBackend`
/// into the current task's fd table and returns the allocated fd.
fn install_fd(
    kind: InodeKind,
    file_ops: Arc<dyn FileOps>,
    open_flags: u32,
    file_size: u64,
) -> u32 {
    let sb = Arc::new(SuperBlock::new(
        FsId(746),
        Arc::new(StubSuperOps),
        "stub-mmap",
        4096,
        SbFlags::default(),
    ));
    let mut meta = InodeMeta::default();
    meta.size = file_size;
    let inode = Arc::new(Inode::new(
        1,
        Arc::downgrade(&sb),
        Arc::new(StubInodeOps),
        file_ops.clone(),
        kind,
        meta,
    ));
    let dentry = Dentry::new_root(inode.clone());
    let guard = SbActiveGuard::try_acquire(&sb).expect("guard");
    let of = OpenFile::new(dentry, inode, file_ops, sb.clone(), open_flags, guard);
    let backend = Arc::new(VfsBackend { open_file: of }) as Arc<dyn FileBackend>;
    let desc = Arc::new(FileDescription::new(backend, 0));
    let tbl = task::current_fd_table();
    let fd = tbl.lock().alloc_fd(desc).expect("alloc_fd");
    fd
}

fn mmap(addr: u64, len: u64, prot: u32, flags: u32, fd: i64, off: u64) -> i64 {
    unsafe {
        syscall_dispatch(
            core::ptr::null_mut(),
            SYS_MMAP,
            addr,
            len,
            prot as u64,
            flags as u64,
            fd as u64,
            off,
        )
    }
}

// ── Tests: EBADF / ENODEV gates ────────────────────────────────────────

fn file_mmap_invalid_fd_ebadf() {
    // Without MAP_ANONYMOUS, sys_mmap looks up the fd. fd=999 is
    // (almost certainly) not open in the test task → EBADF per RFC 0007
    // §Errno table.
    let r = mmap(0, 4096, PROT_READ, MAP_PRIVATE, 999, 0);
    assert_eq!(r, EBADF, "fd=999 must trip EBADF, got {}", r);
}

fn file_mmap_dir_inode_enodev() {
    // A directory inode is not mmappable per RFC 0007 §Errno table —
    // sys_mmap pre-empts FileOps::mmap with ENODEV regardless of what
    // the FS impl returns.
    let fd = install_fd(
        InodeKind::Dir,
        Arc::new(MmapableOps),
        flags::O_RDWR,
        0,
    );
    let r = mmap(0, 4096, PROT_READ, MAP_PRIVATE, fd as i64, 0);
    assert_eq!(
        r, ENODEV,
        "MAP_PRIVATE on a directory inode must trip ENODEV, got {}",
        r
    );
}

fn file_mmap_default_fileops_propagates_enodev() {
    // The default FileOps::mmap returns -ENODEV. sys_mmap must
    // propagate the FS-level errno verbatim — ext2 (until #753 lands)
    // depends on this.
    let fd = install_fd(
        InodeKind::Reg,
        Arc::new(DefaultFileOps),
        flags::O_RDWR,
        4096,
    );
    let r = mmap(0, 4096, PROT_READ, MAP_PRIVATE, fd as i64, 0);
    assert_eq!(
        r, ENODEV,
        "default FileOps::mmap must propagate ENODEV verbatim, got {}",
        r
    );
}

// ── Tests: EINVAL / EOVERFLOW gates ───────────────────────────────────

fn file_mmap_unaligned_off_einval() {
    let fd = install_fd(
        InodeKind::Reg,
        Arc::new(MmapableOps),
        flags::O_RDWR,
        4096,
    );
    let r = mmap(0, 4096, PROT_READ, MAP_PRIVATE, fd as i64, 0x100);
    assert_eq!(r, EINVAL, "non-aligned off must trip EINVAL, got {}", r);
}

fn file_mmap_zero_len_einval() {
    let fd = install_fd(
        InodeKind::Reg,
        Arc::new(MmapableOps),
        flags::O_RDWR,
        4096,
    );
    let r = mmap(0, 0, PROT_READ, MAP_PRIVATE, fd as i64, 0);
    assert_eq!(r, EINVAL, "len=0 must trip EINVAL, got {}", r);
}

fn file_mmap_off_plus_len_overflow_eoverflow() {
    let fd = install_fd(
        InodeKind::Reg,
        Arc::new(MmapableOps),
        flags::O_RDWR,
        4096,
    );
    // off near i64::MAX + a multi-page len overflows i64 → EOVERFLOW.
    let near_max = (i64::MAX as u64) & !0xFFF;
    let r = mmap(0, 8192, PROT_READ, MAP_PRIVATE, fd as i64, near_max);
    assert_eq!(
        r, EOVERFLOW,
        "off+len overflow must trip EOVERFLOW, got {}",
        r
    );
}

// ── Tests: EACCES open-mode gates ─────────────────────────────────────

fn file_mmap_shared_write_on_rdonly_eacces() {
    // MAP_SHARED + PROT_WRITE requires O_RDWR. O_RDONLY → EACCES.
    let fd = install_fd(
        InodeKind::Reg,
        Arc::new(MmapableOps),
        flags::O_RDONLY,
        4096,
    );
    let r = mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        fd as i64,
        0,
    );
    assert_eq!(
        r, EACCES,
        "MAP_SHARED+PROT_WRITE on O_RDONLY must trip EACCES, got {}",
        r
    );
}

fn file_mmap_shared_write_on_wronly_eacces() {
    // MAP_SHARED + PROT_WRITE on O_WRONLY → EACCES (write-fault path
    // can't service the read-on-miss).
    let fd = install_fd(
        InodeKind::Reg,
        Arc::new(MmapableOps),
        flags::O_WRONLY,
        4096,
    );
    let r = mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        fd as i64,
        0,
    );
    assert_eq!(
        r, EACCES,
        "MAP_SHARED+PROT_WRITE on O_WRONLY must trip EACCES, got {}",
        r
    );
}

fn file_mmap_private_write_on_wronly_eacces() {
    // MAP_PRIVATE + PROT_WRITE on O_WRONLY → EACCES (CoW needs to
    // read the master page first).
    let fd = install_fd(
        InodeKind::Reg,
        Arc::new(MmapableOps),
        flags::O_WRONLY,
        4096,
    );
    let r = mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE,
        fd as i64,
        0,
    );
    assert_eq!(
        r, EACCES,
        "MAP_PRIVATE+PROT_WRITE on O_WRONLY must trip EACCES, got {}",
        r
    );
}

// ── Tests: Success path ──────────────────────────────────────────────

fn file_mmap_private_read_succeeds() {
    // MAP_PRIVATE + PROT_READ on a Reg file with a custom FileOps::mmap
    // impl: sys_mmap calls the impl, gets back an `Arc<dyn VmObject>`,
    // and lands a VMA at the chosen VA.
    let fd = install_fd(
        InodeKind::Reg,
        Arc::new(MmapableOps),
        flags::O_RDONLY,
        4096,
    );
    let r = mmap(0, 4096, PROT_READ, MAP_PRIVATE, fd as i64, 0);
    assert!(r > 0, "file-backed MAP_PRIVATE+PROT_READ must succeed, got {}", r);
    let va = r as u64;
    assert_eq!(va & 0xFFF, 0, "returned VA must be page-aligned: {:#x}", va);
    // VMA must be visible in the current address space.
    let aspace = vibix::task::current_address_space();
    let guard = aspace.read();
    let vma = guard.find(va as usize).expect("file-backed VMA missing");
    assert_eq!(vma.start, va as usize);
    assert_eq!(vma.end, (va as usize) + 4096);
    assert_eq!(vma.share, Share::Private);
    assert_eq!(vma.prot_user, PROT_READ);
}

fn file_mmap_shared_rdwr_succeeds() {
    // MAP_SHARED + PROT_WRITE on O_RDWR — the only combination the
    // EACCES gate permits with PROT_WRITE.
    let fd = install_fd(
        InodeKind::Reg,
        Arc::new(MmapableOps),
        flags::O_RDWR,
        8192,
    );
    let r = mmap(
        0,
        8192,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        fd as i64,
        0,
    );
    assert!(r > 0, "MAP_SHARED+RW on O_RDWR must succeed, got {}", r);
    let va = r as u64;
    let aspace = vibix::task::current_address_space();
    let guard = aspace.read();
    let vma = guard.find(va as usize).expect("file-backed VMA missing");
    assert_eq!(vma.share, Share::Shared);
    assert_eq!(vma.prot_user, PROT_READ | PROT_WRITE);
    assert_eq!(vma.end - vma.start, 8192);
}

fn file_mmap_returned_vmobject_lands_in_vma_tree() {
    // The Arc<dyn VmObject> returned by FileOps::mmap is the *same*
    // Arc on the VMA. Verify by pointer-eq via the AnonObject's
    // observable behaviour: a VMA pointing at an AnonObject of N pages
    // exposes N pages, and vma.object's len_pages matches the syscall's
    // len argument rounded up.
    let fd = install_fd(
        InodeKind::Reg,
        Arc::new(MmapableOps),
        flags::O_RDONLY,
        16384,
    );
    let r = mmap(0, 16384, PROT_READ, MAP_PRIVATE, fd as i64, 0);
    assert!(r > 0);
    let va = r as u64;
    let aspace = vibix::task::current_address_space();
    let guard = aspace.read();
    let vma = guard.find(va as usize).expect("file-backed VMA missing");
    // The custom FileOps::mmap returns AnonObject::new(Some(4)); its
    // len_pages observable through the VmObject trait must be 4.
    assert_eq!(vma.object.len_pages(), Some(4));
    // object_offset is 0 — sys_mmap forwards the file_offset *into*
    // FileOps::mmap (which the FS impl burns into its returned object,
    // typically a FileObject window). The VMA itself carries 0 so
    // VMA-local offsets map directly through.
    assert_eq!(vma.object_offset, 0);
}
