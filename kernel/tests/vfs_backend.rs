//! Integration test for issue #237: VfsBackend wires Arc<OpenFile> into
//! the per-process FileDescTable.
//!
//! Exercises the full chain:
//!   FileDescTable → Arc<FileDescription> → VfsBackend → Arc<OpenFile> → FileOps
//!
//! Specifically:
//! - read/write through a VfsBackend-backed fd advance the shared offset.
//! - clone_for_fork shares the same Arc<OpenFile> (POSIX open-file description
//!   semantics: parent and child see the same offset).
//! - close_cloexec drops VfsBackend fds flagged O_CLOEXEC, leaves others.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};

use vibix::fs::vfs::dentry::Dentry;
use vibix::fs::vfs::inode::{Inode, InodeKind, InodeMeta};
use vibix::fs::vfs::open_file::OpenFile;
use vibix::fs::vfs::ops::{FileOps, InodeOps, SetAttr, Stat, StatFs, SuperOps};
use vibix::fs::vfs::super_block::{SbActiveGuard, SbFlags, SuperBlock};
use vibix::fs::vfs::{FsId, VfsBackend};
use vibix::fs::{flags, FileBackend, FileDescTable, FileDescription};
use vibix::{
    exit_qemu, serial_println, task,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

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
        ("read_advances_offset", &(read_advances_offset as fn())),
        ("write_advances_offset", &(write_advances_offset as fn())),
        (
            "fork_shares_open_file_description",
            &(fork_shares_open_file_description as fn()),
        ),
        (
            "close_cloexec_drops_vfs_backend",
            &(close_cloexec_drops_vfs_backend as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ---------------------------------------------------------------------------
// Stubs
// ---------------------------------------------------------------------------

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

/// `FileOps` stub that fills read buffers with `fill_byte` and counts writes.
struct CountingOps {
    fill_byte: u8,
    write_count: AtomicUsize,
}

impl FileOps for CountingOps {
    fn read(&self, _f: &OpenFile, buf: &mut [u8], _off: u64) -> Result<usize, i64> {
        for b in buf.iter_mut() {
            *b = self.fill_byte;
        }
        Ok(buf.len())
    }

    fn write(&self, _f: &OpenFile, buf: &[u8], _off: u64) -> Result<usize, i64> {
        self.write_count.fetch_add(buf.len(), Ordering::Relaxed);
        Ok(buf.len())
    }
}

fn make_open_file(fill_byte: u8) -> Arc<OpenFile> {
    let sb = Arc::new(SuperBlock::new(
        FsId(99),
        Arc::new(StubSuperOps),
        "stub",
        512,
        SbFlags::default(),
    ));
    let inode = Arc::new(Inode::new(
        1,
        Arc::downgrade(&sb),
        Arc::new(StubInodeOps),
        Arc::new(CountingOps {
            fill_byte,
            write_count: AtomicUsize::new(0),
        }),
        InodeKind::Reg,
        InodeMeta::default(),
    ));
    let dentry = Dentry::new_root(inode.clone());
    let file_ops: Arc<dyn FileOps> = Arc::new(CountingOps {
        fill_byte,
        write_count: AtomicUsize::new(0),
    });
    let guard = SbActiveGuard::try_acquire(&sb).expect("guard");
    OpenFile::new(dentry, inode, file_ops, sb.clone(), 0, guard)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Reading through a VfsBackend-backed fd advances the shared file offset.
fn read_advances_offset() {
    let of = make_open_file(0xAB);
    let backend = Arc::new(VfsBackend {
        open_file: of.clone(),
    }) as Arc<dyn FileBackend>;
    let mut t = FileDescTable::new();
    let desc = Arc::new(FileDescription { backend, flags: 0 });
    let fd = t.alloc_fd(desc).expect("alloc_fd");

    let b = t.get(fd).expect("fd open");
    let mut buf = [0u8; 8];
    let n = b.read(&mut buf).expect("read");
    assert_eq!(n, 8, "read must return buf.len()");
    assert_eq!(buf, [0xABu8; 8], "buf must be filled with fill_byte");
    assert_eq!(*of.offset.lock(), 8, "offset must advance by bytes read");
}

/// Writing through a VfsBackend-backed fd advances the shared file offset.
fn write_advances_offset() {
    let of = make_open_file(0);
    let backend = Arc::new(VfsBackend {
        open_file: of.clone(),
    }) as Arc<dyn FileBackend>;
    let mut t = FileDescTable::new();
    let desc = Arc::new(FileDescription { backend, flags: 0 });
    let fd = t.alloc_fd(desc).expect("alloc_fd");

    let b = t.get(fd).expect("fd open");
    let data = b"hello world";
    let n = b.write(data).expect("write");
    assert_eq!(n, data.len(), "write must return buf.len()");
    assert_eq!(
        *of.offset.lock(),
        data.len() as u64,
        "offset advances by bytes written"
    );
}

/// `clone_for_fork` shares the Arc<OpenFile> (shared file description).
///
/// Both parent and child see the same underlying offset — writes via the
/// parent advance the offset visible through the child's fd.
fn fork_shares_open_file_description() {
    let of = make_open_file(0xCD);
    let backend = Arc::new(VfsBackend {
        open_file: of.clone(),
    }) as Arc<dyn FileBackend>;
    let mut parent = FileDescTable::new();
    let desc = Arc::new(FileDescription { backend, flags: 0 });
    let fd = parent.alloc_fd(desc).expect("alloc_fd");

    // Fork the fd table.
    let child = parent.clone_for_fork();

    // Read 3 bytes via parent.
    let parent_b = parent.get(fd).expect("parent fd");
    let mut buf = [0u8; 3];
    parent_b.read(&mut buf).unwrap();
    assert_eq!(*of.offset.lock(), 3, "parent read must advance offset");

    // Child's fd backend wraps the *same* OpenFile, so its offset is 3.
    let child_b = child.get(fd).expect("child fd");
    let mut buf2 = [0u8; 2];
    child_b.read(&mut buf2).unwrap();
    assert_eq!(
        *of.offset.lock(),
        5,
        "child read advances the shared offset"
    );

    // Closing a slot in the child does not affect the parent.
    drop(child);
    assert!(parent.get(fd).is_ok(), "parent fd must survive child drop");
}

/// `close_cloexec` drops VfsBackend fds marked O_CLOEXEC; leaves others.
fn close_cloexec_drops_vfs_backend() {
    struct NullBackend;
    impl FileBackend for NullBackend {
        fn read(&self, _: &mut [u8]) -> Result<usize, i64> {
            Ok(0)
        }
        fn write(&self, buf: &[u8]) -> Result<usize, i64> {
            Ok(buf.len())
        }
    }

    let of = make_open_file(0);
    let cloexec_backend = Arc::new(VfsBackend { open_file: of }) as Arc<dyn FileBackend>;
    let mut t = FileDescTable::new();
    let cloexec_desc = Arc::new(FileDescription {
        backend: cloexec_backend,
        flags: flags::O_CLOEXEC,
    });
    let cloexec_fd = t.alloc_fd(cloexec_desc).expect("alloc cloexec fd");

    // A non-cloexec VfsBackend fd must survive exec.
    let of2 = make_open_file(0);
    let keep_backend = Arc::new(VfsBackend { open_file: of2 }) as Arc<dyn FileBackend>;
    let keep_desc = Arc::new(FileDescription {
        backend: keep_backend,
        flags: 0,
    });
    let keep_fd = t.alloc_fd(keep_desc).expect("alloc keep fd");

    t.close_cloexec();

    assert!(t.get(cloexec_fd).is_err(), "O_CLOEXEC fd must be closed");
    assert!(t.get(keep_fd).is_ok(), "non-cloexec fd must survive");
}
