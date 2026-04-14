//! Integration test for issue #124: per-process file-descriptor table.
//!
//! Boots the kernel, initialises the task scheduler (so every task gets a
//! `FileDescTable`), then:
//! 1. Verifies that the current task's fd table has fds 0/1/2 pre-wired.
//! 2. Exercises `alloc_fd` / `close_fd` / `dup` / `dup2` / `clone_for_fork`
//!    through the public `FileDescTable` API.
//! 3. Confirms that `current_fd_table()` returns a live, usable table and
//!    that writing through fd=1's backend reaches the serial port (echoed
//!    back as test output).

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use alloc::sync::Arc;

use vibix::fs::{flags, FileBackend, FileDescTable, FileDescription, EBADF};
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
        ("stdio_fds_present", &(stdio_fds_present as fn())),
        ("alloc_close_roundtrip", &(alloc_close_roundtrip as fn())),
        ("dup_creates_alias", &(dup_creates_alias as fn())),
        ("dup2_replaces_slot", &(dup2_replaces_slot as fn())),
        (
            "clone_for_fork_independent",
            &(clone_for_fork_independent as fn()),
        ),
        ("close_cloexec", &(close_cloexec as fn())),
        ("write_via_backend", &(write_via_backend as fn())),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct NullBackend;
impl FileBackend for NullBackend {
    fn read(&self, _: &mut [u8]) -> Result<usize, i64> {
        Ok(0)
    }
    fn write(&self, buf: &[u8]) -> Result<usize, i64> {
        Ok(buf.len())
    }
}

fn null() -> Arc<dyn FileBackend> {
    Arc::new(NullBackend)
}

fn null_desc() -> Arc<FileDescription> {
    Arc::new(FileDescription {
        backend: null(),
        flags: 0,
    })
}

fn make_table() -> FileDescTable {
    FileDescTable::new_with_backends(null(), null(), null())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The current task's fd table has fds 0, 1, 2 open after task::init().
fn stdio_fds_present() {
    let tbl = task::current_fd_table();
    let locked = tbl.lock();
    assert!(locked.get(0).is_ok(), "fd 0 (stdin) must be open");
    assert!(locked.get(1).is_ok(), "fd 1 (stdout) must be open");
    assert!(locked.get(2).is_ok(), "fd 2 (stderr) must be open");
    assert_eq!(locked.get(99).err(), Some(EBADF), "fd 99 must be closed");
}

/// Allocate fds beyond stdio, close one, re-allocate lands on the freed slot.
fn alloc_close_roundtrip() {
    let mut t = make_table();
    let fd3 = t.alloc_fd(null_desc()).unwrap();
    assert_eq!(fd3, 3);
    let fd4 = t.alloc_fd(null_desc()).unwrap();
    assert_eq!(fd4, 4);
    t.close_fd(3).unwrap();
    let reused = t.alloc_fd(null_desc()).unwrap();
    assert_eq!(reused, 3, "alloc_fd must return the lowest free fd");
    assert_eq!(t.close_fd(99), Err(EBADF));
}

/// dup() creates a new fd pointing to the same backend.
fn dup_creates_alias() {
    let mut t = make_table();
    let new_fd = t.dup(1).unwrap();
    assert_eq!(new_fd, 3);
    assert!(t.get(1).is_ok());
    assert!(t.get(3).is_ok());
    // Close the original; the alias is unaffected.
    t.close_fd(1).unwrap();
    assert_eq!(t.get(1).err(), Some(EBADF));
    assert!(t.get(3).is_ok());
}

/// dup2() wires newfd to oldfd's description; newfd==oldfd is a no-op.
fn dup2_replaces_slot() {
    let mut t = make_table();
    // dup2(1, 5): extend and wire fd 5 to fd 1's description.
    let r = t.dup2(1, 5).unwrap();
    assert_eq!(r, 5);
    assert!(t.get(5).is_ok());
    // Holes at 3 and 4 must remain closed.
    assert_eq!(t.get(3).err(), Some(EBADF));
    assert_eq!(t.get(4).err(), Some(EBADF));
    // dup2(2, 2) — same fd: no-op, fd 2 stays open.
    assert_eq!(t.dup2(2, 2).unwrap(), 2);
    assert!(t.get(2).is_ok());
}

/// clone_for_fork() gives the child independent slots over shared descriptions.
fn clone_for_fork_independent() {
    let mut t = make_table();
    let mut child = t.clone_for_fork();
    // Close fd 1 in parent; child must still have it.
    t.close_fd(1).unwrap();
    assert_eq!(t.get(1).err(), Some(EBADF));
    assert!(
        child.get(1).is_ok(),
        "child's fd 1 must survive parent close"
    );
    // Close fd 2 in child; parent must still have it.
    child.close_fd(2).unwrap();
    assert!(t.get(2).is_ok(), "parent's fd 2 must survive child close");
}

/// close_cloexec() closes O_CLOEXEC fds and leaves others intact.
fn close_cloexec() {
    let mut t = make_table();
    // FD_CLOEXEC is a per-fd flag — pass it via alloc_fd_with_flags, NOT
    // via FileDescription.flags (which only holds access-mode bits).
    let fd = t
        .alloc_fd_with_flags(null_desc(), flags::O_CLOEXEC)
        .unwrap();
    assert_eq!(fd, 3);
    t.close_cloexec();
    assert_eq!(
        t.get(3).err(),
        Some(EBADF),
        "O_CLOEXEC fd must be closed after exec"
    );
    assert!(t.get(0).is_ok(), "fd 0 must survive close_cloexec");
    assert!(t.get(1).is_ok(), "fd 1 must survive close_cloexec");
    assert!(t.get(2).is_ok(), "fd 2 must survive close_cloexec");
}

/// Writing through fd=1's SerialBackend reaches the serial port.
fn write_via_backend() {
    let tbl = task::current_fd_table();
    let backend = tbl.lock().get(1).expect("fd 1 must be open");
    let msg = b"fd_table: write_via_backend ok\n";
    let n = backend.write(msg).expect("write must succeed");
    assert_eq!(n, msg.len(), "write must return number of bytes written");
}
