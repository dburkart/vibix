//! Integration test for issue #756: `sync(2)` syscall — writeback
//! ordering (page cache before `BlockCache::sync_fs`).
//!
//! Exercises the `SYS_SYNC` (162) dispatch arm end-to-end:
//!
//! - `sync()` returns 0 (Linux ABI: always succeeds).
//! - `sync()` is idempotent — calling it multiple times is harmless.
//! - `sync()` returns 0 even when no dirty data exists.
//!
//! RFC 0007 §Ordering vs fsync (Workstream D): the two-stage ordering
//! (page-cache pages flushed first, then `BlockCache::sync_fs` fences
//! the rest) is structurally encoded in `writeback::sync_all_mounts`;
//! this test verifies the syscall ABI.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use vibix::arch::x86_64::syscall::syscall_dispatch;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

const SYS_SYNC: u64 = 162;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    vibix::task::init();
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
        ("sync_returns_zero", &(sync_returns_zero as fn())),
        ("sync_idempotent", &(sync_idempotent as fn())),
        (
            "sync_no_dirty_data_still_zero",
            &(sync_no_dirty_data_still_zero as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("syscall_sync: {}", name);
        t.run();
    }
}

fn do_sync() -> i64 {
    unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_SYNC, 0, 0, 0, 0, 0, 0) }
}

// --- Tests ----------------------------------------------------------

/// `sync(2)` always returns 0, matching Linux semantics. The mount
/// table contains the boot-time tarfs rootfs; `sync_all_mounts`
/// iterates it, calls `SuperOps::sync_fs` (a no-op for tarfs), and
/// returns — no dirty data, no errors, result is 0.
fn sync_returns_zero() {
    let ret = do_sync();
    assert_eq!(ret, 0, "sync() must return 0, got {}", ret);
}

/// Calling `sync()` twice in a row is harmless. The second call has
/// nothing to flush and returns 0.
fn sync_idempotent() {
    let ret1 = do_sync();
    let ret2 = do_sync();
    assert_eq!(ret1, 0, "first sync() must return 0");
    assert_eq!(ret2, 0, "second sync() must return 0");
}

/// Even when no mount has any dirty data, `sync(2)` returns 0. This
/// pins the "infallible" contract from Linux's `sync(2)` manpage.
fn sync_no_dirty_data_still_zero() {
    // Issue three syncs back-to-back to ensure the empty-dirty-set
    // path is exercised thoroughly.
    for i in 0..3 {
        let ret = do_sync();
        assert_eq!(ret, 0, "sync() iteration {} must return 0, got {}", i, ret);
    }
}
