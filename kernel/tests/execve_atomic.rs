//! Integration test for #209: `execve` (syscall nr=59) must be atomic —
//! a malformed ELF must leave the caller's address space intact and
//! return `-ENOEXEC` so userspace continues running rather than faulting
//! into unmapped code.
//!
//! The test drives the staging path directly via the public
//! `arch::x86_64::syscall::exec_atomic` hook, bypassing the syscall
//! gate (which would require a real ring-3 process). A worker task
//! captures its current address-space `Arc` pointer, calls `exec_atomic`
//! with garbage bytes, asserts the call returns `Err(-8)` (ENOEXEC),
//! and asserts the address-space `Arc` is identity-equal before and
//! after — i.e. the failed exec did not swap a new PML4 in.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};

use vibix::arch::x86_64::syscall::exec_atomic;
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
    let tests: &[(&str, &dyn Testable)] = &[(
        "exec_atomic_preserves_aspace_on_garbage_elf",
        &(exec_atomic_preserves_aspace_on_garbage_elf as fn()),
    )];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

static WORKER_OBSERVED_ENOEXEC: AtomicUsize = AtomicUsize::new(0);
static WORKER_ASPACE_PRESERVED: AtomicUsize = AtomicUsize::new(0);
static WORKER_DONE: AtomicUsize = AtomicUsize::new(0);

fn exec_worker() -> ! {
    // Snapshot the address-space Arc pointer before attempting exec.
    let before = task::current_address_space();
    let before_ptr = Arc::as_ptr(&before) as usize;
    drop(before);

    // Garbage that cannot parse as ELF64 — `try_parse_elf64` rejects
    // and `load_user_elf_with_vmas` returns `Err(LoadError::NotElf64)`,
    // which the syscall arm maps to ENOEXEC (-8).
    static GARBAGE: [u8; 64] = [0u8; 64];
    match exec_atomic(&GARBAGE) {
        Ok(_never) => {
            // exec_atomic returned Ok? That means the swap committed
            // (and we never come back via a normal return because
            // jump_to_ring3 is `!`). Reaching here is impossible.
            unreachable!("exec_atomic returned Ok with garbage bytes");
        }
        Err(code) => {
            if code == -8 {
                WORKER_OBSERVED_ENOEXEC.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    // After the failed exec, the task's address space Arc must still
    // identify the original space. A successful swap would have
    // installed a new Arc with a different pointer.
    let after = task::current_address_space();
    let after_ptr = Arc::as_ptr(&after) as usize;
    drop(after);
    if after_ptr == before_ptr {
        WORKER_ASPACE_PRESERVED.fetch_add(1, Ordering::SeqCst);
    }

    WORKER_DONE.fetch_add(1, Ordering::SeqCst);
    task::exit();
}

fn exec_atomic_preserves_aspace_on_garbage_elf() {
    WORKER_OBSERVED_ENOEXEC.store(0, Ordering::SeqCst);
    WORKER_ASPACE_PRESERVED.store(0, Ordering::SeqCst);
    WORKER_DONE.store(0, Ordering::SeqCst);

    task::spawn(exec_worker);

    for _ in 0..200 {
        if WORKER_DONE.load(Ordering::SeqCst) == 1 {
            for _ in 0..4 {
                x86_64::instructions::hlt();
            }
            break;
        }
        x86_64::instructions::hlt();
    }

    assert_eq!(
        WORKER_DONE.load(Ordering::SeqCst),
        1,
        "exec_worker never finished"
    );
    assert_eq!(
        WORKER_OBSERVED_ENOEXEC.load(Ordering::SeqCst),
        1,
        "exec_atomic with garbage bytes did not return -ENOEXEC"
    );
    assert_eq!(
        WORKER_ASPACE_PRESERVED.load(Ordering::SeqCst),
        1,
        "address-space Arc swapped despite failed exec — atomicity broken"
    );
}
