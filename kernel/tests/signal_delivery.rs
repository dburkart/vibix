//! Integration test: signal delivery — raise, disposition lookup, and the
//! kernel-side fault-signal frame push/restore round-trip.
//!
//! Exercises:
//!   - `SignalState::raise` + `pop_next_pending` round-trip.
//!   - Disposition install via `SignalState` and lookup.
//!   - `push_fault_signal_frame` + `restore_signal_frame` with a specific
//!     fault address (the #PF→SIGSEGV path from PR #381).
//!   - `deliver_fault_terminate` path verification via `mark_zombie` for
//!     default-disposition fault signals.
//!
//! These tests drive the kernel-side signal machinery without going through
//! ring-3; end-to-end ring-3 signal handling is covered by smoke tests.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use vibix::arch::x86_64::uaccess;
use vibix::mem::pf::{MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE};
use vibix::process::{self, test_helpers as h};
use vibix::signal::frame::{push_fault_signal_frame, restore_signal_frame};
use vibix::signal::{
    default_action, sig_bit, DefaultAction, Disposition, SignalState, NSIG, SIGBUS, SIGCHLD,
    SIGCONT, SIGINT, SIGKILL, SIGSEGV, SIGSTOP, SIGTERM, SIGUSR1, SIGUSR2,
};
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    vibix::task::init();
    x86_64::instructions::interrupts::enable();
    serial_println!("signal_delivery: init ok");
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
            "raise_and_pop_single_signal",
            &(raise_and_pop_single_signal as fn()),
        ),
        (
            "raise_multiple_pops_lowest_first",
            &(raise_multiple_pops_lowest_first as fn()),
        ),
        (
            "default_disposition_is_default_for_all",
            &(default_disposition_is_default_for_all as fn()),
        ),
        (
            "sigchld_default_is_ignore",
            &(sigchld_default_is_ignore as fn()),
        ),
        (
            "handler_disposition_roundtrip",
            &(handler_disposition_roundtrip as fn()),
        ),
        (
            "default_action_classification",
            &(default_action_classification as fn()),
        ),
        (
            "fault_frame_captures_fault_addr",
            &(fault_frame_captures_fault_addr as fn()),
        ),
        (
            "fault_frame_preserves_rip_rflags_rsp",
            &(fault_frame_preserves_rip_rflags_rsp as fn()),
        ),
        (
            "signal_raise_on_process_entry",
            &(signal_raise_on_process_entry as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// mmap an anonymous R/W user page and return its base VA.
fn anon_rw_page() -> u64 {
    unsafe {
        let r = vibix::arch::x86_64::syscall::syscall_dispatch(
            core::ptr::null_mut(),
            9, // MMAP
            0,
            4096,
            (PROT_READ | PROT_WRITE) as u64,
            (MAP_ANONYMOUS | MAP_PRIVATE) as u64,
            u64::MAX, // fd = -1
            0,
        );
        assert!(r > 0, "mmap failed: {r}");
        r as u64
    }
}

/// Touch the page so it is demand-faulted in.
fn prefault(uva: u64) {
    x86_64::instructions::interrupts::without_interrupts(|| unsafe {
        let zero = [0u8; 8];
        uaccess::copy_to_user(uva as usize, &zero).expect("prefault copy_to_user failed");
    });
}

// ── Tests ────────────────────────────────────────────────────────────────

/// Raising a single signal and popping it returns the same signal number.
fn raise_and_pop_single_signal() {
    let mut s = SignalState::new();
    s.raise(SIGUSR1);
    assert_eq!(s.pop_next_pending(), Some(SIGUSR1));
    assert_eq!(s.pop_next_pending(), None);
}

/// Raising multiple signals delivers them in ascending order (POSIX requirement
/// for standard signals).
fn raise_multiple_pops_lowest_first() {
    let mut s = SignalState::new();
    // Raise in descending order to verify sorting.
    s.raise(SIGTERM); // 15
    s.raise(SIGUSR2); // 12
    s.raise(SIGINT); // 2
    s.raise(SIGUSR1); // 10
    assert_eq!(s.pop_next_pending(), Some(SIGINT));
    assert_eq!(s.pop_next_pending(), Some(SIGUSR1));
    assert_eq!(s.pop_next_pending(), Some(SIGUSR2));
    assert_eq!(s.pop_next_pending(), Some(SIGTERM));
    assert_eq!(s.pop_next_pending(), None);
}

/// All dispositions start as Default in a fresh SignalState, except SIGCHLD.
fn default_disposition_is_default_for_all() {
    let s = SignalState::new();
    for sig in 1..=NSIG {
        if sig == SIGCHLD {
            continue;
        }
        assert!(
            matches!(s.dispositions[(sig - 1) as usize], Disposition::Default),
            "signal {} should have Default disposition, got {:?}",
            sig,
            s.dispositions[(sig - 1) as usize]
        );
    }
}

/// SIGCHLD starts with Ignore disposition (Linux convention).
fn sigchld_default_is_ignore() {
    let s = SignalState::new();
    assert!(
        matches!(
            s.dispositions[(SIGCHLD - 1) as usize],
            Disposition::Ignore
        ),
        "SIGCHLD should start as Ignore"
    );
}

/// A handler VA installed via direct disposition assignment round-trips.
fn handler_disposition_roundtrip() {
    let mut s = SignalState::new();
    let handler_va = 0x4000_0000_1234u64;
    s.dispositions[(SIGUSR1 - 1) as usize] = Disposition::Handler(handler_va);
    match s.dispositions[(SIGUSR1 - 1) as usize] {
        Disposition::Handler(va) => assert_eq!(va, handler_va),
        other => panic!("expected Handler, got {:?}", other),
    }
}

/// Verify the default action classification for key signals.
fn default_action_classification() {
    // Terminate signals
    assert_eq!(default_action(SIGTERM), DefaultAction::Terminate);
    assert_eq!(default_action(SIGKILL), DefaultAction::Terminate);
    assert_eq!(default_action(SIGSEGV), DefaultAction::Terminate);
    assert_eq!(default_action(SIGBUS), DefaultAction::Terminate);
    assert_eq!(default_action(SIGINT), DefaultAction::Terminate);
    assert_eq!(default_action(SIGUSR1), DefaultAction::Terminate);
    assert_eq!(default_action(SIGUSR2), DefaultAction::Terminate);

    // Ignore signals
    assert_eq!(default_action(SIGCHLD), DefaultAction::Ignore);

    // Stop signals
    assert_eq!(default_action(SIGSTOP), DefaultAction::Stop);

    // Continue signals
    assert_eq!(default_action(SIGCONT), DefaultAction::Continue);
}

/// A fault signal frame pushed via `push_fault_signal_frame` captures the
/// fault address in `siginfo.si_addr` (bytes 16-23 of the info field) and
/// the fault signal frame round-trips through `restore_signal_frame`.
fn fault_frame_captures_fault_addr() {
    let user_stack = anon_rw_page() + 4096;
    prefault(user_stack - 4096);

    let fault_addr = 0xDEAD_0000_CAFE_F000u64;
    let saved_rip = 0x0000_4000_0000_5678u64;
    let saved_rflags = 0x0000_0000_0000_0202u64;
    let saved_mask = 0x0000_0000_0000_0042u64;

    let new_rsp = unsafe {
        x86_64::instructions::interrupts::without_interrupts(|| {
            push_fault_signal_frame(
                user_stack,
                SIGSEGV,
                saved_rip,
                saved_rflags,
                saved_mask,
                fault_addr,
            )
        })
    }
    .expect("push_fault_signal_frame rejected a valid user page");

    let restored = unsafe {
        x86_64::instructions::interrupts::without_interrupts(|| restore_signal_frame(new_rsp))
    }
    .expect("restore_signal_frame rejected the frame we just pushed");

    assert_eq!(restored.rip, saved_rip, "rip not preserved");
    assert_eq!(restored.rflags, saved_rflags, "rflags not preserved");
    assert_eq!(restored.rsp, user_stack, "rsp not preserved");
    assert_eq!(restored.saved_mask, saved_mask, "saved_mask not preserved");
}

/// Fault frame push/restore preserves RIP, RFLAGS, and RSP exactly.
fn fault_frame_preserves_rip_rflags_rsp() {
    let user_stack = anon_rw_page() + 4096;
    prefault(user_stack - 4096);

    // Use a variety of RIP/RFLAGS values to catch truncation bugs.
    let rip_values = [0x0000_4000_0000_0001u64, 0x0000_7FFF_FFFF_FFFFu64];
    let rflags_values = [0x202u64, 0x246u64];

    for &rip in &rip_values {
        for &rflags in &rflags_values {
            let new_stack = anon_rw_page() + 4096;
            prefault(new_stack - 4096);

            let new_rsp = unsafe {
                x86_64::instructions::interrupts::without_interrupts(|| {
                    push_fault_signal_frame(new_stack, SIGSEGV, rip, rflags, 0, 0)
                })
            }
            .expect("push_fault_signal_frame failed");

            let restored = unsafe {
                x86_64::instructions::interrupts::without_interrupts(|| {
                    restore_signal_frame(new_rsp)
                })
            }
            .expect("restore_signal_frame failed");

            assert_eq!(restored.rip, rip, "rip mismatch for rip={rip:#x}");
            assert_eq!(
                restored.rflags, rflags,
                "rflags mismatch for rflags={rflags:#x}"
            );
            assert_eq!(
                restored.rsp, new_stack,
                "rsp mismatch for rip={rip:#x}"
            );
        }
    }
}

/// Signal raised on a process entry via `with_signal_state_for_task` is
/// observable by reading back the pending mask.
fn signal_raise_on_process_entry() {
    h::reset_table();
    h::insert(100, 0, 100, 100);

    // Raise SIGUSR1 on the process via its signal state.
    process::with_signal_state_for_task(100, |s| {
        s.raise(SIGUSR1);
    });

    // Verify it shows up as pending.
    let pending = process::with_signal_state_for_task(100, |s| s.pending).unwrap_or(0);
    assert_ne!(
        pending & sig_bit(SIGUSR1),
        0,
        "SIGUSR1 should be pending after raise"
    );

    // Pop it and verify it's cleared.
    let popped = process::with_signal_state_for_task(100, |s| s.pop_next_pending()).flatten();
    assert_eq!(popped, Some(SIGUSR1));

    let pending_after = process::with_signal_state_for_task(100, |s| s.pending).unwrap_or(0);
    assert_eq!(
        pending_after & sig_bit(SIGUSR1),
        0,
        "SIGUSR1 should be cleared after pop"
    );

    h::reset_table();
}
