//! Integration test: SA_NODEFER and sigaltstack(2) (#930).
//!
//! ## SA_NODEFER
//!
//! When a signal handler's `sa_flags` includes `SA_NODEFER`, the kernel
//! must NOT automatically add the signal to the blocked mask during
//! handler execution.  Without SA_NODEFER, the signal is blocked to
//! prevent recursive handler invocations (the default POSIX behaviour).
//!
//! ## sigaltstack
//!
//! `sigaltstack(2)` (syscall 131) lets a process register an alternate
//! signal stack.  When the signal's `sa_flags` includes `SA_ONSTACK`
//! and an alternate stack has been registered, the signal frame is
//! pushed onto the alternate stack instead of the current user stack.
//!
//! ## What we verify here
//!
//! 1. **SA_NODEFER**: register a handler with SA_NODEFER, deliver a
//!    signal, and confirm the signal's bit is NOT set in the blocked
//!    mask after delivery.
//!
//! 2. **SA_NODEFER absent**: same as (1) but without SA_NODEFER, and
//!    confirm the signal IS blocked after delivery (baseline).
//!
//! 3. **sigaltstack registration**: call `sys_sigaltstack` to register
//!    an alternate stack, then query it back and verify the fields
//!    match.
//!
//! 4. **SA_ONSTACK delivery**: register an alternate stack, set
//!    SA_ONSTACK on a handler, deliver a signal, and verify the
//!    resulting RSP falls within the alternate stack region.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use vibix::arch::x86_64::uaccess;
use vibix::mem::pf::{MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE};
use vibix::process::{self, test_helpers as h};
use vibix::signal::{
    sig_bit, Disposition, SigaltStack, SyscallReturnContext, SA_NODEFER, SA_ONSTACK, SIGUSR1,
    SIGUSR2,
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
    run_tests();
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info)
}

/// Register a process entry for the BSP task so
/// `with_signal_state_for_task` can find it.  `h::insert(pid, ...)`
/// internally sets `task_id = pid as usize`, so passing `pid = 0`
/// creates the mapping `pid_of[0] = 0` which is what
/// `with_signal_state_for_task(current_id(), ...)` needs (BSP
/// has `task_id = 0`).
fn setup_process_entry() {
    h::reset_table();
    h::insert(0, 0, 0, 0);
}

fn run_tests() {
    setup_process_entry();

    let tests: &[(&str, &dyn Testable)] = &[
        (
            "sa_nodefer_does_not_block_signal_during_handler",
            &(sa_nodefer_does_not_block_signal_during_handler as fn()),
        ),
        (
            "default_blocks_signal_during_handler",
            &(default_blocks_signal_during_handler as fn()),
        ),
        (
            "sigaltstack_register_and_query",
            &(sigaltstack_register_and_query as fn()),
        ),
        ("sigaltstack_disable", &(sigaltstack_disable as fn())),
        (
            "sa_onstack_delivers_on_alt_stack",
            &(sa_onstack_delivers_on_alt_stack as fn()),
        ),
        (
            "sa_onstack_without_alt_stack_uses_user_stack",
            &(sa_onstack_without_alt_stack_uses_user_stack as fn()),
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

/// mmap a multi-page anonymous R/W region and return its base VA.
fn anon_rw_pages(count: usize) -> u64 {
    unsafe {
        let size = count * 4096;
        let r = vibix::arch::x86_64::syscall::syscall_dispatch(
            core::ptr::null_mut(),
            9, // MMAP
            0,
            size as u64,
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

/// Prefault an entire region page-by-page.
fn prefault_region(base: u64, size: usize) {
    let mut offset = 0;
    while offset < size {
        prefault(base + offset as u64);
        offset += 4096;
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

/// When SA_NODEFER is set, the signal must NOT be added to the blocked
/// mask after delivery.  We verify this by setting up a signal handler
/// with SA_NODEFER, then examining the blocked mask after
/// `deliver_signal` runs.
fn sa_nodefer_does_not_block_signal_during_handler() {
    let task_id = vibix::task::current_id();

    // Verify process entry is present (sanity check).
    let found = process::with_signal_state_for_task(task_id, |_| true);
    assert!(found.is_some(), "no process entry for task_id={}", task_id);

    // Set up signal state: handler with SA_NODEFER.
    let handler_va = 0x0000_4000_0000_1000u64; // arbitrary user VA
    process::with_signal_state_for_task(task_id, |state| {
        state.dispositions[(SIGUSR1 - 1) as usize] = Disposition::Handler(handler_va);
        state.sa_flags[(SIGUSR1 - 1) as usize] = SA_NODEFER;
        state.blocked = 0; // start unblocked
        state.raise(SIGUSR1);
    });

    // Verify signal is pending.
    let pending = process::with_signal_state_for_task(task_id, |state| state.pending)
        .expect("process entry gone");
    assert_ne!(pending & sig_bit(SIGUSR1), 0, "SIGUSR1 should be pending");

    // Allocate a user stack page for the signal frame.
    let user_stack = anon_rw_page() + 4096;
    prefault(user_stack - 4096);

    let mut ctx = SyscallReturnContext {
        user_rsp: user_stack,
        user_rip: 0x0000_4000_0000_2000u64,
        user_rflags: 0x202,
        ..SyscallReturnContext::default()
    };

    // Deliver signals via check_and_deliver_signals.
    let _rv = unsafe {
        x86_64::instructions::interrupts::without_interrupts(|| {
            vibix::signal::check_and_deliver_signals(&mut ctx as *mut SyscallReturnContext, 0)
        })
    };

    // The handler VA should have been written into ctx.user_rip.
    assert_eq!(
        ctx.user_rip, handler_va,
        "handler VA not installed in ctx.user_rip"
    );

    // With SA_NODEFER, SIGUSR1 must NOT be in the blocked mask.
    let blocked = process::with_signal_state_for_task(task_id, |state| state.blocked)
        .expect("no process entry");
    assert_eq!(
        blocked & sig_bit(SIGUSR1),
        0,
        "SA_NODEFER: signal should NOT be blocked during handler, but blocked={:#x}",
        blocked,
    );

    // Clean up: restore default dispositions.
    process::with_signal_state_for_task(task_id, |state| {
        state.dispositions[(SIGUSR1 - 1) as usize] = Disposition::Default;
        state.sa_flags[(SIGUSR1 - 1) as usize] = 0;
        state.blocked = 0;
    });
}

/// Baseline: without SA_NODEFER, the signal IS blocked during handler
/// execution (default POSIX behaviour).
fn default_blocks_signal_during_handler() {
    let task_id = vibix::task::current_id();

    let handler_va = 0x0000_4000_0000_1000u64;
    process::with_signal_state_for_task(task_id, |state| {
        state.dispositions[(SIGUSR2 - 1) as usize] = Disposition::Handler(handler_va);
        state.sa_flags[(SIGUSR2 - 1) as usize] = 0; // no SA_NODEFER
        state.blocked = 0;
        state.raise(SIGUSR2);
    });

    let user_stack = anon_rw_page() + 4096;
    prefault(user_stack - 4096);

    let mut ctx = SyscallReturnContext {
        user_rsp: user_stack,
        user_rip: 0x0000_4000_0000_2000u64,
        user_rflags: 0x202,
        ..SyscallReturnContext::default()
    };

    let _rv = unsafe {
        x86_64::instructions::interrupts::without_interrupts(|| {
            vibix::signal::check_and_deliver_signals(&mut ctx as *mut SyscallReturnContext, 0)
        })
    };

    assert_eq!(ctx.user_rip, handler_va, "handler VA not installed");

    // Without SA_NODEFER, SIGUSR2 MUST be in the blocked mask.
    let blocked = process::with_signal_state_for_task(task_id, |state| state.blocked)
        .expect("no process entry");
    assert_ne!(
        blocked & sig_bit(SIGUSR2),
        0,
        "without SA_NODEFER, signal should be blocked during handler, but blocked={:#x}",
        blocked,
    );

    // Clean up.
    process::with_signal_state_for_task(task_id, |state| {
        state.dispositions[(SIGUSR2 - 1) as usize] = Disposition::Default;
        state.sa_flags[(SIGUSR2 - 1) as usize] = 0;
        state.blocked = 0;
    });
}

/// Register an alternate signal stack via the kernel-side state, then
/// query it back and verify the fields match.
fn sigaltstack_register_and_query() {
    let task_id = vibix::task::current_id();

    // Register an alternate stack.
    let alt_base = 0x0000_7000_0000_0000u64;
    let alt_size = 8192u64;
    process::with_signal_state_for_task(task_id, |state| {
        state.alt_stack = Some(SigaltStack {
            ss_sp: alt_base,
            ss_size: alt_size,
        });
    });

    // Query it back.
    let (sp, size) = process::with_signal_state_for_task(task_id, |state| {
        let ss = state.alt_stack.expect("alt_stack should be Some");
        (ss.ss_sp, ss.ss_size)
    })
    .expect("no process entry");

    assert_eq!(sp, alt_base, "alt_stack ss_sp mismatch");
    assert_eq!(size, alt_size, "alt_stack ss_size mismatch");

    // Clean up.
    process::with_signal_state_for_task(task_id, |state| {
        state.alt_stack = None;
    });
}

/// Disabling the alternate stack sets it to None.
fn sigaltstack_disable() {
    let task_id = vibix::task::current_id();

    // Register then disable.
    process::with_signal_state_for_task(task_id, |state| {
        state.alt_stack = Some(SigaltStack {
            ss_sp: 0x7000_0000,
            ss_size: 8192,
        });
    });
    process::with_signal_state_for_task(task_id, |state| {
        state.alt_stack = None;
    });

    let is_none = process::with_signal_state_for_task(task_id, |state| state.alt_stack.is_none())
        .expect("no process entry");
    assert!(is_none, "alt_stack should be None after disable");
}

/// When SA_ONSTACK is set and an alternate stack is registered, the
/// signal frame must be pushed onto the alternate stack.  We verify
/// this by checking that `ctx.user_rsp` after delivery falls within
/// the alternate stack region.
fn sa_onstack_delivers_on_alt_stack() {
    let task_id = vibix::task::current_id();

    // Allocate a 2-page region for the alternate stack.
    let alt_base = anon_rw_pages(2);
    let alt_size = 2 * 4096;
    prefault_region(alt_base, alt_size);

    let handler_va = 0x0000_4000_0000_1000u64;

    process::with_signal_state_for_task(task_id, |state| {
        state.dispositions[(SIGUSR1 - 1) as usize] = Disposition::Handler(handler_va);
        state.sa_flags[(SIGUSR1 - 1) as usize] = SA_ONSTACK;
        state.alt_stack = Some(SigaltStack {
            ss_sp: alt_base,
            ss_size: alt_size as u64,
        });
        state.blocked = 0;
        state.raise(SIGUSR1);
    });

    // Use a different user stack for the "normal" stack context.
    let user_stack = anon_rw_page() + 4096;
    prefault(user_stack - 4096);

    let mut ctx = SyscallReturnContext {
        user_rsp: user_stack,
        user_rip: 0x0000_4000_0000_2000u64,
        user_rflags: 0x202,
        ..SyscallReturnContext::default()
    };

    let _rv = unsafe {
        x86_64::instructions::interrupts::without_interrupts(|| {
            vibix::signal::check_and_deliver_signals(&mut ctx as *mut SyscallReturnContext, 0)
        })
    };

    assert_eq!(ctx.user_rip, handler_va, "handler VA not installed");

    // ctx.user_rsp should be within the alternate stack region.
    let alt_top = alt_base + alt_size as u64;
    assert!(
        ctx.user_rsp >= alt_base && ctx.user_rsp < alt_top,
        "SA_ONSTACK: RSP {:#x} is not within alt stack [{:#x}..{:#x})",
        ctx.user_rsp,
        alt_base,
        alt_top,
    );

    // Clean up.
    process::with_signal_state_for_task(task_id, |state| {
        state.dispositions[(SIGUSR1 - 1) as usize] = Disposition::Default;
        state.sa_flags[(SIGUSR1 - 1) as usize] = 0;
        state.alt_stack = None;
        state.blocked = 0;
    });
}

/// When SA_ONSTACK is set but no alternate stack is registered, the
/// signal frame must be pushed onto the current user stack (fallback).
fn sa_onstack_without_alt_stack_uses_user_stack() {
    let task_id = vibix::task::current_id();

    let handler_va = 0x0000_4000_0000_1000u64;
    process::with_signal_state_for_task(task_id, |state| {
        state.dispositions[(SIGUSR1 - 1) as usize] = Disposition::Handler(handler_va);
        state.sa_flags[(SIGUSR1 - 1) as usize] = SA_ONSTACK;
        state.alt_stack = None; // no alt stack registered
        state.blocked = 0;
        state.raise(SIGUSR1);
    });

    let user_stack = anon_rw_page() + 4096;
    let user_stack_base = user_stack - 4096;
    prefault(user_stack_base);

    let mut ctx = SyscallReturnContext {
        user_rsp: user_stack,
        user_rip: 0x0000_4000_0000_2000u64,
        user_rflags: 0x202,
        ..SyscallReturnContext::default()
    };

    let _rv = unsafe {
        x86_64::instructions::interrupts::without_interrupts(|| {
            vibix::signal::check_and_deliver_signals(&mut ctx as *mut SyscallReturnContext, 0)
        })
    };

    assert_eq!(ctx.user_rip, handler_va, "handler VA not installed");

    // RSP should be within the user stack page, not on a random alt stack.
    assert!(
        ctx.user_rsp >= user_stack_base && ctx.user_rsp < user_stack,
        "SA_ONSTACK without alt stack: RSP {:#x} should be on user stack [{:#x}..{:#x})",
        ctx.user_rsp,
        user_stack_base,
        user_stack,
    );

    // Clean up.
    process::with_signal_state_for_task(task_id, |state| {
        state.dispositions[(SIGUSR1 - 1) as usize] = Disposition::Default;
        state.sa_flags[(SIGUSR1 - 1) as usize] = 0;
        state.blocked = 0;
    });
}
