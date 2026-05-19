//! End-to-end integration test: SA_RESTART + SIGTTOU handler round-trip
//! preserves the original WRITE syscall arg registers (issue #499).
//!
//! ## What this exercises
//!
//! The full kernel-side signal path for a TOSTOP-gated `write(2)`:
//!
//! 1. A background-pgrp process calls `write` on a tty with TOSTOP set.
//! 2. `tty_check_tostop` raises SIGTTOU on the caller and returns
//!    `KERN_ERESTARTSYS`.
//! 3. `check_and_deliver_signals` sees `KERN_ERESTARTSYS` + a pending
//!    SIGTTOU with `Disposition::Handler` + `SA_RESTART`, so it:
//!      a. Rewinds `ctx.user_rip` by 2 (the SYSCALL insn length).
//!      b. Captures the seven Linux syscall-ABI registers from `ctx`
//!         (rax=WRITE nr, rdi=fd, rsi=buf, rdx=len, r10/r8/r9) into
//!         a `SigFrame` on the user stack.
//!      c. Redirects `ctx.user_rip` to the handler VA.
//! 4. The handler runs and returns via `sigreturn(2)`.
//! 5. The SIGRETURN dispatch arm reads the `SigFrame`, sees
//!    `restart_flag != 0`, writes the seven saved arg regs back into
//!    `ctx`, and asserts `SYSCALL_RESTART_PENDING` so the asm trampoline
//!    reloads them before SYSRETQ.
//! 6. The re-executed SYSCALL sees the original `(nr=WRITE, fd, buf, len)`.
//!
//! Without the fix from #522 / PR #528, step 5 would not restore the arg
//! regs and the restarted WRITE would see whatever the handler left in
//! rax/rdi/rsi/rdx/r10/r8/r9 — typically garbage.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::sync::atomic::Ordering;

use vibix::arch::x86_64::syscall::SYSCALL_RESTART_PENDING;
use vibix::arch::x86_64::uaccess;
use vibix::mem::pf::{MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE};
use vibix::process::{self, test_helpers as h};
use vibix::signal::frame::restore_signal_frame;
use vibix::signal::{
    check_and_deliver_signals, sig_bit, Disposition, SyscallReturnContext, SA_RESTART, SIGTTOU,
};
use vibix::tty::KERN_ERESTARTSYS;
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

fn run_tests() {
    let tests: &[(&str, &dyn Testable)] = &[
        (
            "tostop_sa_restart_handler_preserves_write_args",
            &(tostop_sa_restart_handler_preserves_write_args as fn()),
        ),
        (
            "sigframe_captures_rewound_rip_and_original_rsp",
            &(sigframe_captures_rewound_rip_and_original_rsp as fn()),
        ),
        (
            "handler_mask_restored_after_sigreturn",
            &(handler_mask_restored_after_sigreturn as fn()),
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

/// Touch the page via `copy_to_user` to demand-fault it in.
fn prefault(uva: u64) {
    x86_64::instructions::interrupts::without_interrupts(|| unsafe {
        let zero = [0u8; 8];
        uaccess::copy_to_user(uva as usize, &zero).expect("prefault copy_to_user failed");
    });
}

/// Sentinel handler VA — must be a valid user-space address. We never
/// actually jump here; the test only verifies that `ctx.user_rip` is
/// redirected to it.
const HANDLER_VA: u64 = 0x0000_4000_DEAD_0000;

/// Linux x86_64 syscall number for `write(2)`.
const NR_WRITE: u64 = 1;

/// Set up a process table entry for the current task (task_id=0) with a
/// SIGTTOU handler installed with SA_RESTART.
fn setup_process_with_sigttou_handler() {
    h::reset_table();
    // pid=0, parent=0, session=5, pgrp=5. task_id = pid as usize = 0,
    // which matches the current scheduler task after `task::init()`.
    h::insert(0, 0, 5, 5);

    // Install SA_RESTART handler for SIGTTOU.
    process::with_signal_state_for_task(0, |state| {
        state.dispositions[(SIGTTOU - 1) as usize] = Disposition::Handler(HANDLER_VA);
        state.sa_flags[(SIGTTOU - 1) as usize] = SA_RESTART;
    });
}

// ── Tests ────────────────────────────────────────────────────────────────

/// End-to-end: a write(fd=1, buf=0x4000_1000, len=13) on a TOSTOP tty
/// returns KERN_ERESTARTSYS with SIGTTOU pending. The full
/// `check_and_deliver_signals` → `push_signal_frame` → handler redirect
/// → `syscall_dispatch(SIGRETURN)` → arg-reg restore round-trip must
/// land back with the original WRITE args in the `SyscallReturnContext`
/// and `SYSCALL_RESTART_PENDING` asserted.
fn tostop_sa_restart_handler_preserves_write_args() {
    setup_process_with_sigttou_handler();

    // Allocate a user-space page for the signal frame (the user "stack").
    let user_stack_base = anon_rw_page();
    prefault(user_stack_base);
    let user_stack_top = user_stack_base + 4096;

    // The WRITE syscall args we want to survive the handler round-trip.
    let orig_rax = NR_WRITE; // syscall nr
    let orig_rdi = 1u64; // fd = stdout
    let orig_rsi = 0x0000_4000_1000u64; // buf pointer
    let orig_rdx = 13u64; // len
    let orig_r10 = 0u64; // unused by write but part of the contract
    let orig_r8 = 0u64;
    let orig_r9 = 0u64;

    // The user RIP at SYSCALL entry: rcx captures the instruction *after*
    // the SYSCALL. So `user_rip = instruction_after_syscall`. The rewind
    // subtracts 2 to land back *on* the SYSCALL instruction.
    let user_rip_after_syscall = 0x0000_4000_0042u64;

    // Build a SyscallReturnContext as the asm trampoline would leave it
    // after a WRITE syscall.
    let mut ctx = SyscallReturnContext {
        user_rax: orig_rax,
        user_rdi: orig_rdi,
        user_rsi: orig_rsi,
        user_rdx: orig_rdx,
        user_r10: orig_r10,
        user_r8: orig_r8,
        user_r9: orig_r9,
        user_rip: user_rip_after_syscall,
        user_rflags: 0x0000_0000_0000_0202u64,
        user_rsp: user_stack_top,
        ..SyscallReturnContext::default()
    };

    // Raise SIGTTOU on the current process (mimics tty_check_tostop).
    process::with_signal_state_for_task(0, |state| {
        state.raise(SIGTTOU);
    });

    // Clear the restart flag so we can verify it after the round-trip.
    SYSCALL_RESTART_PENDING.store(0, Ordering::Relaxed);

    // Drive check_and_deliver_signals as the asm trampoline would.
    let rv = unsafe {
        check_and_deliver_signals(&mut ctx as *mut SyscallReturnContext, KERN_ERESTARTSYS)
    };

    // rv should be 0 (ERESTARTSYS consumed by Restart decision).
    assert_eq!(
        rv, 0,
        "check_and_deliver_signals should return 0 on Restart, got {rv}"
    );

    // ctx.user_rip must now point at the handler VA.
    assert_eq!(
        ctx.user_rip, HANDLER_VA,
        "ctx.user_rip should be redirected to handler VA {:#x}, got {:#x}",
        HANDLER_VA, ctx.user_rip,
    );

    // ctx.user_rsp must have moved down (signal frame pushed).
    assert!(
        ctx.user_rsp < user_stack_top,
        "ctx.user_rsp should be below user_stack_top after frame push: rsp={:#x} top={:#x}",
        ctx.user_rsp,
        user_stack_top,
    );

    // SYSCALL_RESTART_PENDING must NOT be set yet — it would be wrong to
    // assert it before the handler runs; the handler's own sigreturn
    // syscall must not be hijacked into a replay.
    assert_eq!(
        SYSCALL_RESTART_PENDING.load(Ordering::Relaxed),
        0,
        "SYSCALL_RESTART_PENDING should not be set during handler execution"
    );

    let sigframe_rsp = ctx.user_rsp;

    // ── Verify the SigFrame contains the original WRITE arg regs ──
    let restored = unsafe {
        x86_64::instructions::interrupts::without_interrupts(|| restore_signal_frame(sigframe_rsp))
    }
    .expect("restore_signal_frame failed on the frame pushed by check_and_deliver_signals");

    assert_eq!(
        restored.syscall_regs.rax, orig_rax,
        "SigFrame rax (syscall nr) mismatch"
    );
    assert_eq!(
        restored.syscall_regs.rdi, orig_rdi,
        "SigFrame rdi (fd) mismatch"
    );
    assert_eq!(
        restored.syscall_regs.rsi, orig_rsi,
        "SigFrame rsi (buf) mismatch"
    );
    assert_eq!(
        restored.syscall_regs.rdx, orig_rdx,
        "SigFrame rdx (len) mismatch"
    );
    assert_eq!(restored.syscall_regs.r10, orig_r10, "SigFrame r10 mismatch");
    assert_eq!(restored.syscall_regs.r8, orig_r8, "SigFrame r8 mismatch");
    assert_eq!(restored.syscall_regs.r9, orig_r9, "SigFrame r9 mismatch");
    assert!(
        restored.restart_pending,
        "SigFrame restart_flag should be set"
    );

    // ── Simulate handler returning via sigreturn ──
    //
    // The handler has "run" (we don't actually execute it — the handler VA
    // is never jumped to in this test) and now issues sigreturn. At this
    // point ctx.user_rsp still points at the SigFrame (the handler's RSP
    // at entry is the SigFrame address; when the handler returns via the
    // pretcode trampoline, RSP is back at the SigFrame). Drive the
    // SIGRETURN dispatch arm.
    let mut sigreturn_ctx = SyscallReturnContext {
        user_rax: 0xDEAD_DEAD_DEAD_DEADu64, // handler clobbered rax
        user_rdi: 0xBAD0_BAD0_BAD0_BAD0u64, // handler clobbered rdi
        user_rsi: 0xBAD1_BAD1_BAD1_BAD1u64,
        user_rdx: 0xBAD2_BAD2_BAD2_BAD2u64,
        user_r10: 0xBAD3_BAD3_BAD3_BAD3u64,
        user_r8: 0xBAD4_BAD4_BAD4_BAD4u64,
        user_r9: 0xBAD5_BAD5_BAD5_BAD5u64,
        user_rip: 0xFFFF_FFFF_FFFF_FFFFu64, // will be overwritten by sigreturn
        user_rflags: 0,
        user_rsp: sigframe_rsp,
        ..SyscallReturnContext::default()
    };

    let rv = unsafe {
        vibix::arch::x86_64::syscall::syscall_dispatch(
            &mut sigreturn_ctx as *mut SyscallReturnContext,
            15, // SIGRETURN
            0,
            0,
            0,
            0,
            0,
            0,
        )
    };
    assert_eq!(rv, 0, "SIGRETURN returned non-zero: {rv}");

    // After sigreturn, the ctx must have the original WRITE args restored.
    assert_eq!(
        sigreturn_ctx.user_rax, orig_rax,
        "after sigreturn: rax (syscall nr) not restored: got {:#x}, want {:#x}",
        sigreturn_ctx.user_rax, orig_rax,
    );
    assert_eq!(
        sigreturn_ctx.user_rdi, orig_rdi,
        "after sigreturn: rdi (fd) not restored: got {:#x}, want {:#x}",
        sigreturn_ctx.user_rdi, orig_rdi,
    );
    assert_eq!(
        sigreturn_ctx.user_rsi, orig_rsi,
        "after sigreturn: rsi (buf) not restored: got {:#x}, want {:#x}",
        sigreturn_ctx.user_rsi, orig_rsi,
    );
    assert_eq!(
        sigreturn_ctx.user_rdx, orig_rdx,
        "after sigreturn: rdx (len) not restored: got {:#x}, want {:#x}",
        sigreturn_ctx.user_rdx, orig_rdx,
    );
    assert_eq!(
        sigreturn_ctx.user_r10, orig_r10,
        "after sigreturn: r10 not restored"
    );
    assert_eq!(
        sigreturn_ctx.user_r8, orig_r8,
        "after sigreturn: r8 not restored"
    );
    assert_eq!(
        sigreturn_ctx.user_r9, orig_r9,
        "after sigreturn: r9 not restored"
    );

    // The asm-trampoline flag must be asserted so the replay happens.
    assert_eq!(
        SYSCALL_RESTART_PENDING.load(Ordering::Relaxed),
        1,
        "SYSCALL_RESTART_PENDING not set after sigreturn — asm trampoline would skip reload"
    );

    // user_rip must be rewound to the SYSCALL instruction (2 bytes before
    // the original post-SYSCALL RIP).
    assert_eq!(
        sigreturn_ctx.user_rip,
        user_rip_after_syscall - 2,
        "after sigreturn: user_rip not rewound to SYSCALL instruction: got {:#x}, want {:#x}",
        sigreturn_ctx.user_rip,
        user_rip_after_syscall - 2,
    );

    // user_rsp must be the original user stack top (restored from the frame).
    assert_eq!(
        sigreturn_ctx.user_rsp, user_stack_top,
        "after sigreturn: user_rsp not restored: got {:#x}, want {:#x}",
        sigreturn_ctx.user_rsp, user_stack_top,
    );

    // Clean up global state.
    SYSCALL_RESTART_PENDING.store(0, Ordering::Relaxed);

    serial_println!("  PASS: tostop SA_RESTART handler preserves write(1, buf, 13) args");
}

/// Verify that the SigFrame pushed by `check_and_deliver_signals` records
/// the rewound RIP (pointing at the SYSCALL instruction, not the
/// instruction after it) and the original user RSP.
fn sigframe_captures_rewound_rip_and_original_rsp() {
    setup_process_with_sigttou_handler();

    let user_stack_base = anon_rw_page();
    prefault(user_stack_base);
    let user_stack_top = user_stack_base + 4096;

    let user_rip_after_syscall = 0x0000_4000_0100u64;

    let mut ctx = SyscallReturnContext {
        user_rax: NR_WRITE,
        user_rdi: 2, // fd = stderr
        user_rsi: 0x0000_4000_2000,
        user_rdx: 42,
        user_r10: 0,
        user_r8: 0,
        user_r9: 0,
        user_rip: user_rip_after_syscall,
        user_rflags: 0x202,
        user_rsp: user_stack_top,
        ..SyscallReturnContext::default()
    };

    process::with_signal_state_for_task(0, |state| {
        state.raise(SIGTTOU);
    });

    SYSCALL_RESTART_PENDING.store(0, Ordering::Relaxed);

    unsafe {
        check_and_deliver_signals(&mut ctx as *mut SyscallReturnContext, KERN_ERESTARTSYS);
    }

    let sigframe_rsp = ctx.user_rsp;
    let restored = unsafe {
        x86_64::instructions::interrupts::without_interrupts(|| restore_signal_frame(sigframe_rsp))
    }
    .expect("restore_signal_frame failed");

    // The saved RIP in the frame must be the rewound address (SYSCALL insn),
    // not the post-SYSCALL address.
    assert_eq!(
        restored.rip,
        user_rip_after_syscall - 2,
        "SigFrame saved rip should be the rewound SYSCALL address: got {:#x}, want {:#x}",
        restored.rip,
        user_rip_after_syscall - 2,
    );

    // The saved RSP in the frame must be the original user stack top.
    assert_eq!(
        restored.rsp, user_stack_top,
        "SigFrame saved rsp should be the original user stack top: got {:#x}, want {:#x}",
        restored.rsp, user_stack_top,
    );

    SYSCALL_RESTART_PENDING.store(0, Ordering::Relaxed);
}

/// The signal mask should be temporarily modified during handler execution
/// (SIGTTOU blocked) and restored by sigreturn.
fn handler_mask_restored_after_sigreturn() {
    setup_process_with_sigttou_handler();

    let user_stack_base = anon_rw_page();
    prefault(user_stack_base);
    let user_stack_top = user_stack_base + 4096;

    // Start with a known blocked mask (block SIGUSR1 = signal 10).
    let initial_mask = sig_bit(10);
    process::with_signal_state_for_task(0, |state| {
        state.blocked = initial_mask;
        state.raise(SIGTTOU);
    });

    let mut ctx = SyscallReturnContext {
        user_rax: NR_WRITE,
        user_rdi: 1,
        user_rsi: 0x0000_4000_1000,
        user_rdx: 5,
        user_r10: 0,
        user_r8: 0,
        user_r9: 0,
        user_rip: 0x0000_4000_0200,
        user_rflags: 0x202,
        user_rsp: user_stack_top,
        ..SyscallReturnContext::default()
    };

    SYSCALL_RESTART_PENDING.store(0, Ordering::Relaxed);

    unsafe {
        check_and_deliver_signals(&mut ctx as *mut SyscallReturnContext, KERN_ERESTARTSYS);
    }

    // During handler execution, SIGTTOU should be blocked.
    let blocked_during_handler =
        process::with_signal_state_for_task(0, |state| state.blocked).unwrap();
    assert_ne!(
        blocked_during_handler & sig_bit(SIGTTOU),
        0,
        "SIGTTOU should be blocked during handler execution"
    );
    // SIGUSR1 should still be blocked too.
    assert_ne!(
        blocked_during_handler & sig_bit(10),
        0,
        "SIGUSR1 should still be blocked during handler"
    );

    // Simulate sigreturn.
    let sigframe_rsp = ctx.user_rsp;
    let mut sigreturn_ctx = SyscallReturnContext {
        user_rax: 0,
        user_rdi: 0,
        user_rsi: 0,
        user_rdx: 0,
        user_r10: 0,
        user_r8: 0,
        user_r9: 0,
        user_rip: 0,
        user_rflags: 0,
        user_rsp: sigframe_rsp,
        ..SyscallReturnContext::default()
    };

    unsafe {
        vibix::arch::x86_64::syscall::syscall_dispatch(
            &mut sigreturn_ctx as *mut SyscallReturnContext,
            15, // SIGRETURN
            0,
            0,
            0,
            0,
            0,
            0,
        );
    }

    // After sigreturn, the blocked mask should be restored to the
    // pre-delivery state (initial_mask = SIGUSR1 only, SIGTTOU unblocked).
    let restored_mask = process::with_signal_state_for_task(0, |state| state.blocked).unwrap();
    assert_eq!(
        restored_mask, initial_mask,
        "signal mask not restored after sigreturn: got {:#x}, want {:#x}",
        restored_mask, initial_mask,
    );

    SYSCALL_RESTART_PENDING.store(0, Ordering::Relaxed);
}
