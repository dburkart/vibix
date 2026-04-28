//! Integration test: SA_RESTART + user handler preserves syscall arg
//! registers across the handler round-trip (issue #522).
//!
//! ## What the bug is
//!
//! Pre-#522: when `check_and_deliver_signals` processed a `KERN_ERESTARTSYS`
//! with a handler + SA_RESTART, it rewound `ctx.user_rip` back to the
//! SYSCALL instruction but deferred setting `SYSCALL_RESTART_PENDING`
//! (the asm-trampoline flag that reloads saved arg regs). The rationale
//! was that the restart happens from `sigreturn`, not at the current
//! SYSRETQ — but `sys_sigreturn` only restored `rip/rflags/rsp`. The
//! re-executed SYSCALL therefore picked up whatever the handler had
//! left in `rax/rdi/rsi/rdx/r10/r8/r9`, silently corrupting the restart.
//!
//! ## What we verify here
//!
//! The kernel-side contract has three halves:
//!
//! 1. `push_signal_frame` captures the seven Linux syscall-ABI registers
//!    (rax, rdi, rsi, rdx, r10, r8, r9) into the `SigFrame` `gregs` slots
//!    that `restore_signal_frame` reads back from.
//! 2. When the frame was pushed on an SA_RESTART-ed ERESTARTSYS path
//!    (`restart_pending = true`), the `SIGRETURN` dispatch arm writes the
//!    recovered arg regs into the caller's `SyscallReturnContext` and
//!    asserts `SYSCALL_RESTART_PENDING` so the asm trampoline reloads
//!    those slots on its way to SYSRETQ.
//! 3. When the frame was pushed on a non-restart path
//!    (`restart_pending = false`), the `SIGRETURN` dispatch arm MUST NOT
//!    clobber the ctx's `user_rax..user_r9` (they still hold the
//!    post-syscall result the handler was interrupted over) and MUST
//!    NOT assert `SYSCALL_RESTART_PENDING`. This is the regression
//!    surface called out in the #528 review.
//!
//! End-to-end ring-3 SA_RESTART coverage (a user handler that actually
//! clobbers arg regs and a syscall like `read`/`write` that restarts) is
//! provided by the shell-level smoke test; the kernel-side invariants
//! verified here are what make that end-to-end behaviour correct.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::sync::atomic::Ordering;

use vibix::arch::x86_64::syscall::SYSCALL_RESTART_PENDING;
use vibix::arch::x86_64::uaccess;
use vibix::mem::pf::{MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE};
use vibix::signal::frame::{
    push_fault_signal_frame, push_signal_frame, restore_signal_frame, SavedSyscallRegs,
};
use vibix::signal::{SyscallReturnContext, SIGUSR1};
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
            "syscall_regs_roundtrip_through_sigframe",
            &(syscall_regs_roundtrip_through_sigframe as fn()),
        ),
        (
            "zero_syscall_regs_are_preserved_verbatim",
            &(zero_syscall_regs_are_preserved_verbatim as fn()),
        ),
        (
            "fault_frame_leaves_syscall_gregs_zero",
            &(fault_frame_leaves_syscall_gregs_zero as fn()),
        ),
        (
            "sigreturn_dispatch_writes_ctx_and_asserts_restart",
            &(sigreturn_dispatch_writes_ctx_and_asserts_restart as fn()),
        ),
        (
            "sigreturn_dispatch_leaves_ctx_alone_when_not_restart",
            &(sigreturn_dispatch_leaves_ctx_alone_when_not_restart as fn()),
        ),
        (
            "restart_flag_roundtrips_through_sigframe",
            &(restart_flag_roundtrips_through_sigframe as fn()),
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

/// Touch the page so it is demand-faulted in before we start doing STAC-
/// bracketed copies. Writing a zero by way of the sanctioned `copy_to_user`
/// both faults in the page and exercises the user-write path.
fn prefault(uva: u64) {
    x86_64::instructions::interrupts::without_interrupts(|| unsafe {
        let zero = [0u8; 8];
        uaccess::copy_to_user(uva as usize, &zero).expect("prefault copy_to_user failed");
    });
}

fn distinct_regs() -> SavedSyscallRegs {
    // Distinct non-zero sentinels so a mis-wired gregs index in either
    // push or restore surfaces as a cross-field swap (the "pairwise
    // distinct" unit test catches index collisions; these catch value
    // aliasing across the copy).
    SavedSyscallRegs {
        rax: 0x0123_4567_89AB_CDEFu64,
        rdi: 0x1111_1111_1111_1111u64,
        rsi: 0x2222_2222_2222_2222u64,
        rdx: 0x3333_3333_3333_3333u64,
        r10: 0x4444_4444_4444_4444u64,
        r8: 0x5555_5555_5555_5555u64,
        r9: 0x6666_6666_6666_6666u64,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

/// A `SigFrame` pushed with a specific set of syscall arg regs must be
/// restored with exactly the same values. This is the core #522 property:
/// the seven-register payload round-trips across the handler.
fn syscall_regs_roundtrip_through_sigframe() {
    let user_stack = anon_rw_page() + 4096; // top of the page; sig frame grows down
    prefault(user_stack - 4096);

    let regs = distinct_regs();
    // Arbitrary RIP/RFLAGS/mask to verify the unrelated slots are
    // undisturbed by the new arg-reg plumbing.
    let saved_rip = 0x0000_4000_0000_1234u64;
    let saved_rflags = 0x0000_0000_0000_0202u64;
    let saved_mask = 0xDEAD_BEEF_0000_0001u64;

    let new_rsp = unsafe {
        x86_64::instructions::interrupts::without_interrupts(|| {
            push_signal_frame(
                user_stack,
                SIGUSR1,
                saved_rip,
                saved_rflags,
                saved_mask,
                regs,
                /* restart_pending = */ true,
            )
        })
    }
    .expect("push_signal_frame rejected a valid user page");

    let restored = unsafe {
        x86_64::instructions::interrupts::without_interrupts(|| restore_signal_frame(new_rsp))
    }
    .expect("restore_signal_frame rejected the frame we just pushed");

    // Baseline fields unaffected by the #522 change.
    assert_eq!(restored.rip, saved_rip, "rip not preserved");
    assert_eq!(restored.rflags, saved_rflags, "rflags not preserved");
    assert_eq!(restored.rsp, user_stack, "rsp not preserved");
    assert_eq!(restored.saved_mask, saved_mask, "saved_mask not preserved");

    // The #522 payload: every syscall arg register must round-trip.
    assert_eq!(
        restored.syscall_regs, regs,
        "syscall arg regs did not round-trip through SigFrame: got {:#x?}, want {:#x?}",
        restored.syscall_regs, regs
    );
}

/// All-zero arg regs are a valid input (some syscalls take zero args);
/// they must round-trip unchanged, not be confused with "uninitialised".
fn zero_syscall_regs_are_preserved_verbatim() {
    let user_stack = anon_rw_page() + 4096;
    prefault(user_stack - 4096);

    let regs = SavedSyscallRegs::default();
    let new_rsp = unsafe {
        x86_64::instructions::interrupts::without_interrupts(|| {
            push_signal_frame(user_stack, SIGUSR1, 0x4000_0000, 0x202, 0, regs, true)
        })
    }
    .expect("push_signal_frame failed");
    let restored = unsafe {
        x86_64::instructions::interrupts::without_interrupts(|| restore_signal_frame(new_rsp))
    }
    .expect("restore_signal_frame failed");
    assert_eq!(restored.syscall_regs, regs);
}

/// Fault-path sigframes do not interrupt a SYSCALL instruction — the
/// interrupted PC is ordinary user code. `push_fault_signal_frame` must
/// leave the syscall-arg gregs at zero so `sys_sigreturn` cannot be
/// tricked into replaying a SYSCALL with attacker-chosen args after a
/// fault-signal handler returns.
fn fault_frame_leaves_syscall_gregs_zero() {
    let user_stack = anon_rw_page() + 4096;
    prefault(user_stack - 4096);

    let new_rsp = unsafe {
        x86_64::instructions::interrupts::without_interrupts(|| {
            push_fault_signal_frame(
                user_stack,
                SIGUSR1,
                0x4000_0000,
                0x202,
                0,
                /* fault_addr = */ 0xDEAD_F000,
            )
        })
    }
    .expect("push_fault_signal_frame rejected a valid user page");

    let restored = unsafe {
        x86_64::instructions::interrupts::without_interrupts(|| restore_signal_frame(new_rsp))
    }
    .expect("restore_signal_frame failed on a fault frame");

    assert_eq!(
        restored.syscall_regs,
        SavedSyscallRegs::default(),
        "fault frame leaked non-zero syscall-arg gregs: {:#x?}",
        restored.syscall_regs
    );
}

/// End-to-end kernel-side drive of the SIGRETURN dispatch arm: we push
/// a `SigFrame` with distinct arg-reg sentinels onto user-mapped memory,
/// then call `syscall_dispatch` with `nr = SIGRETURN` as the asm
/// trampoline would. The arm must (a) pull the seven arg regs out of
/// the frame and stamp them into the caller's `SyscallReturnContext`,
/// and (b) raise `SYSCALL_RESTART_PENDING` so the trampoline's restart-
/// restore branch reloads them on the way out of SYSRETQ. Without (a),
/// the interrupted SYSCALL replays with handler-clobbered args; without
/// (b), the trampoline's common path drops them on the floor. Both are
/// the root cause fixed by #522.
fn sigreturn_dispatch_writes_ctx_and_asserts_restart() {
    let user_stack = anon_rw_page() + 4096;
    prefault(user_stack - 4096);

    let regs = distinct_regs();
    let new_rsp = unsafe {
        x86_64::instructions::interrupts::without_interrupts(|| {
            push_signal_frame(
                user_stack,
                SIGUSR1,
                0x4000_0000,
                0x202,
                0,
                regs,
                /* restart_pending = */ true,
            )
        })
    }
    .expect("push_signal_frame failed");

    // Build a SyscallReturnContext laid out as the asm trampoline would
    // leave it: user_rsp already pointing at the SigFrame (that's how
    // the handler's sigreturn syscall arrives), everything else is
    // scratch from the handler and must be overwritten by the dispatch
    // arm. Pre-fill with a sentinel so "not written" is distinguishable
    // from "written to zero by the handler".
    const SENTINEL: u64 = 0xAAAA_BBBB_CCCC_DDDDu64;
    let mut ctx = SyscallReturnContext {
        user_rax: SENTINEL,
        user_rdi: SENTINEL,
        user_rsi: SENTINEL,
        user_rdx: SENTINEL,
        user_r10: SENTINEL,
        user_r8: SENTINEL,
        user_r9: SENTINEL,
        user_rip: SENTINEL,
        user_rflags: SENTINEL,
        user_rsp: new_rsp,
        ..SyscallReturnContext::default()
    };

    SYSCALL_RESTART_PENDING.store(0, Ordering::Relaxed);

    // Drive the SIGRETURN dispatch arm exactly as the asm trampoline
    // would: `nr = 15`, ctx by pointer, args are don't-cares.
    let rv = unsafe {
        x86_64::instructions::interrupts::without_interrupts(|| {
            vibix::arch::x86_64::syscall::syscall_dispatch(
                &mut ctx as *mut SyscallReturnContext,
                15, // SIGRETURN
                0,
                0,
                0,
                0,
                0,
                0,
            )
        })
    };
    assert_eq!(rv, 0, "SIGRETURN returned non-zero: {rv}");

    // The dispatch arm must have written every syscall arg slot in the
    // ctx from the frame we pushed.
    assert_eq!(ctx.user_rax, regs.rax, "rax not restored into ctx");
    assert_eq!(ctx.user_rdi, regs.rdi, "rdi not restored into ctx");
    assert_eq!(ctx.user_rsi, regs.rsi, "rsi not restored into ctx");
    assert_eq!(ctx.user_rdx, regs.rdx, "rdx not restored into ctx");
    assert_eq!(ctx.user_r10, regs.r10, "r10 not restored into ctx");
    assert_eq!(ctx.user_r8, regs.r8, "r8 not restored into ctx");
    assert_eq!(ctx.user_r9, regs.r9, "r9 not restored into ctx");

    // And the asm-trampoline flag that actually fires the reload.
    assert_eq!(
        SYSCALL_RESTART_PENDING.load(Ordering::Relaxed),
        1,
        "SIGRETURN dispatch did not assert SYSCALL_RESTART_PENDING; \
         the trampoline's reload branch would be skipped at SYSRETQ"
    );

    // Leave global state clean for neighbouring tests.
    SYSCALL_RESTART_PENDING.store(0, Ordering::Relaxed);
}

/// Regression for the #528 review finding: on a non-SA_RESTART
/// sigreturn, the dispatch arm must leave `ctx.user_rax..user_r9`
/// untouched and NOT assert `SYSCALL_RESTART_PENDING`. Otherwise the
/// post-syscall return value the handler was interrupted over (still
/// sitting in `user_rax`) gets silently clobbered back to the
/// syscall-entry rax on its way to SYSRETQ, and the asm trampoline
/// replays an unrelated syscall with the frame's rdi..r9.
fn sigreturn_dispatch_leaves_ctx_alone_when_not_restart() {
    let user_stack = anon_rw_page() + 4096;
    prefault(user_stack - 4096);

    // Same distinct sentinels as the restart-case test, but pushed with
    // `restart_pending = false` — this mirrors the normal "handler ran,
    // now returning" path where `check_and_deliver_signals` did not
    // rewind RIP for a syscall replay.
    let frame_regs = distinct_regs();
    let new_rsp = unsafe {
        x86_64::instructions::interrupts::without_interrupts(|| {
            push_signal_frame(
                user_stack,
                SIGUSR1,
                0x4000_0000,
                0x202,
                0,
                frame_regs,
                /* restart_pending = */ false,
            )
        })
    }
    .expect("push_signal_frame failed");

    // Pre-fill ctx with a different, ctx-specific set of sentinels so
    // any accidental write from the dispatch arm shows up as a
    // frame-regs value aliasing over the sentinel.
    const CTX_RAX: u64 = 0xBEEF_0000_0000_0042u64; // plausible syscall rv
    const CTX_RDI: u64 = 0xBEEF_0000_0000_00D1u64;
    const CTX_RSI: u64 = 0xBEEF_0000_0000_0051u64;
    const CTX_RDX: u64 = 0xBEEF_0000_0000_00D2u64;
    const CTX_R10: u64 = 0xBEEF_0000_0000_0010u64;
    const CTX_R8: u64 = 0xBEEF_0000_0000_0008u64;
    const CTX_R9: u64 = 0xBEEF_0000_0000_0009u64;
    let mut ctx = SyscallReturnContext {
        user_rax: CTX_RAX,
        user_rdi: CTX_RDI,
        user_rsi: CTX_RSI,
        user_rdx: CTX_RDX,
        user_r10: CTX_R10,
        user_r8: CTX_R8,
        user_r9: CTX_R9,
        user_rip: 0,
        user_rflags: 0,
        user_rsp: new_rsp,
        ..SyscallReturnContext::default()
    };

    SYSCALL_RESTART_PENDING.store(0, Ordering::Relaxed);

    let rv = unsafe {
        x86_64::instructions::interrupts::without_interrupts(|| {
            vibix::arch::x86_64::syscall::syscall_dispatch(
                &mut ctx as *mut SyscallReturnContext,
                15, // SIGRETURN
                0,
                0,
                0,
                0,
                0,
                0,
            )
        })
    };
    assert_eq!(rv, 0, "SIGRETURN returned non-zero: {rv}");

    // Each arg slot must be the ctx sentinel, NOT the frame payload.
    // If any of these drift to the frame value, the dispatch arm is
    // writing back on a path where `restart_pending` is false — the
    // exact bug called out in the #528 review.
    assert_eq!(
        ctx.user_rax, CTX_RAX,
        "non-restart SIGRETURN clobbered ctx.user_rax: got {:#x}, frame had {:#x}",
        ctx.user_rax, frame_regs.rax
    );
    assert_eq!(ctx.user_rdi, CTX_RDI, "non-restart SIGRETURN clobbered rdi");
    assert_eq!(ctx.user_rsi, CTX_RSI, "non-restart SIGRETURN clobbered rsi");
    assert_eq!(ctx.user_rdx, CTX_RDX, "non-restart SIGRETURN clobbered rdx");
    assert_eq!(ctx.user_r10, CTX_R10, "non-restart SIGRETURN clobbered r10");
    assert_eq!(ctx.user_r8, CTX_R8, "non-restart SIGRETURN clobbered r8");
    assert_eq!(ctx.user_r9, CTX_R9, "non-restart SIGRETURN clobbered r9");

    // And the global flag must stay cleared — if set, the asm trampoline
    // would reload the (now-stale) user_rax..user_r9 from ctx and emit
    // a spurious syscall replay at SYSRETQ.
    assert_eq!(
        SYSCALL_RESTART_PENDING.load(Ordering::Relaxed),
        0,
        "non-restart SIGRETURN spuriously asserted SYSCALL_RESTART_PENDING"
    );
}

/// The `restart_pending` bit itself round-trips through the SigFrame —
/// push-then-restore with `true` must observe `true`, with `false` must
/// observe `false`. Belt-and-braces: the two behavioural tests above
/// already depend on this, but an explicit round-trip check pins the
/// failure to "restart bit wrong" if the underlying frame slot ever
/// drifts to a wrong offset.
fn restart_flag_roundtrips_through_sigframe() {
    for want in [true, false] {
        let user_stack = anon_rw_page() + 4096;
        prefault(user_stack - 4096);
        let new_rsp = unsafe {
            x86_64::instructions::interrupts::without_interrupts(|| {
                push_signal_frame(
                    user_stack,
                    SIGUSR1,
                    0x4000_0000,
                    0x202,
                    0,
                    SavedSyscallRegs::default(),
                    want,
                )
            })
        }
        .expect("push_signal_frame failed");
        let restored = unsafe {
            x86_64::instructions::interrupts::without_interrupts(|| restore_signal_frame(new_rsp))
        }
        .expect("restore_signal_frame failed");
        assert_eq!(
            restored.restart_pending, want,
            "restart_pending did not round-trip: pushed {want}, got {}",
            restored.restart_pending
        );
    }
}
