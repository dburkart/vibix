//! POSIX signal state and delivery logic.
//!
//! ## Signal model
//!
//! Each process carries a [`SignalState`] (wrapped in `Arc<Mutex<_>>`) that
//! holds:
//!
//! - `pending` — bitmask of signals that have been raised but not yet
//!   delivered.  Bit `n` = signal `n+1` (signals are 1-indexed; bits are
//!   0-indexed for compactness).
//! - `blocked` — the process signal mask (`sigprocmask`).  Pending bits that
//!   are also set in `blocked` are deferred until unblocked or the signal is
//!   a default-action terminal signal.
//! - `dispositions` — per-signal action: `SIG_DFL`, `SIG_IGN`, or a user
//!   handler address.
//!
//! ## Delivery point
//!
//! Signals are delivered at every kernel→userspace boundary:
//!
//! 1. **Syscall return** — `check_and_deliver_signals` is called from the
//!    `syscall_entry` asm trampoline just before `SYSRETQ`, passing a mutable
//!    pointer to the saved `[user_rip, user_rflags, user_rsp]` context on the
//!    kernel stack.  If a signal is pending, the handler pushes a `SigFrame`
//!    onto the user stack and rewrites those saved values so `SYSRETQ` lands
//!    in the signal handler rather than the original user RIP.
//!
//! 2. **Exception return from ring-3** — the `#PF` handler (and future
//!    `#GP`) calls [`deliver_fault_signal_iret`] which directly modifies the
//!    `InterruptStackFrame` so `IRETQ` redirects to the signal handler.
//!
//! ## Limitations (known, tracked as follow-ups)
//!
//! - FPU state (`fpstate_ptr` in `SigFrame`) is always null — signals
//!   delivered to a task using SSE/x87 will see corrupted FP registers.
//! - `SA_NODEFER` is not honoured. `SA_RESTART` is honoured by the
//!   syscall trampoline's `KERN_ERESTARTSYS` path; other `sa_flags`
//!   bits round-trip through `sigaction(2)` but are otherwise ignored.
//! - Real-time signals (`SIGRTMIN`..`SIGRTMAX`) are not implemented.
//! - `sigaltstack` is not implemented.
//! - Multi-threaded signal delivery is not implemented (single-CPU, single-
//!   threaded for now).

pub mod frame;

use crate::arch::x86_64::uaccess;

// ── Signal numbers (Linux x86_64) ────────────────────────────────────────

pub const SIGHUP: u8 = 1;
pub const SIGINT: u8 = 2;
pub const SIGQUIT: u8 = 3;
pub const SIGILL: u8 = 4;
pub const SIGTRAP: u8 = 5;
pub const SIGABRT: u8 = 6;
pub const SIGBUS: u8 = 7;
pub const SIGFPE: u8 = 8;
pub const SIGKILL: u8 = 9;
pub const SIGUSR1: u8 = 10;
pub const SIGSEGV: u8 = 11;
pub const SIGUSR2: u8 = 12;
pub const SIGPIPE: u8 = 13;
pub const SIGALRM: u8 = 14;
pub const SIGTERM: u8 = 15;
pub const SIGCHLD: u8 = 17;
pub const SIGCONT: u8 = 18;
pub const SIGSTOP: u8 = 19;
pub const SIGTSTP: u8 = 20;
pub const SIGTTIN: u8 = 21;
pub const SIGTTOU: u8 = 22;

/// Maximum signal number supported.  Linux defines 64 but we only need the
/// standard 31 for now.  The bitmask is a `u64` so the representation is
/// future-proof.
pub const NSIG: u8 = 64;

// ── Sigaction disposition ─────────────────────────────────────────────────

/// `SIG_DFL` — default action for the signal.
pub const SIG_DFL: u64 = 0;
/// `SIG_IGN` — ignore the signal.
pub const SIG_IGN: u64 = 1;

// ── Sigaction flags (Linux values) ────────────────────────────────────────

/// `SA_RESTART` — restart syscalls that return `KERN_ERESTARTSYS` when this
/// signal is delivered via a user handler. Without this flag, the syscall
/// is converted to `-EINTR` instead.
pub const SA_RESTART: u64 = 0x1000_0000;

/// Per-signal disposition.
#[derive(Clone, Copy, Debug)]
pub enum Disposition {
    /// Default kernel action (see [`default_action`]).
    Default,
    /// Ignore — no action taken.
    Ignore,
    /// Call the userspace handler at this VA.
    Handler(u64),
}

impl Disposition {
    fn from_handler_ptr(ptr: u64) -> Self {
        match ptr {
            SIG_DFL => Disposition::Default,
            SIG_IGN => Disposition::Ignore,
            va => Disposition::Handler(va),
        }
    }

    fn to_handler_ptr(self) -> u64 {
        match self {
            Disposition::Default => SIG_DFL,
            Disposition::Ignore => SIG_IGN,
            Disposition::Handler(va) => va,
        }
    }
}

/// What the kernel does when a signal's disposition is `SIG_DFL`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DefaultAction {
    /// Terminate the process (exit with signal number as status).
    Terminate,
    /// Ignore — no action.
    Ignore,
    /// Stop the process (not yet implemented; treated as Ignore).
    Stop,
    /// Continue a stopped process (not yet implemented; treated as Ignore).
    Continue,
}

/// Return the default action for signal `sig` (1-indexed).
pub fn default_action(sig: u8) -> DefaultAction {
    match sig {
        SIGCHLD => DefaultAction::Ignore,
        SIGCONT => DefaultAction::Continue,
        SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => DefaultAction::Stop,
        SIGURG | 28 => DefaultAction::Ignore, // SIGWINCH=28, SIGURG=23
        _ => DefaultAction::Terminate,
    }
}

const SIGURG: u8 = 23;

// ── Signal mask helpers ───────────────────────────────────────────────────

/// Convert a 1-indexed signal number to a bitmask bit.  Returns `0` for
/// out-of-range signal numbers.
#[inline]
pub fn sig_bit(sig: u8) -> u64 {
    if sig == 0 || sig > NSIG {
        0
    } else {
        1u64 << (sig - 1)
    }
}

/// True if `sig` cannot be caught, blocked, or ignored (SIGKILL / SIGSTOP).
#[inline]
pub fn is_unblockable(sig: u8) -> bool {
    sig == SIGKILL || sig == SIGSTOP
}

// ── sigprocmask `how` values ──────────────────────────────────────────────

pub const SIG_BLOCK: u64 = 0;
pub const SIG_UNBLOCK: u64 = 1;
pub const SIG_SETMASK: u64 = 2;

// ── Per-process signal state ──────────────────────────────────────────────

/// Per-process signal state — one instance per `ProcessEntry`, shared via
/// `Arc<Mutex<SignalState>>`.
pub struct SignalState {
    /// Bitmask of pending (raised, not yet delivered) signals.
    pub pending: u64,
    /// Current signal mask — bits set here are blocked (deferred).
    /// SIGKILL and SIGSTOP cannot be blocked regardless of this value.
    pub blocked: u64,
    /// Per-signal disposition table (indexed 0 = signal 1).
    pub dispositions: [Disposition; NSIG as usize],
    /// Per-signal `sa_flags` (Linux `struct sigaction.sa_flags`). Only
    /// `SA_RESTART` is honoured today; other bits round-trip through
    /// `sigaction(2)` but are otherwise ignored.
    pub sa_flags: [u64; NSIG as usize],
}

impl SignalState {
    pub fn new() -> Self {
        let mut dispositions = [Disposition::Default; NSIG as usize];
        // SIGCHLD: default is to ignore (SIG_DFL for SIGCHLD means ignore
        // on Linux unless SA_NOCLDWAIT / SA_NOCLDSTOP is used).
        dispositions[(SIGCHLD - 1) as usize] = Disposition::Ignore;
        Self {
            pending: 0,
            blocked: 0,
            dispositions,
            sa_flags: [0; NSIG as usize],
        }
    }

    /// Raise signal `sig` on this process: set the pending bit.
    pub fn raise(&mut self, sig: u8) {
        self.pending |= sig_bit(sig);
    }

    /// Return the lowest-numbered signal that is both pending and not blocked
    /// (unless it is SIGKILL/SIGSTOP which bypass the blocked mask), then
    /// clear the pending bit.
    ///
    /// Returns `None` if no actionable signal is pending.
    pub fn pop_next_pending(&mut self) -> Option<u8> {
        // Deliverable = pending & (~blocked | unblockable_bits)
        let unblockable = sig_bit(SIGKILL) | sig_bit(SIGSTOP);
        let deliverable = self.pending & (!self.blocked | unblockable);
        if deliverable == 0 {
            return None;
        }
        // Lowest-numbered pending signal first (POSIX requirement for
        // non-real-time signals).
        let bit = deliverable & deliverable.wrapping_neg(); // lowest set bit
        self.pending &= !bit;
        // Convert bit position back to 1-indexed signal number.
        Some(bit.trailing_zeros() as u8 + 1)
    }

    /// Apply `sigprocmask(how, set)` and return the old mask.
    ///
    /// Always strips SIGKILL and SIGSTOP from the result (they cannot be
    /// blocked).
    pub fn update_mask(&mut self, how: u64, set: u64) -> u64 {
        let old = self.blocked;
        let unblockable = sig_bit(SIGKILL) | sig_bit(SIGSTOP);
        let new_mask = match how {
            SIG_BLOCK => old | set,
            SIG_UNBLOCK => old & !set,
            SIG_SETMASK => set,
            _ => old, // invalid `how` — leave mask unchanged
        };
        self.blocked = new_mask & !unblockable;
        old
    }
}

// ── Process-level helpers ─────────────────────────────────────────────────

/// Raise signal `sig` on the process with the given `task_id`.
///
/// Looks up the process entry to find the `Arc<Mutex<SignalState>>`, sets
/// the pending bit, then wakes the task if it is currently blocked.
pub fn raise_signal_on_task(task_id: usize, sig: u8) {
    crate::process::with_signal_state_for_task(task_id, |state| {
        state.raise(sig);
    });
    // Wake the target task in case it is sleeping — it will check for
    // pending signals at its next syscall return.
    crate::task::wake(task_id);
}

/// Raise signal `sig` on the process identified by `pid`.  Returns `-ESRCH`
/// if the pid is not found, `-EINVAL` for an out-of-range signal.
pub fn raise_signal_on_pid(pid: u32, sig: u8) -> i64 {
    if sig > NSIG {
        return -22; // EINVAL
    }
    match crate::process::task_id_for_pid(pid) {
        Some(task_id) => {
            raise_signal_on_task(task_id, sig);
            0
        }
        None => -3, // ESRCH
    }
}

/// Send signal `sig` to every live member of process group `pgid`.
///
/// Returns the number of processes the signal was delivered to. `pgid == 0`
/// yields `0`. `-EINVAL` (-22) for `sig == 0` or out-of-range. Unlike
/// POSIX `kill()`, the "signal 0 = existence check" form has no caller in
/// the kernel — the N_TTY ISIG fast path only ever sends 1..=NSIG — so the
/// safer choice is to reject it outright rather than silently walk the
/// pgrp and wake tasks. Used by the N_TTY ISIG fast path (#431); the
/// caller reads `tty.ctrl.pgrp_snapshot` lock-free and passes the result
/// here.
pub fn send_to_pgrp(pgid: u32, sig: u8) -> i64 {
    if sig == 0 || sig > NSIG {
        return -22; // EINVAL
    }
    if pgid == 0 {
        return 0;
    }
    let mut pids: alloc::vec::Vec<u32> = alloc::vec::Vec::new();
    crate::process::collect_pgrp_members(pgid, &mut pids);
    let mut delivered: i64 = 0;
    for pid in pids {
        if raise_signal_on_pid(pid, sig) == 0 {
            delivered += 1;
        }
    }
    delivered
}

// ── Syscall handlers ──────────────────────────────────────────────────────

/// `sigaction(sig, act_uva, oldact_uva)` — register or query a signal
/// handler.
///
/// `act_uva` and `oldact_uva` are user pointers to `struct sigaction`
/// (Linux x86_64 layout: `sa_handler: u64, sa_flags: u64, sa_restorer: u64,
/// sa_mask: u64`).  `sa_handler` and `sa_flags` round-trip through the
/// kernel; `sa_restorer` and `sa_mask` are read/written as zero. Of the
/// flag bits only `SA_RESTART` is honoured (by the syscall trampoline's
/// `KERN_ERESTARTSYS` path).
///
/// # Safety
/// `act_uva` and `oldact_uva` are user VA pointers validated via
/// `uaccess::check_user_range`.
pub unsafe fn sys_sigaction(sig: u64, act_uva: u64, oldact_uva: u64) -> i64 {
    let sig = sig as u8;
    if sig == 0 || sig > NSIG || is_unblockable(sig) && act_uva != 0 {
        return -22; // EINVAL
    }

    let task_id = crate::task::current_id();
    let result = crate::process::with_signal_state_for_task(task_id, |state| {
        let old_disp = state.dispositions[(sig - 1) as usize];
        let old_flags = state.sa_flags[(sig - 1) as usize];

        // Write old disposition to userspace if requested.
        if oldact_uva != 0 {
            let mut sa: [u8; 32] = [0u8; 32];
            let handler_ptr = old_disp.to_handler_ptr();
            sa[..8].copy_from_slice(&handler_ptr.to_ne_bytes());
            sa[8..16].copy_from_slice(&old_flags.to_ne_bytes());
            if uaccess::copy_to_user(oldact_uva as usize, &sa).is_err() {
                return -14i64; // EFAULT
            }
        }

        // Install new disposition if provided.
        if act_uva != 0 {
            let mut sa: [u8; 32] = [0u8; 32];
            if uaccess::copy_from_user(&mut sa, act_uva as usize).is_err() {
                return -14i64; // EFAULT
            }
            let handler_ptr = u64::from_ne_bytes(sa[..8].try_into().unwrap());
            let flags = u64::from_ne_bytes(sa[8..16].try_into().unwrap());
            state.dispositions[(sig - 1) as usize] = Disposition::from_handler_ptr(handler_ptr);
            state.sa_flags[(sig - 1) as usize] = flags;
        }

        0i64
    });
    result.unwrap_or(-3) // ESRCH if no process entry
}

/// `sigprocmask(how, set_uva, oldset_uva)` — update the signal mask.
///
/// `set_uva` and `oldset_uva` are user pointers to `sigset_t` (u64 on
/// Linux x86_64).
///
/// # Safety
/// Pointers are validated via `uaccess`.
pub unsafe fn sys_sigprocmask(how: u64, set_uva: u64, oldset_uva: u64) -> i64 {
    let task_id = crate::task::current_id();
    let result = crate::process::with_signal_state_for_task(task_id, |state| {
        // Read new mask from user if provided.
        let old_mask = if set_uva != 0 {
            let mut buf = [0u8; 8];
            if uaccess::copy_from_user(&mut buf, set_uva as usize).is_err() {
                return -14i64; // EFAULT
            }
            let new_mask = u64::from_ne_bytes(buf);
            state.update_mask(how, new_mask)
        } else {
            state.blocked
        };

        if oldset_uva != 0 {
            if uaccess::copy_to_user(oldset_uva as usize, &old_mask.to_ne_bytes()).is_err() {
                return -14i64; // EFAULT
            }
        }
        0i64
    });
    result.unwrap_or(-3) // ESRCH
}

/// `kill(pid, sig)` — send signal `sig` to process `pid`.
///
/// `pid == 0` sends to the process group (not yet implemented — treated as
/// ESRCH).  Negative `pid` is not yet supported.
pub fn sys_kill(pid: u64, sig: u64) -> i64 {
    let pid = pid as i32;
    let sig = sig as u8;
    if sig > NSIG {
        return -22; // EINVAL
    }
    if pid <= 0 {
        return -3; // ESRCH — process group kill not implemented
    }
    raise_signal_on_pid(pid as u32, sig)
}

// ── Delivery from exception handlers (IRETQ path) ─────────────────────────

/// Deliver a synchronous fault signal raised from an exception handler (e.g.
/// `#PF` on a ring-3 access violation) to the currently running task.
///
/// Unlike [`check_and_deliver_signals`] (syscall-return path), this is called
/// from an interrupt handler — the user RIP/RSP/RFLAGS are captured in the
/// hardware-pushed `InterruptStackFrame`.
///
/// - `Disposition::Handler(va)`: pushes a `SigFrame` onto the user stack and
///   rewrites the `InterruptStackFrame` so that `IRETQ` redirects execution to
///   the signal handler.  Returns normally; the caller must then return from
///   the exception handler so `IRETQ` fires.
/// - `Disposition::Default` / `Disposition::Ignore`: the default action for
///   fault signals is `Terminate`.  Calls `task::exit()` (`-> !`), so neither
///   the caller nor `IRETQ` runs.
///
/// `fault_addr` is written into `siginfo.si_addr` (bytes 16–23 of `info`) so
/// the handler can inspect the faulting address via `siginfo_t.si_addr`.
///
/// # Safety
/// - Must be called from an exception handler on behalf of the currently
///   running task.
/// - `frame` must point to the live hardware-pushed `InterruptStackFrame` for
///   the current exception.  Mutating it redirects `IRETQ`.
pub unsafe fn deliver_fault_signal_iret(
    sig: u8,
    frame: &mut x86_64::structures::idt::InterruptStackFrame,
    fault_addr: u64,
) {
    // Precondition: `sig` is a valid signal number. `sig == 0` would underflow
    // the `dispositions[sig - 1]` index below; guard it in debug builds so a
    // future caller that forgets fails loudly instead of corrupting memory.
    debug_assert!(sig > 0 && sig <= NSIG, "invalid signal number");

    let task_id = crate::task::current_id();
    // Raise, immediately clear the pending bit (we service synchronously),
    // and read the disposition + pre-delivery mask under a single lock
    // acquisition.  Capturing the mask here matches `deliver_signal` semantics:
    // the saved `uc_sigmask` in the frame is what was in effect before delivery,
    // so `sigreturn` restores it correctly.
    let (disp, pre_block_mask) = crate::process::with_signal_state_for_task(task_id, |state| {
        state.raise(sig);
        state.pending &= !sig_bit(sig);
        let pre = state.blocked;
        state.blocked |= sig_bit(sig); // block signal for duration of handler
        (state.dispositions[(sig - 1) as usize], pre)
    })
    .unwrap_or((Disposition::Default, 0));

    match disp {
        Disposition::Handler(handler_va) => {
            // Validate the handler VA before touching the frame.  A
            // kernel-space VA here would be a compromised sigaction; fall
            // through to Terminate rather than redirecting IRETQ into the
            // kernel.
            if uaccess::check_user_range(handler_va as usize, 1).is_err() {
                crate::serial_println!(
                    "signal: handler VA {:#x} is not user-space — terminating pid={}",
                    handler_va,
                    crate::process::current_pid()
                );
                deliver_fault_terminate(sig);
            }

            // Snapshot user RIP/RSP/RFLAGS from the hardware frame.
            let saved_rip = frame.instruction_pointer.as_u64();
            let saved_rflags = frame.cpu_flags.bits();
            let saved_rsp = frame.stack_pointer.as_u64();

            // Push signal frame.  On failure (bad user RSP) terminate.
            let new_rsp = match frame::push_fault_signal_frame(
                saved_rsp,
                sig,
                saved_rip,
                saved_rflags,
                pre_block_mask,
                fault_addr,
            ) {
                Ok(sp) => sp,
                Err(()) => {
                    deliver_fault_terminate(sig);
                }
            };

            // Redirect IRETQ to the handler.  The volatile write through
            // `as_mut()` is required so LLVM does not optimise away the
            // store (the frame lives on the exception stack, not a normal
            // Rust allocation).
            frame.as_mut().update(|f| {
                f.instruction_pointer = x86_64::VirtAddr::new(handler_va);
                f.stack_pointer = x86_64::VirtAddr::new(new_rsp);
            });
            // Return normally — the caller must `return` so IRETQ fires.
        }
        Disposition::Ignore | Disposition::Default => {
            // Default / Ignore for a synchronous fault means Terminate.
            deliver_fault_terminate(sig);
        }
    }
}

/// Terminate the current process due to a fault signal.  Called from
/// [`deliver_fault_signal_iret`] for the `Default`/`Ignore` case.
///
/// Does not return (`-> !`).
fn deliver_fault_terminate(sig: u8) -> ! {
    let pid = crate::process::current_pid();
    crate::serial_println!("signal: terminate pid={} sig={} (fault)", pid, sig);
    if pid != 0 {
        crate::process::reparent_children(pid);
        crate::process::mark_zombie(pid, -(sig as i32));
    }
    crate::task::exit();
}

// ── Delivery at syscall return ────────────────────────────────────────────

/// Kernel-stack layout pushed by the `syscall_entry` asm trampoline
/// immediately before calling `syscall_dispatch`.
///
/// The trampoline pushes (in order, so lowest address is last pushed):
///   `[rsp+0]`  = user RIP  (rcx at entry)
///   `[rsp+8]`  = user RFLAGS (r11 at entry)
///   `[rsp+16]` = user RSP
///
/// `check_and_deliver_signals` receives `rsp` as the pointer to this layout
/// and may rewrite any of these fields to redirect the return to a signal
/// handler.
#[repr(C)]
pub struct SyscallReturnContext {
    pub user_rip: u64,
    pub user_rflags: u64,
    pub user_rsp: u64,
}

/// Length of the `SYSCALL` opcode (0x0F 0x05) in bytes. Rewinding
/// `user_rip` by this amount re-enters the syscall on SYSRETQ.
pub const SYSCALL_INSN_LEN: u64 = 2;

/// Decision returned by [`restart_decision`] — a pure classifier over
/// `(rv, sig_opt, disp, sa_flags)` that the trampoline executes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartDecision {
    /// Leave `rv` and `rip` alone. Continue with normal signal delivery.
    NoChange,
    /// Rewind `rip` by the syscall insn length and clobber `rv` so
    /// userspace sees the restarted syscall's fresh return value. Still
    /// deliver the signal handler afterwards when `deliver_handler` is
    /// true (handler + SA_RESTART case).
    Restart { deliver_handler: bool },
    /// Replace `rv` with `-EINTR`. Still deliver the signal handler.
    Eintr,
}

/// Classify what the syscall-return path should do given the dispatcher's
/// return value, the signal (if any) that was just popped, its disposition,
/// and its `sa_flags`.
///
/// Mirrors the Linux `get_signal` / `do_signal` interaction for
/// `ERESTARTSYS`:
/// - If `rv` is not `KERN_ERESTARTSYS`, nothing to do.
/// - No signal consumed this tick (caller returned `ERESTARTSYS` but the
///   pending mask was empty — e.g. a spurious wake or a race where the
///   signal had already been consumed): **unconditional restart**. Matches
///   Linux's behaviour when an interruptible sleep is unwound with no
///   signal actually raised.
/// - Signal whose disposition is `Default` with `DefaultAction::Stop` or
///   `Ignore`: restart unconditionally (no handler will run, so EINTR
///   would strand the syscall and the task would never make progress on
///   the job-control condition the caller just hit).
/// - Signal with `Disposition::Ignore` or a default-Terminate: restart
///   (Linux restarts for `ERESTARTSYS` + no handler).
/// - Signal with `Disposition::Handler` + `SA_RESTART`: restart **and**
///   deliver the handler on top of the restarted syscall.
/// - Signal with `Disposition::Handler` and no `SA_RESTART`: convert to
///   `-EINTR` and deliver the handler.
pub fn restart_decision(
    rv: i64,
    sig: Option<u8>,
    disp: Disposition,
    sa_flags: u64,
) -> RestartDecision {
    if rv != crate::tty::KERN_ERESTARTSYS {
        return RestartDecision::NoChange;
    }
    match sig {
        None => RestartDecision::Restart {
            deliver_handler: false,
        },
        Some(s) => match disp {
            Disposition::Handler(_) => {
                if sa_flags & SA_RESTART != 0 {
                    RestartDecision::Restart {
                        deliver_handler: true,
                    }
                } else {
                    RestartDecision::Eintr
                }
            }
            Disposition::Ignore => RestartDecision::Restart {
                deliver_handler: false,
            },
            Disposition::Default => match default_action(s) {
                // Stop/Ignore/Continue with no handler: restart the
                // syscall. Once the task is stopped/woken, re-entering
                // the syscall will re-check the gate condition.
                DefaultAction::Stop | DefaultAction::Ignore | DefaultAction::Continue => {
                    RestartDecision::Restart {
                        deliver_handler: false,
                    }
                }
                // Default-terminate: the task is about to be killed by
                // `deliver_signal`. Restart is academic — pick it to
                // match Linux rather than leaving a dangling -512 in rax.
                DefaultAction::Terminate => RestartDecision::Restart {
                    deliver_handler: false,
                },
            },
        },
    }
}

/// Called from the `syscall_entry` asm trampoline between steps 5 and 6
/// (after `syscall_dispatch` returns, before `pop rcx / sysretq`).
///
/// Three responsibilities:
///
/// 1. **sigreturn**: if `SIGRETURN_PENDING` is set (syscall 15 just ran),
///    overwrite `ctx` with the restored user context from `FORK_USER_*`
///    statics and clear the flag.
///
/// 2. **ERESTARTSYS handling**: if the dispatcher returned
///    `KERN_ERESTARTSYS`, consult [`restart_decision`]. On restart, rewind
///    `ctx.user_rip` by the syscall insn length and clobber `rv` so the
///    caller sees the freshly-restarted syscall's result.
///
/// 3. **signal delivery**: if a signal was popped (either by step 2's
///    lookup or a fresh pop after sigreturn), look up its disposition and
///    either push a `SigFrame` + redirect `ctx->user_rip` (user handler),
///    exit the process (default terminate), or do nothing (ignored).
///
/// The returned value replaces `rax` for SYSRETQ.
///
/// # Safety
/// `ctx` must point to the [`SyscallReturnContext`] fields on the current
/// task's kernel stack.  Called only from `syscall_entry` with IF disabled.
#[no_mangle]
pub unsafe extern "C" fn check_and_deliver_signals(ctx: *mut SyscallReturnContext, rv: i64) -> i64 {
    use core::sync::atomic::Ordering;

    // Handle sigreturn: restore saved context from FORK_USER_* statics.
    if crate::arch::x86_64::syscall::SIGRETURN_PENDING.load(Ordering::Relaxed) != 0 {
        crate::arch::x86_64::syscall::SIGRETURN_PENDING.store(0, Ordering::Relaxed);
        (*ctx).user_rip = crate::arch::x86_64::syscall::FORK_USER_RIP.load(Ordering::Relaxed);
        (*ctx).user_rflags = crate::arch::x86_64::syscall::FORK_USER_RFLAGS.load(Ordering::Relaxed);
        (*ctx).user_rsp = crate::arch::x86_64::syscall::FORK_USER_RSP.load(Ordering::Relaxed);
        // After sigreturn still check for any newly-pending signal.
    }

    let task_id = crate::task::current_id();
    // Peek the next deliverable signal and its (disposition, sa_flags) in
    // a single lock window so the restart-decision classifier sees a
    // consistent snapshot.
    let popped: Option<(u8, Disposition, u64)> =
        crate::process::with_signal_state_for_task(task_id, |state| {
            state.pop_next_pending().map(|s| {
                let i = (s - 1) as usize;
                (s, state.dispositions[i], state.sa_flags[i])
            })
        })
        .flatten();

    let mut rv_out = rv;
    let sig_for_delivery: Option<u8> = match restart_decision(
        rv,
        popped.map(|(s, _, _)| s),
        popped.map(|(_, d, _)| d).unwrap_or(Disposition::Default),
        popped.map(|(_, _, f)| f).unwrap_or(0),
    ) {
        RestartDecision::NoChange => popped.map(|(s, _, _)| s),
        RestartDecision::Restart { deliver_handler } => {
            (*ctx).user_rip = (*ctx).user_rip.wrapping_sub(SYSCALL_INSN_LEN);
            // Clobber rv: after restart, userspace will get the result of
            // the re-executed syscall; the stale -ERESTARTSYS must not
            // leak in case something later skips the restart.
            rv_out = 0;
            if deliver_handler {
                popped.map(|(s, _, _)| s)
            } else {
                None
            }
        }
        RestartDecision::Eintr => {
            rv_out = crate::fs::EINTR;
            popped.map(|(s, _, _)| s)
        }
    };

    if let Some(sig) = sig_for_delivery {
        deliver_signal(sig, &mut *ctx);
    }
    rv_out
}

/// Deliver signal `sig` by either redirecting return-to-user context to the
/// handler or terminating the process for default-terminate signals.
///
/// # Safety
/// `ctx` must point to valid kernel-stack-saved user context.
unsafe fn deliver_signal(sig: u8, ctx: &mut SyscallReturnContext) {
    let task_id = crate::task::current_id();

    // Capture the pre-delivery mask and block the signal in one lock window.
    // The pre-delivery mask is what sigreturn must restore; capturing it before
    // setting the block bit ensures uc_sigmask in the frame is correct.
    let (disp, pre_block_mask) =
        match crate::process::with_signal_state_for_task(task_id, |state| {
            let pre = state.blocked;
            state.blocked |= sig_bit(sig);
            (state.dispositions[(sig - 1) as usize], pre)
        }) {
            Some(pair) => pair,
            None => return,
        };

    match disp {
        Disposition::Ignore => {
            // Unblock the signal again (we blocked it above).
            let _ = crate::process::with_signal_state_for_task(task_id, |state| {
                state.blocked &= !sig_bit(sig);
                ()
            });
        }
        Disposition::Default => {
            let _ = crate::process::with_signal_state_for_task(task_id, |state| {
                state.blocked &= !sig_bit(sig);
                ()
            });
            match default_action(sig) {
                DefaultAction::Terminate => {
                    let pid = crate::process::current_pid();
                    crate::serial_println!("signal: terminate pid={} sig={}", pid, sig);
                    if pid != 0 {
                        crate::process::reparent_children(pid);
                        crate::process::mark_zombie(pid, -(sig as i32));
                    }
                    crate::task::exit();
                }
                _ => {} // Ignore / Stop / Continue — no-op for now
            }
        }
        Disposition::Handler(handler_va) => {
            // Push signal frame onto the user stack and redirect SYSRETQ.
            let new_user_rsp = match frame::push_signal_frame(
                ctx.user_rsp,
                sig,
                ctx.user_rip,
                ctx.user_rflags,
                pre_block_mask,
            ) {
                Ok(sp) => sp,
                Err(_) => {
                    // Could not push the frame (bad user RSP) — terminate.
                    let pid = crate::process::current_pid();
                    if pid != 0 {
                        crate::process::reparent_children(pid);
                        crate::process::mark_zombie(pid, -(sig as i32));
                    }
                    crate::task::exit();
                }
            };
            ctx.user_rip = handler_va;
            ctx.user_rsp = new_user_rsp;
            // Leave ctx.user_rflags as-is (handler sees caller's rflags).
        }
    }
}

/// `sigreturn()` — restore register context from the `SigFrame` on the user
/// stack and resume the interrupted code.
///
/// Reads the `SigFrame` at `user_rsp` (which is the value of RSP when the
/// signal handler was invoked — the frame's `pretcode` word is at `[rsp]`
/// followed by the frame itself), restores `user_rip`, `user_rflags`,
/// `user_rsp` from it, and also restores the saved signal mask.
///
/// The caller must write the returned [`SigReturnRegs`] back into the
/// kernel-stack-saved context so `SYSRETQ` returns to the right place.
///
/// # Safety
/// `user_rsp` must point to a valid `SigFrame` in user space.
pub unsafe fn sys_sigreturn(user_rsp: u64) -> SigReturnRegs {
    match frame::restore_signal_frame(user_rsp) {
        Ok(restored) => {
            // Restore the signal mask that was saved when we delivered.
            let task_id = crate::task::current_id();
            let _ = crate::process::with_signal_state_for_task(task_id, |state| {
                // The saved mask in the frame is what blocked was set to
                // before delivery.  Restore it and unblock the signal that
                // was temporarily added.
                state.blocked = restored.saved_mask;
                ()
            });
            SigReturnRegs {
                rip: restored.rip,
                rflags: restored.rflags,
                rsp: restored.rsp,
            }
        }
        Err(_) => {
            // Corrupt frame — kill the process.
            let pid = crate::process::current_pid();
            if pid != 0 {
                crate::process::reparent_children(pid);
                crate::process::mark_zombie(pid, -(SIGSEGV as i32));
            }
            crate::task::exit();
        }
    }
}

/// The register values to restore after `sigreturn`.
pub struct SigReturnRegs {
    pub rip: u64,
    pub rflags: u64,
    pub rsp: u64,
}

// ── Host-side unit tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sig_bit_is_1_indexed() {
        assert_eq!(sig_bit(1), 1u64);
        assert_eq!(sig_bit(2), 2u64);
        assert_eq!(sig_bit(64), 1u64 << 63);
        assert_eq!(sig_bit(0), 0u64); // invalid
        assert_eq!(sig_bit(65), 0u64); // out of range
    }

    #[test]
    fn pop_next_pending_lowest_first() {
        let mut s = SignalState::new();
        s.raise(SIGTERM);
        s.raise(SIGUSR1);
        s.raise(SIGINT);
        // SIGINT=2 < SIGUSR1=10 < SIGTERM=15
        assert_eq!(s.pop_next_pending(), Some(SIGINT));
        assert_eq!(s.pop_next_pending(), Some(SIGUSR1));
        assert_eq!(s.pop_next_pending(), Some(SIGTERM));
        assert_eq!(s.pop_next_pending(), None);
    }

    #[test]
    fn blocked_signals_are_deferred() {
        let mut s = SignalState::new();
        s.raise(SIGUSR1);
        s.blocked = sig_bit(SIGUSR1); // block it
        assert_eq!(s.pop_next_pending(), None);
        s.blocked = 0; // unblock
        assert_eq!(s.pop_next_pending(), Some(SIGUSR1));
    }

    #[test]
    fn sigkill_bypasses_blocked_mask() {
        let mut s = SignalState::new();
        s.raise(SIGKILL);
        s.blocked = !0u64; // try to block everything
                           // SIGKILL must still be deliverable.
        assert_eq!(s.pop_next_pending(), Some(SIGKILL));
    }

    #[test]
    fn update_mask_block() {
        let mut s = SignalState::new();
        let old = s.update_mask(SIG_BLOCK, sig_bit(SIGUSR1));
        assert_eq!(old, 0);
        assert_eq!(s.blocked, sig_bit(SIGUSR1));
    }

    #[test]
    fn update_mask_unblock() {
        let mut s = SignalState::new();
        s.blocked = sig_bit(SIGUSR1) | sig_bit(SIGUSR2);
        let old = s.update_mask(SIG_UNBLOCK, sig_bit(SIGUSR1));
        assert_eq!(old, sig_bit(SIGUSR1) | sig_bit(SIGUSR2));
        assert_eq!(s.blocked, sig_bit(SIGUSR2));
    }

    #[test]
    fn update_mask_setmask() {
        let mut s = SignalState::new();
        s.blocked = sig_bit(SIGUSR1);
        let old = s.update_mask(SIG_SETMASK, sig_bit(SIGUSR2));
        assert_eq!(old, sig_bit(SIGUSR1));
        assert_eq!(s.blocked, sig_bit(SIGUSR2));
    }

    #[test]
    fn sigkill_cannot_be_blocked() {
        let mut s = SignalState::new();
        s.update_mask(SIG_SETMASK, !0u64);
        assert_eq!(s.blocked & sig_bit(SIGKILL), 0);
        assert_eq!(s.blocked & sig_bit(SIGSTOP), 0);
    }

    #[test]
    fn disposition_roundtrip() {
        assert!(matches!(
            Disposition::from_handler_ptr(SIG_DFL),
            Disposition::Default
        ));
        assert!(matches!(
            Disposition::from_handler_ptr(SIG_IGN),
            Disposition::Ignore
        ));
        let va = 0xDEAD_BEEF_0000_0000u64;
        let d = Disposition::from_handler_ptr(va);
        assert!(matches!(d, Disposition::Handler(_)));
        assert_eq!(d.to_handler_ptr(), va);
    }

    #[test]
    fn default_action_terminate() {
        assert_eq!(default_action(SIGTERM), DefaultAction::Terminate);
        assert_eq!(default_action(SIGKILL), DefaultAction::Terminate);
        assert_eq!(default_action(SIGSEGV), DefaultAction::Terminate);
    }

    #[test]
    fn default_action_ignore_for_sigchld() {
        // SIGCHLD disposition starts as Ignore in SignalState::new().
        let s = SignalState::new();
        assert!(matches!(
            s.dispositions[(SIGCHLD - 1) as usize],
            Disposition::Ignore
        ));
    }

    // ── restart_decision classifier ───────────────────────────────────

    #[test]
    fn restart_noop_when_rv_is_not_erestartsys() {
        // Any non-ERESTARTSYS rv is passed through untouched even if a
        // signal is queued with SA_RESTART clear.
        assert_eq!(
            restart_decision(-4, Some(SIGTTOU), Disposition::Handler(0x1000), 0),
            RestartDecision::NoChange
        );
        assert_eq!(
            restart_decision(0, None, Disposition::Default, 0),
            RestartDecision::NoChange
        );
    }

    #[test]
    fn restart_without_signal_rewinds_unconditionally() {
        // ERESTARTSYS with no pending signal (e.g. spurious wake) must
        // rewind rip so the syscall re-runs; no handler to deliver.
        assert_eq!(
            restart_decision(crate::tty::KERN_ERESTARTSYS, None, Disposition::Default, 0),
            RestartDecision::Restart {
                deliver_handler: false
            }
        );
    }

    #[test]
    fn restart_handler_with_sa_restart_rewinds_and_delivers() {
        assert_eq!(
            restart_decision(
                crate::tty::KERN_ERESTARTSYS,
                Some(SIGTTOU),
                Disposition::Handler(0x4000_0000),
                SA_RESTART
            ),
            RestartDecision::Restart {
                deliver_handler: true
            }
        );
    }

    #[test]
    fn restart_handler_without_sa_restart_returns_eintr() {
        assert_eq!(
            restart_decision(
                crate::tty::KERN_ERESTARTSYS,
                Some(SIGTTOU),
                Disposition::Handler(0x4000_0000),
                0
            ),
            RestartDecision::Eintr
        );
    }

    #[test]
    fn restart_handler_with_other_flags_still_needs_sa_restart() {
        // SA_NODEFER alone doesn't enable restart.
        let sa_nodefer: u64 = 0x4000_0000;
        assert_eq!(
            restart_decision(
                crate::tty::KERN_ERESTARTSYS,
                Some(SIGTTOU),
                Disposition::Handler(0x4000_0000),
                sa_nodefer
            ),
            RestartDecision::Eintr
        );
    }

    #[test]
    fn restart_ignored_signal_rewinds() {
        // SIG_IGN on an ERESTARTSYS-returning syscall: restart (no
        // handler to run, nothing for userspace to see).
        assert_eq!(
            restart_decision(
                crate::tty::KERN_ERESTARTSYS,
                Some(SIGTTOU),
                Disposition::Ignore,
                0
            ),
            RestartDecision::Restart {
                deliver_handler: false
            }
        );
    }

    #[test]
    fn restart_default_stop_rewinds_no_handler() {
        // Default SIGTTOU/SIGTTIN/SIGTSTP is Stop — the caller will
        // re-enter the syscall after wake; don't convert to EINTR.
        assert_eq!(
            restart_decision(
                crate::tty::KERN_ERESTARTSYS,
                Some(SIGTTOU),
                Disposition::Default,
                0
            ),
            RestartDecision::Restart {
                deliver_handler: false
            }
        );
    }

    #[test]
    fn restart_default_terminate_rewinds_no_handler() {
        // Default-terminate (e.g. SIGTERM): the task is about to die
        // via deliver_signal → task::exit. Picking Restart (rather than
        // NoChange) ensures -512 never leaks into userspace if the
        // terminate path is ever made non-fatal.
        assert_eq!(
            restart_decision(
                crate::tty::KERN_ERESTARTSYS,
                Some(SIGTERM),
                Disposition::Default,
                0
            ),
            RestartDecision::Restart {
                deliver_handler: false
            }
        );
    }

    #[test]
    fn sigaction_flags_roundtrip_in_state() {
        // The SignalState machinery itself (not sys_sigaction, which
        // requires a live process entry) stores sa_flags per signal.
        let mut s = SignalState::new();
        s.sa_flags[(SIGTTOU - 1) as usize] = SA_RESTART;
        assert_eq!(s.sa_flags[(SIGTTOU - 1) as usize], SA_RESTART);
        assert_eq!(s.sa_flags[(SIGTERM - 1) as usize], 0);
    }
}
