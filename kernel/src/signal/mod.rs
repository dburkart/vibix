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
//! - `SA_RESTART` is honoured both on the bare-restart path (no handler)
//!   and on the handler path: the syscall arg registers (rax, rdi, rsi,
//!   rdx, r10, r8, r9) are captured into the `SigFrame` at delivery and
//!   restored by `sys_sigreturn` so the re-executed SYSCALL sees the
//!   original `(nr, a0..a5)` — see issue #522.
//! - `SA_NODEFER` is honoured: when set, the signal is not automatically
//!   blocked during handler execution, allowing recursive handlers.
//! - `SA_ONSTACK` is honoured: when set and an alternate signal stack is
//!   registered via `sigaltstack(2)`, the handler runs on the alternate
//!   stack.
//! - Real-time signals (`SIGRTMIN`..`SIGRTMAX`) are not implemented.
//! - Multi-threaded signal delivery is not implemented (single-CPU, single-
//!   threaded for now).

// `frame.rs` and the SYSCALL-trampoline / iret-frame plumbing are
// bare-metal-only because they touch `arch::x86_64::*`. The host-build
// arm under `feature = "sched-mock"` exposes only `SignalState` — the
// per-process signal-mask + pending-bitmap data structure that
// `process::ProcessEntry` carries — so the host-side simulator
// (RFC 0008 / #790) can construct an entry without the full delivery
// path being host-buildable.
#[cfg(target_os = "none")]
pub mod frame;

#[cfg(target_os = "none")]
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

/// `SA_NODEFER` — do not automatically add the signal to the blocked mask
/// while the handler is executing. This allows the handler to be
/// re-entered by the same signal (recursive signal handling).
pub const SA_NODEFER: u64 = 0x4000_0000;

/// `SA_ONSTACK` — deliver this signal on the alternate signal stack
/// registered via `sigaltstack(2)`, if one is available.
pub const SA_ONSTACK: u64 = 0x0800_0000;

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
    // Host-buildable accessors are only used by the bare-metal
    // sigaction syscall arms; the host arm of `signal::*`
    // (RFC 0008 / #790) carries `SignalState` only and never reaches
    // these helpers. Gate to bare metal to silence the dead-code
    // warning under `feature = "sched-mock"`.
    #[cfg(target_os = "none")]
    fn from_handler_ptr(ptr: u64) -> Self {
        match ptr {
            SIG_DFL => Disposition::Default,
            SIG_IGN => Disposition::Ignore,
            va => Disposition::Handler(va),
        }
    }

    #[cfg(target_os = "none")]
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

// ── sigaltstack constants and struct ─────────────────────────────────────

/// `SS_ONSTACK` — returned by `sigaltstack(2)` in `ss_flags` when the
/// process is currently executing on the alternate signal stack.
pub const SS_ONSTACK: u64 = 1;
/// `SS_DISABLE` — passed in `ss_flags` to disable the alternate stack.
pub const SS_DISABLE: u64 = 2;

/// Per-task alternate signal stack registration, matching Linux `stack_t`.
#[derive(Clone, Copy, Debug)]
pub struct SigaltStack {
    /// Base address of the alternate stack (user VA).
    pub ss_sp: u64,
    /// Size of the alternate stack in bytes.
    pub ss_size: u64,
}

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
    /// Saved signal mask for `sigsuspend(2)`.  When `Some(mask)`, the
    /// signal delivery path uses this as the `uc_sigmask` in the
    /// `SigFrame` so that `sigreturn` restores the original mask
    /// rather than the temporary one installed by `sigsuspend`.
    /// Cleared after use.
    pub saved_mask: Option<u64>,
    /// Alternate signal stack registered via `sigaltstack(2)`.
    /// When `Some`, signals whose `sa_flags` include `SA_ONSTACK` are
    /// delivered on this stack instead of the current user stack.
    pub alt_stack: Option<SigaltStack>,
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
            saved_mask: None,
            alt_stack: None,
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

    /// Return true if at least one signal is both pending and deliverable
    /// (not blocked, or SIGKILL/SIGSTOP).
    pub fn has_deliverable(&self) -> bool {
        let unblockable = sig_bit(SIGKILL) | sig_bit(SIGSTOP);
        let deliverable = self.pending & (!self.blocked | unblockable);
        deliverable != 0
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

// Everything below depends on bare-metal-only modules
// (`arch::x86_64`, `task::wake`, `task::exit`, `tty::KERN_ERESTARTSYS`,
// `serial_println`, the `frame` submodule, etc.) and is gated to
// `target_os = "none"` via the `bare_metal_only!` macro below. The
// host arm under `feature = "sched-mock"` exposes only the
// `SignalState`-facing surface above. RFC 0008 §"Slim host arm"
// documents the tradeoff.

/// `cfg(target_os = "none")` wrapper around a section of code.
/// Used below to gate the bare-metal signal-delivery glue without
/// indenting it under a module (which would change item paths).
#[allow(unused_macros)]
macro_rules! bare_metal_only {
    ($($body:item)*) => { $( #[cfg(target_os = "none")] $body )* };
}

bare_metal_only! {

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

/// `sigpending(set_uva)` — return the set of signals that are both pending
/// and blocked for the calling process.
///
/// `set_uva` is a user pointer to a `sigset_t` (u64 on Linux x86_64).
/// On success the kernel writes the pending-and-blocked bitmap there.
///
/// # Safety
/// `set_uva` is validated via `uaccess`.
pub unsafe fn sys_sigpending(set_uva: u64) -> i64 {
    if set_uva == 0 {
        return -14; // EFAULT
    }
    let task_id = crate::task::current_id();
    let result = crate::process::with_signal_state_for_task(task_id, |state| {
        // POSIX: sigpending returns the intersection of pending and blocked.
        let pending_blocked = state.pending & state.blocked;
        if uaccess::copy_to_user(set_uva as usize, &pending_blocked.to_ne_bytes()).is_err() {
            return -14i64; // EFAULT
        }
        0i64
    });
    result.unwrap_or(-3) // ESRCH
}

/// `sigaltstack(ss_uva, old_ss_uva)` — register or query the alternate
/// signal stack.
///
/// `ss_uva` and `old_ss_uva` are user pointers to `stack_t`
/// (Linux x86_64 layout: `ss_sp: u64, ss_flags: i32, _pad: i32,
/// ss_size: u64` — total 24 bytes).
///
/// When `ss_uva` is non-null:
///   - If `ss_flags & SS_DISABLE`, the alternate stack is disabled.
///   - Otherwise, `ss_sp` and `ss_size` define the new alternate stack.
///     `ss_size` must be >= `MINSIGSTKSZ` (2048 on x86_64).
///
/// When `old_ss_uva` is non-null, the current alternate stack state is
/// written there before any change.
///
/// # Safety
/// User pointers are validated via `uaccess`.
pub unsafe fn sys_sigaltstack(ss_uva: u64, old_ss_uva: u64) -> i64 {
    const MINSIGSTKSZ: u64 = 2048;
    let task_id = crate::task::current_id();

    let result = crate::process::with_signal_state_for_task(task_id, |state| {
        // Write the current state to old_ss_uva if requested.
        if old_ss_uva != 0 {
            let mut buf = [0u8; 24];
            match &state.alt_stack {
                Some(ss) => {
                    buf[..8].copy_from_slice(&ss.ss_sp.to_ne_bytes());
                    // ss_flags: 0 = alternate stack is registered but not
                    // currently active. We do not track on-stack status
                    // dynamically yet (would require checking the current
                    // RSP against the alt-stack range), so report 0.
                    buf[8..12].copy_from_slice(&0u32.to_ne_bytes());
                    buf[12..16].copy_from_slice(&0u32.to_ne_bytes()); // padding
                    buf[16..24].copy_from_slice(&ss.ss_size.to_ne_bytes());
                }
                None => {
                    // No alternate stack: ss_sp=0, ss_flags=SS_DISABLE, ss_size=0
                    buf[8..12].copy_from_slice(&(SS_DISABLE as u32).to_ne_bytes());
                }
            }
            if uaccess::copy_to_user(old_ss_uva as usize, &buf).is_err() {
                return -14i64; // EFAULT
            }
        }

        // Install a new alternate stack if requested.
        // TODO: Linux returns -EPERM when attempting to change the alt stack
        // while the thread is currently executing on it (SS_ONSTACK).  We
        // would need to check the current RSP against [ss_sp, ss_sp+ss_size)
        // to enforce this.  Track as a follow-up once we have a reliable way
        // to read the user RSP from within the syscall handler.
        if ss_uva != 0 {
            let mut buf = [0u8; 24];
            if uaccess::copy_from_user(&mut buf, ss_uva as usize).is_err() {
                return -14i64; // EFAULT
            }
            let ss_sp = u64::from_ne_bytes(buf[..8].try_into().unwrap());
            let ss_flags = u32::from_ne_bytes(buf[8..12].try_into().unwrap()) as u64;
            let ss_size = u64::from_ne_bytes(buf[16..24].try_into().unwrap());

            if ss_flags & SS_DISABLE != 0 {
                // Disable the alternate stack.
                state.alt_stack = None;
            } else {
                if ss_size < MINSIGSTKSZ {
                    return -12i64; // ENOMEM
                }
                state.alt_stack = Some(SigaltStack { ss_sp, ss_size });
            }
        }

        0i64
    });
    result.unwrap_or(-3) // ESRCH
}

/// Per-task wait queue used by `sigsuspend`.  Tasks park here and are
/// woken by [`raise_signal_on_task`] (which calls `task::wake`).
///
/// We use the same wake mechanism as the rest of the kernel: when a
/// signal is raised on a task, `task::wake(task_id)` is called, which
/// sets `wake_pending` and unblocks the task. The `WaitQueue` here
/// gives `sigsuspend` a place to park; the `cond` closure checks
/// whether a deliverable signal is pending under the temporary mask.
pub static SIGSUSPEND_WAIT: crate::sync::WaitQueue = crate::sync::WaitQueue::new();

/// `sigsuspend(mask_uva)` — atomically replace the signal mask, suspend
/// until a signal is delivered, then restore the original mask.
///
/// Always returns `-EINTR` (via `KERN_ERESTARTSYS` so the trampoline's
/// signal-delivery path runs before the syscall result reaches
/// userspace).
///
/// `mask_uva` is a user pointer to a `sigset_t` (u64).
///
/// # Safety
/// `mask_uva` is validated via `uaccess`.
pub unsafe fn sys_sigsuspend(mask_uva: u64) -> i64 {
    if mask_uva == 0 {
        return -14; // EFAULT
    }
    // Read the temporary mask from user space.
    let mut buf = [0u8; 8];
    if uaccess::copy_from_user(&mut buf, mask_uva as usize).is_err() {
        return -14; // EFAULT
    }
    let temp_mask = u64::from_ne_bytes(buf);

    let task_id = crate::task::current_id();
    let unblockable = sig_bit(SIGKILL) | sig_bit(SIGSTOP);

    // Atomically: save old mask, install temporary mask, record
    // saved_mask so the signal-delivery path writes the original
    // mask into the SigFrame's uc_sigmask.
    let swapped = crate::process::with_signal_state_for_task(task_id, |state| {
        let old_mask = state.blocked;
        state.blocked = temp_mask & !unblockable;
        state.saved_mask = Some(old_mask);
    });
    if swapped.is_none() {
        return -3; // ESRCH
    }

    // Block until a signal is deliverable under the temporary mask.
    SIGSUSPEND_WAIT.wait_while(|| {
        crate::process::with_signal_state_for_task(task_id, |state| {
            !state.has_deliverable()
        })
        .unwrap_or(false) // if process gone, stop waiting
    });

    // Do NOT restore the original mask here.  Restoring before
    // `check_and_deliver_signals` runs would re-block the wake signal
    // under the original mask, so `pop_next_pending` would return
    // `None` and the syscall would livelock on restart.
    //
    // Instead, `deliver_signal` consumes `saved_mask` to fill the
    // SigFrame's `uc_sigmask` (handler path — sigreturn restores it)
    // or directly restores `blocked` from it (Ignore / non-terminate
    // Default paths).  Both paths ensure the pre-sigsuspend mask is
    // eventually reinstated without re-blocking the wake signal
    // before delivery.

    // Return KERN_ERESTARTSYS so check_and_deliver_signals picks up
    // the now-deliverable signal and either delivers a handler or
    // applies the default action. The restart_decision classifier
    // will convert this to -EINTR when a handler is installed
    // without SA_RESTART.  With SA_RESTART the handler runs and the
    // syscall restarts — matching POSIX semantics where sigsuspend
    // always returns -1/EINTR after a caught signal.
    crate::tty::KERN_ERESTARTSYS
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
    // and read the disposition + pre-delivery mask + sa_flags + alt_stack
    // under a single lock acquisition.  Capturing the mask here matches
    // `deliver_signal` semantics: the saved `uc_sigmask` in the frame is
    // what was in effect before delivery, so `sigreturn` restores it
    // correctly.
    let (disp, pre_block_mask, flags, alt) =
        crate::process::with_signal_state_for_task(task_id, |state| {
            state.raise(sig);
            state.pending &= !sig_bit(sig);
            let pre = state.blocked;
            let f = state.sa_flags[(sig - 1) as usize];
            // SA_NODEFER: do NOT automatically add the signal to blocked.
            if f & SA_NODEFER == 0 {
                state.blocked |= sig_bit(sig);
            }
            (state.dispositions[(sig - 1) as usize], pre, f, state.alt_stack)
        })
        .unwrap_or((Disposition::Default, 0, 0, None));

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

            // Determine the stack to push the signal frame onto.
            let frame_rsp = if flags & SA_ONSTACK != 0 {
                if let Some(ss) = alt {
                    ss.ss_sp + ss.ss_size
                } else {
                    saved_rsp
                }
            } else {
                saved_rsp
            };

            // Push signal frame.  On failure (bad user RSP) terminate.
            let new_rsp = match frame::push_fault_signal_frame(
                frame_rsp,
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
/// The trampoline pushes the syscall-arg registers so a syscall restart
/// (rip rewound to the SYSCALL instruction) can re-execute the syscall
/// with the original `rax` (syscall number) and argument registers. Push
/// order is high→low address; `check_and_deliver_signals` receives `rsp`
/// as the pointer to the start of this struct (the last-pushed field).
///
/// Layout (low address → high):
///   `[rsp+0]`   = saved user `rax` (syscall nr)
///   `[rsp+8]`   = saved user `rdi` (a0)
///   `[rsp+16]`  = saved user `rsi` (a1)
///   `[rsp+24]`  = saved user `rdx` (a2)
///   `[rsp+32]`  = saved user `r10` (a3)
///   `[rsp+40]`  = saved user `r8`  (a4)
///   `[rsp+48]`  = saved user `r9`  (a5)
///   `[rsp+56]`  = user RIP   (rcx at entry)
///   `[rsp+64]`  = user RFLAGS (r11 at entry)
///   `[rsp+72]`  = user RSP
///   `[rsp+80]`  = saved user `rbx`  (callee-saved, #690)
///   `[rsp+88]`  = saved user `rbp`  (callee-saved, #690)
///   `[rsp+96]`  = saved user `r12`  (callee-saved, #690)
///   `[rsp+104]` = saved user `r13`  (callee-saved, #690)
///   `[rsp+112]` = saved user `r14`  (callee-saved, #690)
///   `[rsp+120]` = saved user `r15`  (callee-saved, #690)
///
/// The six callee-saved slots (`rbx`, `rbp`, `r12`–`r15`) were added in
/// #690 so the FORK syscall can publish the parent's full SysV
/// callee-saved set into the forked child's user register state.
/// Without these slots, `fork_child_sysret` only restored `rcx/r11/rsp`
/// before SYSRETQ and the child resumed ring-3 with whatever the kernel
/// happened to leave in `rbx/rbp/r12-r15` — silently corrupting any
/// userspace local the compiler was holding in a callee-saved register
/// across `sys_fork()`.
#[repr(C)]
#[derive(Default)]
pub struct SyscallReturnContext {
    pub user_rax: u64,
    pub user_rdi: u64,
    pub user_rsi: u64,
    pub user_rdx: u64,
    pub user_r10: u64,
    pub user_r8: u64,
    pub user_r9: u64,
    pub user_rip: u64,
    pub user_rflags: u64,
    pub user_rsp: u64,
    pub user_rbx: u64,
    pub user_rbp: u64,
    pub user_r12: u64,
    pub user_r13: u64,
    pub user_r14: u64,
    pub user_r15: u64,
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

/// Pure classifier: given a restart decision and the (signal, disposition)
/// popped from the pending mask, return `Some(sig)` if `deliver_signal`
/// should be called, or `None` if the syscall return path should skip
/// delivery.
///
/// The distinction matters on the `RestartDecision::Restart` path: a bare
/// restart must still dispatch default-action signals (SIGTERM → task
/// exit; SIGTTOU/TSTP/TTIN → stop — currently a no-op). Only
/// `Disposition::Ignore` and "no signal popped" skip delivery outright.
/// On `Eintr` and `NoChange`, delivery always occurs if a signal was
/// popped.
pub fn signal_to_deliver(
    decision: RestartDecision,
    popped: Option<(u8, Disposition)>,
) -> Option<u8> {
    match decision {
        RestartDecision::NoChange => popped.map(|(s, _)| s),
        RestartDecision::Eintr => popped.map(|(s, _)| s),
        RestartDecision::Restart { deliver_handler } => match popped {
            None => None,
            Some((s, disp)) => {
                if deliver_handler {
                    Some(s)
                } else {
                    match disp {
                        Disposition::Ignore => None,
                        _ => Some(s),
                    }
                }
            }
        },
    }
}

/// Called from the `syscall_entry` asm trampoline between steps 5 and 6
/// (after `syscall_dispatch` returns, before `pop rcx / sysretq`).
///
/// Two responsibilities:
///
/// 1. **ERESTARTSYS handling**: if the dispatcher returned
///    `KERN_ERESTARTSYS`, consult [`restart_decision`]. On restart, rewind
///    `ctx.user_rip` by the syscall insn length and clobber `rv` so the
///    caller sees the freshly-restarted syscall's result.
///
/// 2. **signal delivery**: if a signal was popped, look up its
///    disposition and either push a `SigFrame` + redirect `ctx->user_rip`
///    (user handler), exit the process (default terminate), or do
///    nothing (ignored).
///
/// The returned value replaces `rax` for SYSRETQ.
///
/// `sigreturn(2)` (syscall 15) restores `ctx->user_{rip,rflags,rsp}`
/// directly from inside `syscall_dispatch`, so no cross-call fix-up is
/// needed here (issue #504 removed the former FORK_USER_* hand-off).
///
/// # Safety
/// `ctx` must point to the [`SyscallReturnContext`] fields on the current
/// task's kernel stack.  Called only from `syscall_entry` with IF disabled.
#[no_mangle]
pub unsafe extern "C" fn check_and_deliver_signals(ctx: *mut SyscallReturnContext, rv: i64) -> i64 {
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

    let decision = restart_decision(
        rv,
        popped.map(|(s, _, _)| s),
        popped.map(|(_, d, _)| d).unwrap_or(Disposition::Default),
        popped.map(|(_, _, f)| f).unwrap_or(0),
    );
    let mut rv_out = rv;
    match decision {
        RestartDecision::NoChange => {}
        RestartDecision::Restart { .. } => {
            (*ctx).user_rip = (*ctx).user_rip.wrapping_sub(SYSCALL_INSN_LEN);
            // On the bare-restart path (no handler), ask the asm
            // trampoline to reload the saved user syscall regs from the
            // SyscallReturnContext before SYSRETQ so the re-executed
            // SYSCALL sees the original (nr, a0..a5).
            //
            // On the handler+SA_RESTART path the restart happens after
            // the handler returns: `deliver_signal` captures the live
            // syscall arg regs into the SigFrame, and `sys_sigreturn`
            // restores them into the ctx and raises SYSCALL_RESTART_PENDING
            // itself (issue #522). Raising the flag here as well would be
            // wrong — the handler is about to run next, and its own
            // syscall (e.g. sigreturn itself) must not be hijacked into
            // a replay of the interrupted one.
            if !matches!(
                decision,
                RestartDecision::Restart {
                    deliver_handler: true
                }
            ) {
                crate::arch::x86_64::syscall::SYSCALL_RESTART_PENDING
                    .store(1, core::sync::atomic::Ordering::Relaxed);
            }
            // Clobber rv: after restart, userspace will get the result of
            // the re-executed syscall; the stale -ERESTARTSYS must not
            // leak in case something later skips the restart.
            rv_out = 0;
        }
        RestartDecision::Eintr => {
            rv_out = crate::fs::EINTR;
        }
    }
    let sig_for_delivery = signal_to_deliver(decision, popped.map(|(s, d, _)| (s, d)));

    if let Some(sig) = sig_for_delivery {
        // Only mark the frame as restart-pending when we actually rewound
        // RIP to the SYSCALL instruction for an SA_RESTART replay.
        // Handler-only deliveries on non-restart paths (EINTR, NoChange)
        // must leave the SigFrame's restart_flag cleared so `sigreturn`
        // does not clobber the post-handler `user_rax` with the pre-
        // handler syscall number (issue #522, PR #528 review).
        let restart_pending = matches!(
            decision,
            RestartDecision::Restart {
                deliver_handler: true
            }
        );
        deliver_signal(sig, &mut *ctx, restart_pending);
    }
    rv_out
}

/// Deliver signal `sig` by either redirecting return-to-user context to the
/// handler or terminating the process for default-terminate signals.
///
/// `restart_pending` is true iff the caller (`check_and_deliver_signals`)
/// rewound `ctx.user_rip` to the SYSCALL instruction for an SA_RESTART-ed
/// ERESTARTSYS replay. That bit is embedded in the pushed `SigFrame` and
/// read back out by `sigreturn` — only a restart-marked frame causes the
/// syscall-arg gregs to be written back into the kernel context and
/// `SYSCALL_RESTART_PENDING` to be asserted (issue #522).
///
/// # Safety
/// `ctx` must point to valid kernel-stack-saved user context.
unsafe fn deliver_signal(sig: u8, ctx: &mut SyscallReturnContext, restart_pending: bool) {
    let task_id = crate::task::current_id();

    // Capture the pre-delivery mask, sa_flags, and optionally the
    // alternate stack in one lock window.  Block the signal unless
    // SA_NODEFER is set.
    //
    // When `saved_mask` is `Some` (set by `sigsuspend`), the frame's
    // `uc_sigmask` must be the *original* mask that was saved before
    // `sigsuspend` installed the temporary one. This way `sigreturn`
    // restores the process to its pre-sigsuspend signal mask rather than
    // the ephemeral temporary mask. The `saved_mask` is consumed (taken)
    // here so a second delivery in the same syscall-return window does
    // not re-use a stale value.
    let (disp, pre_block_mask, flags, alt) =
        match crate::process::with_signal_state_for_task(task_id, |state| {
            let pre = state.saved_mask.take().unwrap_or(state.blocked);
            let f = state.sa_flags[(sig - 1) as usize];
            // SA_NODEFER: do NOT automatically add the signal to blocked.
            if f & SA_NODEFER == 0 {
                state.blocked |= sig_bit(sig);
            }
            (state.dispositions[(sig - 1) as usize], pre, f, state.alt_stack)
        }) {
            Some(tuple) => tuple,
            None => return,
        };

    match disp {
        Disposition::Ignore => {
            // Restore the mask to the pre-delivery state.  When
            // sigsuspend is in effect, `pre_block_mask` is the
            // *original* mask (from `saved_mask`), so this restores
            // the pre-sigsuspend mask. Otherwise it just undoes the
            // signal-blocking we added above.
            let _ = crate::process::with_signal_state_for_task(task_id, |state| {
                state.blocked = pre_block_mask;
                ()
            });
        }
        Disposition::Default => {
            let _ = crate::process::with_signal_state_for_task(task_id, |state| {
                state.blocked = pre_block_mask;
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
            // Determine the stack to push the signal frame onto.
            // If SA_ONSTACK is set and an alternate stack is registered,
            // use the top of the alternate stack; otherwise use the
            // current user RSP.
            let frame_rsp = if flags & SA_ONSTACK != 0 {
                if let Some(ss) = alt {
                    // Top of the alternate stack (stack grows down).
                    ss.ss_sp + ss.ss_size
                } else {
                    ctx.user_rsp
                }
            } else {
                ctx.user_rsp
            };

            // Capture the syscall arg registers from the caller's own
            // SyscallReturnContext. On the SA_RESTART+handler path,
            // `check_and_deliver_signals` rewound `ctx.user_rip` to the
            // SYSCALL instruction; these are the regs that were live on
            // that SYSCALL and must be replayed when the handler returns
            // via `sigreturn`. On non-restart paths they are harmless to
            // save — the restart trampoline only reloads them when
            // `SYSCALL_RESTART_PENDING` is set (issue #522).
            let saved_regs = frame::SavedSyscallRegs {
                rax: ctx.user_rax,
                rdi: ctx.user_rdi,
                rsi: ctx.user_rsi,
                rdx: ctx.user_rdx,
                r10: ctx.user_r10,
                r8: ctx.user_r8,
                r9: ctx.user_r9,
            };
            // Push signal frame onto the (possibly alternate) stack
            // and redirect SYSRETQ.
            let new_user_rsp = match frame::push_signal_frame(
                frame_rsp,
                sig,
                ctx.user_rip,
                ctx.user_rflags,
                pre_block_mask,
                saved_regs,
                restart_pending,
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
/// `user_rsp` from it, and also restores the saved signal mask. Also
/// recovers the seven Linux x86_64 syscall registers captured at signal
/// delivery so an SA_RESTART-ed syscall underneath the handler replays
/// with its original `(nr, a0..a5)` instead of whatever the handler left
/// behind (issue #522).
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
                syscall_regs: restored.syscall_regs,
                restart_pending: restored.restart_pending,
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
///
/// `syscall_regs` carries the Linux x86_64 syscall registers that were
/// live at the time the signal was delivered. When `restart_pending` is
/// true the caller MUST write `syscall_regs` back into the task's
/// `SyscallReturnContext` and assert `SYSCALL_RESTART_PENDING` so the
/// re-executed SYSCALL sees the original `(nr, a0..a5)`. When
/// `restart_pending` is false the caller MUST leave both the kernel
/// context and the global flag untouched — otherwise a handler that
/// returns normally on a non-SA_RESTART path would have its
/// post-syscall return value in `user_rax` clobbered back to the
/// syscall number (issue #522).
pub struct SigReturnRegs {
    pub rip: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub syscall_regs: frame::SavedSyscallRegs,
    pub restart_pending: bool,
}

} // end bare_metal_only!

// ── Host-side unit tests ──────────────────────────────────────────────────
//
// These tests reference `restart_decision` / the bare-metal
// signal-delivery glue, all of which is gated to `target_os = "none"`
// inside the `bare_metal_only!` block above. Under
// `cargo test --lib --features sched-mock` (host build) those items
// don't exist, so the tests can't compile — gate the module
// accordingly. The tests still run on bare-metal builds via
// `cargo xtask test`; this gate doesn't reduce coverage.

#[cfg(all(test, target_os = "none"))]
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

    // ── has_deliverable ──────────────────────────────────────────────

    #[test]
    fn has_deliverable_empty() {
        let s = SignalState::new();
        assert!(!s.has_deliverable());
    }

    #[test]
    fn has_deliverable_pending_unblocked() {
        let mut s = SignalState::new();
        s.raise(SIGUSR1);
        assert!(s.has_deliverable());
    }

    #[test]
    fn has_deliverable_pending_blocked() {
        let mut s = SignalState::new();
        s.raise(SIGUSR1);
        s.blocked = sig_bit(SIGUSR1);
        assert!(!s.has_deliverable());
    }

    #[test]
    fn has_deliverable_sigkill_bypasses_block() {
        let mut s = SignalState::new();
        s.raise(SIGKILL);
        s.blocked = !0u64;
        assert!(s.has_deliverable());
    }

    // ── saved_mask (sigsuspend support) ──────────────────────────────

    #[test]
    fn saved_mask_starts_none() {
        let s = SignalState::new();
        assert!(s.saved_mask.is_none());
    }

    #[test]
    fn saved_mask_roundtrip() {
        let mut s = SignalState::new();
        s.saved_mask = Some(sig_bit(SIGUSR1) | sig_bit(SIGUSR2));
        assert_eq!(s.saved_mask, Some(sig_bit(SIGUSR1) | sig_bit(SIGUSR2)));
    }

    #[test]
    fn saved_mask_take_clears() {
        let mut s = SignalState::new();
        s.saved_mask = Some(sig_bit(SIGTERM));
        let taken = s.saved_mask.take();
        assert_eq!(taken, Some(sig_bit(SIGTERM)));
        assert!(s.saved_mask.is_none());
    }

    // ── sigpending semantics (pending & blocked) ─────────────────────

    #[test]
    fn pending_and_blocked_intersection() {
        let mut s = SignalState::new();
        s.raise(SIGUSR1);
        s.raise(SIGUSR2);
        s.raise(SIGTERM);
        s.blocked = sig_bit(SIGUSR1) | sig_bit(SIGTERM);
        // sigpending returns the intersection of pending and blocked.
        let result = s.pending & s.blocked;
        assert_eq!(result, sig_bit(SIGUSR1) | sig_bit(SIGTERM));
        // SIGUSR2 is pending but not blocked, so not in sigpending.
        assert_eq!(result & sig_bit(SIGUSR2), 0);
    }

    // ── SA_NODEFER flag ─────────────────────────────────────────────────

    #[test]
    fn sa_nodefer_constant_matches_linux() {
        // Linux x86_64: SA_NODEFER = 0x40000000
        assert_eq!(SA_NODEFER, 0x4000_0000);
    }

    #[test]
    fn sa_onstack_constant_matches_linux() {
        // Linux x86_64: SA_ONSTACK = 0x08000000
        assert_eq!(SA_ONSTACK, 0x0800_0000);
    }

    #[test]
    fn sa_nodefer_does_not_collide_with_sa_restart() {
        assert_eq!(SA_NODEFER & SA_RESTART, 0);
    }

    #[test]
    fn sa_onstack_does_not_collide_with_other_flags() {
        assert_eq!(SA_ONSTACK & SA_RESTART, 0);
        assert_eq!(SA_ONSTACK & SA_NODEFER, 0);
    }

    // ── sigaltstack state ───────────────────────────────────────────────

    #[test]
    fn alt_stack_starts_none() {
        let s = SignalState::new();
        assert!(s.alt_stack.is_none());
    }

    #[test]
    fn alt_stack_roundtrip() {
        let mut s = SignalState::new();
        let ss = SigaltStack {
            ss_sp: 0x7000_0000,
            ss_size: 8192,
        };
        s.alt_stack = Some(ss);
        let stored = s.alt_stack.unwrap();
        assert_eq!(stored.ss_sp, 0x7000_0000);
        assert_eq!(stored.ss_size, 8192);
    }

    #[test]
    fn alt_stack_disable() {
        let mut s = SignalState::new();
        s.alt_stack = Some(SigaltStack {
            ss_sp: 0x7000_0000,
            ss_size: 8192,
        });
        s.alt_stack = None; // SS_DISABLE
        assert!(s.alt_stack.is_none());
    }

    #[test]
    fn ss_disable_constant_matches_linux() {
        assert_eq!(SS_DISABLE, 2);
    }

    #[test]
    fn ss_onstack_constant_matches_linux() {
        assert_eq!(SS_ONSTACK, 1);
    }
}
