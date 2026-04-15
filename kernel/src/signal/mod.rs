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
//!    `#GP`) calls [`deliver_fault_signal`] which directly modifies the
//!    `InterruptStackFrame` so `IRETQ` redirects to the signal handler.
//!
//! ## Limitations (known, tracked as follow-ups)
//!
//! - FPU state (`fpstate_ptr` in `SigFrame`) is always null — signals
//!   delivered to a task using SSE/x87 will see corrupted FP registers.
//! - `SA_NODEFER` and `SA_RESTART` flags are not honoured.
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

/// Maximum signal number supported.  Linux defines 64 but we only need the
/// standard 31 for now.  The bitmask is a `u64` so the representation is
/// future-proof.
pub const NSIG: u8 = 64;

// ── Sigaction disposition ─────────────────────────────────────────────────

/// `SIG_DFL` — default action for the signal.
pub const SIG_DFL: u64 = 0;
/// `SIG_IGN` — ignore the signal.
pub const SIG_IGN: u64 = 1;

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
        SIGSTOP | SIGTSTP => DefaultAction::Stop,
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

// ── Syscall handlers ──────────────────────────────────────────────────────

/// `sigaction(sig, act_uva, oldact_uva)` — register or query a signal
/// handler.
///
/// `act_uva` and `oldact_uva` are user pointers to `struct sigaction`
/// (Linux x86_64 layout: `sa_handler: u64, sa_flags: u64, sa_restorer: u64,
/// sa_mask: u64`).  Only `sa_handler` is read / written; the rest are stored
/// as zero for now (no SA_RESTART / SA_SIGINFO support).
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

        // Write old disposition to userspace if requested.
        if oldact_uva != 0 {
            let mut sa: [u8; 32] = [0u8; 32];
            let handler_ptr = old_disp.to_handler_ptr();
            sa[..8].copy_from_slice(&handler_ptr.to_ne_bytes());
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
            state.dispositions[(sig - 1) as usize] = Disposition::from_handler_ptr(handler_ptr);
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
/// from an interrupt handler with no saved `SyscallReturnContext` — the user
/// RIP/RSP/RFLAGS are captured in the hardware-pushed `InterruptStackFrame`.
///
/// Current scope: only the `SIG_DFL` / `DefaultAction::Terminate` case is
/// implemented. The signal is raised on the current task, then the terminate
/// path runs directly: `reparent_children → mark_zombie(-sig) → task::exit()`.
/// `task::exit()` is `!`, so the exception handler never returns — the
/// scheduler context-switches to the next task instead of executing `IRETQ`.
///
/// Handler-dispatch (`Disposition::Handler`) for fault signals is not yet
/// implemented; installing a SIGSEGV handler and triggering a #PF will fall
/// through to terminate semantics. Tracked in the follow-up to #337.
///
/// # Safety
/// Must be called from an exception handler on behalf of the currently
/// running task. Does not return.
pub unsafe fn deliver_fault_signal_iret(sig: u8) -> ! {
    // Precondition: `sig` is a valid signal number. `sig == 0` would underflow
    // the `dispositions[sig - 1]` index below; guard it in debug builds so a
    // future caller that forgets fails loudly instead of corrupting memory.
    debug_assert!(sig > 0 && sig <= NSIG, "invalid signal number");

    let task_id = crate::task::current_id();
    // Raise, immediately clear the pending bit (we service synchronously),
    // and read the disposition under a single lock acquisition. Doing this in
    // one critical section avoids a window where another path could observe
    // the signal pending while we're already about to service it.
    let disp = crate::process::with_signal_state_for_task(task_id, |state| {
        state.raise(sig);
        state.pending &= !sig_bit(sig);
        state.dispositions[(sig - 1) as usize]
    })
    .unwrap_or(Disposition::Default);

    match disp {
        Disposition::Handler(_) | Disposition::Ignore | Disposition::Default => {
            // Handler + Ignore paths aren't meaningful for a synchronous fault
            // (the faulting instruction would re-fault immediately on IRETQ).
            // Fall through to Terminate for all cases until the follow-up lands.
            let pid = crate::process::current_pid();
            crate::serial_println!("signal: terminate pid={} sig={} (fault)", pid, sig);
            if pid != 0 {
                crate::process::reparent_children(pid);
                crate::process::mark_zombie(pid, -(sig as i32));
            }
        }
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

/// Called from the `syscall_entry` asm trampoline between steps 5 and 6
/// (after `syscall_dispatch` returns, before `pop rcx / sysretq`).
///
/// Two responsibilities:
///
/// 1. **sigreturn**: if `SIGRETURN_PENDING` is set (syscall 15 just ran),
///    overwrite `ctx` with the restored user context from `FORK_USER_*`
///    statics and clear the flag.
///
/// 2. **signal delivery**: if a signal is pending for the current process,
///    pop the lowest pending signal, look up its disposition, and either
///    push a `SigFrame` + redirect `ctx->user_rip` (user handler), exit the
///    process (default terminate), or do nothing (ignored).
///
/// # Safety
/// `ctx` must point to the [`SyscallReturnContext`] fields on the current
/// task's kernel stack.  Called only from `syscall_entry` with IF disabled.
#[no_mangle]
pub unsafe extern "C" fn check_and_deliver_signals(ctx: *mut SyscallReturnContext) {
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
    let sig =
        match crate::process::with_signal_state_for_task(task_id, |state| state.pop_next_pending())
        {
            Some(Some(sig)) => sig,
            _ => return, // no pending signal or no process entry
        };
    deliver_signal(sig, &mut *ctx);
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
}
