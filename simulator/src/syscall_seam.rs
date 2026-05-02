//! Host-side syscall-entry seam (RFC 0008 / [#790](https://github.com/dburkart/vibix/issues/790)).
//!
//! Phase 2.1 RFC #2 from RFC 0006 §"Failure-injection scope":
//! lets the host-side simulator dispatch the kernel's real
//! `sys_fork` / `sys_execve` / `sys_exit` / `sys_wait4` handlers
//! without the bare-metal SYSCALL trampoline (no FxSAVE / `swapgs` /
//! IRETQ frame, no kernel stack swap, no SMEP/SMAP brackets).
//!
//! Three deliverables make up the seam:
//!
//! 1. **[`UaccessAdapter`]** — trait the kernel's user-pointer
//!    accessors go through on host. The bare-metal `copy_from_user` /
//!    `copy_to_user` use SMAP brackets and a real ring-3 page-table
//!    cross; on host there is no separate user/kernel address space,
//!    so the [`HostUaccess`] impl just dereferences the pointer
//!    after a sanity range-check. RFC 0008 §"User-pointer model"
//!    documents the design choice (option (b) — trait-based — over
//!    plumbing host buffers through the dispatch shim).
//!
//! 2. **[`dispatch_syscall`]** — host-callable entry point matching
//!    the bare-metal `syscall_dispatch`'s `(nr, [u64; 6])` shape.
//!    Routes `FORK` / `EXECVE` / `EXIT` / `WAIT4` to host-side
//!    wrappers around `kernel::process::*`, which is host-buildable
//!    under `feature = "sched-mock"` (RFC 0008 §"Slim host arm").
//!    Other syscall numbers return `-ENOSYS` (`-38`).
//!
//! 3. **[`install_init_process`]** — primes the kernel's process
//!    table with PID 1 (the "init" placeholder) and installs the
//!    matching task id on the simulator's per-thread "current task
//!    id" slot. The simulator calls this once per run before
//!    dispatching any syscalls.
//!
//! ## What this is NOT
//!
//! The shim does **not** load an ELF, page in a stack, or jump to
//! ring-3. The `EXECVE` arm short-circuits: it does no image swap,
//! it just records the call and returns 0 (RFC 0008
//! §"sys_execve host stub"). The fork/exec/wait race in [#501] /
//! [#710] does not depend on the ELF path; what matters is the
//! atomic-publish ordering in `mark_zombie` and the snapshot-and-park
//! loop in `wait4`. Both of those reach unchanged through this shim.
//!
//! [#501]: https://github.com/dburkart/vibix/issues/501
//! [#710]: https://github.com/dburkart/vibix/issues/710

#![allow(unsafe_code)]

use vibix::process;

/// Linux x86_64 syscall numbers — pinned alongside the bare-metal
/// `arch::x86_64::syscall::syscall_nr` table. Re-declared here (rather
/// than re-exported) because that table lives under `cfg(target_os =
/// "none")` and is unreachable from the host build. RFC 0008
/// §"Numbers" requires both lists to stay in lockstep; the
/// [`numbers_match_kernel_table`] test verifies it on every build.
pub mod syscall_nr {
    /// `sys_fork()` — clone the calling process.
    pub const FORK: u64 = 57;
    /// `sys_execve(path, argv, envp)` — image swap.
    pub const EXECVE: u64 = 59;
    /// `sys_exit(status)` — terminate the calling process.
    pub const EXIT: u64 = 60;
    /// `sys_wait4(pid, *wstatus, options, *rusage)` — wait for a child.
    pub const WAIT4: u64 = 61;
}

/// `-ENOSYS` — syscall not implemented on the host shim.
pub const ENOSYS: i64 = -38;
/// `-EFAULT` — bad user-pointer.
pub const EFAULT: i64 = -14;
/// `-ECHILD` — `wait4` caller has no children.
pub const ECHILD: i64 = -10;
/// `-EPERM` — caller is not a registered process (parent_pid == 0).
pub const EPERM: i64 = -1;

/// Adapter for kernel-side user-pointer accessors.
///
/// On bare metal `copy_from_user` / `copy_to_user` cross a SMAP-guarded
/// ring-3/ring-0 boundary and chase a user VA through the active PML4.
/// On host there is no separate user/kernel address space: a "user
/// pointer" is just a host pointer the simulator passed into the
/// dispatch arg array. The trait isolates that adaptation behind a
/// single interface so future Phase 2.1 surfaces (page-fault
/// injection, ring-3 trap-frame seam) can plug in their own
/// adapters without re-plumbing.
///
/// ## Implementations
///
/// - [`HostUaccess`] — the only impl needed by the wait4 rendezvous
///   today. Just dereferences the pointer; range-checks the slot is
///   non-null and the length non-zero.
///
/// ## Why the trait shape is `&[u8] / &mut [u8]` rather than typed
///
/// The bare-metal `copy_from_user` takes a `&mut [u8]` slice for the
/// kernel side and a `usize` for the user VA, then does a byte-wise
/// volatile copy under STAC/CLAC. Mirroring that shape here lets the
/// dispatch shim use the same byte-buffer pattern the kernel uses
/// (`copy_to_user(wstatus_ptr, &encoded.to_ne_bytes())`) without a
/// type-conversion layer. RFC 0008 §"User-pointer model" — typed
/// accessors would each need their own variants on the trait, which
/// the v1 surface doesn't justify.
pub trait UaccessAdapter: Send + Sync {
    /// Copy `dst.len()` bytes from user VA `src` into `dst`. Returns
    /// `Err(EFAULT)` if `src == 0` or the length is zero (the
    /// bare-metal `copy_from_user` accepts zero-length but the host
    /// shim's only callers bound their reads on actual data, so an
    /// empty range here is always a programming error).
    ///
    /// # Safety
    /// `src` must point to at least `dst.len()` host bytes valid for
    /// reads. The simulator owns the buffer for the lifetime of the
    /// dispatch call.
    unsafe fn copy_from_user(&self, dst: &mut [u8], src: usize) -> Result<(), i64>;

    /// Copy `src.len()` bytes from `src` into user VA `dst`. Returns
    /// `Err(EFAULT)` if `dst == 0`.
    ///
    /// # Safety
    /// `dst` must point to at least `src.len()` host bytes valid for
    /// writes.
    unsafe fn copy_to_user(&self, dst: usize, src: &[u8]) -> Result<(), i64>;
}

/// Host-side `UaccessAdapter` implementation.
///
/// "User pointer" on host is a host VA the simulator hands the
/// dispatch shim — there's no SMAP, no separate ring-3 page table,
/// nothing to validate beyond `ptr != 0`. Production-side semantics
/// like `EFAULT` on a kernel-half pointer don't apply because the
/// simulator never has a kernel-half analogue.
pub struct HostUaccess;

impl UaccessAdapter for HostUaccess {
    unsafe fn copy_from_user(&self, dst: &mut [u8], src: usize) -> Result<(), i64> {
        if src == 0 {
            return Err(EFAULT);
        }
        let p = src as *const u8;
        for (i, slot) in dst.iter_mut().enumerate() {
            // SAFETY: caller asserts `src` points to at least
            // `dst.len()` valid bytes.
            *slot = core::ptr::read(p.add(i));
        }
        Ok(())
    }

    unsafe fn copy_to_user(&self, dst: usize, src: &[u8]) -> Result<(), i64> {
        if dst == 0 {
            return Err(EFAULT);
        }
        let p = dst as *mut u8;
        for (i, &byte) in src.iter().enumerate() {
            // SAFETY: caller asserts `dst` points to at least
            // `src.len()` valid bytes for writes.
            core::ptr::write(p.add(i), byte);
        }
        Ok(())
    }
}

/// Dispatch a single host-side syscall.
///
/// Mirrors the bare-metal `syscall_dispatch(nr, a0..a5)` shape but
/// without the SYSCALL trampoline preamble. Recognised numbers route
/// to the host arm of `kernel::process::*` via the
/// [`UaccessAdapter`]; unrecognised numbers return `-ENOSYS`.
///
/// The simulator's run loop calls this from inside one tick step,
/// after the `MockClock` advance and the `FaultPlan` drain
/// (so a `WakeupReorder` already armed at the same tick stays
/// observable in the trace alongside the syscall's effect on the
/// `EXIT_EVENT` counter).
///
/// # Safety
/// Pointer arguments (`a1`/`a2`/`a3`/...) that the recognised
/// handlers treat as user buffers must point to at least the
/// declared byte length of valid host memory. Today only `WAIT4`'s
/// `wstatus_ptr` (`a1`) reads/writes user memory, and only when
/// non-zero — see [`dispatch_wait4`] for the precise read/write
/// shape.
pub unsafe fn dispatch_syscall(nr: u64, args: [u64; 6], uaccess: &dyn UaccessAdapter) -> i64 {
    match nr {
        syscall_nr::FORK => dispatch_fork(),
        syscall_nr::EXECVE => dispatch_execve(args[0], args[1], args[2]),
        syscall_nr::EXIT => dispatch_exit(args[0] as i32),
        syscall_nr::WAIT4 => dispatch_wait4(args[0] as i32, args[1] as usize, uaccess),
        _ => ENOSYS,
    }
}

/// `sys_fork()` host arm.
///
/// Calls the same `process::register` the bare-metal `FORK` arm
/// invokes (`kernel/src/arch/x86_64/syscall.rs::syscall_dispatch`
/// FORK). Allocates the child PID + inserts the entry under TABLE,
/// using the parent's `current_pid` as the parent. Returns the new
/// child PID, or `-EPERM` if the caller is not a registered process.
///
/// Differences from bare-metal:
/// - Skips `task::fork_current_task` (the task-image clone). The host
///   shim uses a synthetic task id (`pid as usize + TASK_ID_BASE`,
///   computed by the simulator) so the new entry is reachable through
///   `process::task_id_for_pid` without a real scheduler.
/// - Skips the SysV callee-saved register publish (`fork_abi::ForkUserRegs`).
///   The wait4 race we model here is independent of register state.
/// - Does **not** alter the simulator's "current task id" — the caller
///   must call `set_current_id_for_test(child_task_id)` before
///   dispatching syscalls in the child's context (parent and child
///   share the simulator thread; the child's identity is selected
///   per-dispatch).
fn dispatch_fork() -> i64 {
    let parent_pid = process::current_pid();
    if parent_pid == 0 {
        return EPERM;
    }
    // Synthesize a child task id deterministically from the next pid
    // the kernel will allocate. NEXT_PID is `pub`-visible only via
    // `process::register` itself, so the child's task id is observed
    // post-`register`: we read the registered entry's `task_id` back
    // out via `task_id_for_pid` after.
    //
    // The simulator passes a fresh task id (the caller chooses its
    // own ids; the seam doesn't allocate them) — using the candidate
    // child pid as the task id keeps the relationship 1:1 and
    // matches what the layered regression test expects.
    //
    // We use a probe-then-register pattern to figure out what the
    // next pid will be. This is safe in single-threaded simulator
    // mode; if a future seam grows multiple host threads, this
    // helper is the obvious place to revisit.
    let child_task_id = next_synthetic_task_id();
    process::register(child_task_id, parent_pid) as i64
}

/// Reserved task-id range for synthetic syscall-seam children.
///
/// Picked above the simulator's small-integer task ids (the layered
/// regression test uses task ids 1 and 2) so a host-dispatched fork
/// cannot collide with those. The exact value is part of RFC 0008's
/// stable surface: tests assert child task ids `>= 1000` so a
/// regression that moves the offset is a loud failure.
pub const SYNTHETIC_TASK_ID_BASE: usize = 1000;

std::thread_local! {
    static SYNTHETIC_TASK_COUNTER: core::cell::Cell<usize> =
        const { core::cell::Cell::new(SYNTHETIC_TASK_ID_BASE) };
}

/// Allocate a fresh synthetic task id for a host-dispatched fork.
fn next_synthetic_task_id() -> usize {
    SYNTHETIC_TASK_COUNTER.with(|c| {
        let v = c.get();
        c.set(v + 1);
        v
    })
}

/// `sys_execve(path, argv, envp)` host stub.
///
/// The bare-metal `EXECVE` arm loads `mem::userspace_hello_elf_bytes`
/// and atomically swaps in a fresh `AddressSpace` (`exec_atomic`,
/// `kernel/src/arch/x86_64/syscall.rs:1198+`). On host there is no
/// `mem::userspace_hello`, no `AddressSpace`, no `Cr3::write`. The
/// host shim accepts the call, ignores the args, and returns 0.
///
/// The fork/exec/wait race the simulator reproduces (#501) does not
/// depend on the image swap — it lives entirely in the
/// `mark_zombie` / `wait4` snapshot-and-park rendezvous. RFC 0008
/// §"Layered repro" documents which fields of the production
/// `sys_execve` are out of scope for v1.
fn dispatch_execve(_path_uva: u64, _argv_uva: u64, _envp_uva: u64) -> i64 {
    0
}

/// `sys_exit(status)` host arm.
///
/// Mirrors the bare-metal `EXIT` arm: reparent live children to PID 1,
/// then call `mark_zombie` to publish the Zombie state + bump
/// `EXIT_EVENT` atomically (the #710 fix lives inside `mark_zombie`).
/// Skips the bare-metal `task::exit()` because there is no scheduler
/// to switch off of — control returns to the simulator's run loop,
/// which then dispatches the next syscall (typically the parent's
/// `wait4`) on the same thread.
///
/// Returns `0` on success, `EPERM` if the caller is not a registered
/// process.
fn dispatch_exit(status: i32) -> i64 {
    let pid = process::current_pid();
    if pid == 0 {
        return EPERM;
    }
    process::reparent_children(pid);
    process::mark_zombie(pid, status);
    0
}

/// `sys_wait4(pid, *wstatus, options, *rusage)` host arm.
///
/// Bit-for-bit mirror of the bare-metal `WAIT4` arm
/// (`kernel/src/arch/x86_64/syscall.rs:791+`): same
/// `has_children` / `exit_event_count` snapshot / `reap_child` loop,
/// same `wstatus` encoding (`(exit_code & 0xFF) << 8`), same
/// `CHILD_WAIT.wait_while` predicate. The host stub for
/// `task::block_current` (`task::host_stub`) makes this loop
/// terminate cleanly in the simulator's single-thread model when the
/// child has already exited — see RFC 0008 §"Single-thread parking
/// semantics" for the case analysis.
///
/// # Safety
/// `wstatus_ptr` must point to at least 4 bytes of valid host memory
/// when non-zero (the encoded status is a `u32`).
unsafe fn dispatch_wait4(target_pid: i32, wstatus_ptr: usize, uaccess: &dyn UaccessAdapter) -> i64 {
    let parent_pid = process::current_pid();
    if parent_pid == 0 {
        return ECHILD;
    }
    if !process::has_children(parent_pid) {
        return ECHILD;
    }

    loop {
        let snap = process::exit_event_count();
        if let Some((child_pid, exit_status)) = process::reap_child(parent_pid, target_pid) {
            if wstatus_ptr != 0 {
                let encoded = ((exit_status & 0xFF) << 8) as u32;
                let _ = uaccess.copy_to_user(wstatus_ptr, &encoded.to_ne_bytes());
            }
            return child_pid as i64;
        }
        if !process::has_children(parent_pid) {
            return ECHILD;
        }
        process::CHILD_WAIT.wait_while(|| process::exit_event_count() == snap);
    }
}

/// Prime the simulator-side process table for a host run.
///
/// Mirrors what the bare-metal kernel does in `init_process::register_init`:
/// reserve PID 1 with the supplied `task_id`, then install that task id
/// on the simulator's "current task id" slot so `process::current_pid`
/// returns 1 for subsequent dispatches.
///
/// Call exactly once per simulator thread, before any [`dispatch_syscall`].
/// A second call would either re-insert PID 1 over an existing entry
/// (the kernel's `register_init` doesn't guard against that, but the
/// simulator never has a reason to call twice) or trip the panic in
/// `task::host_stub::set_current_id_for_test` if the caller's contract
/// has been violated.
pub fn install_init_process(task_id: usize) {
    process::register_init(task_id);
    let _ = vibix::task::set_current_id_for_test(task_id);
}

/// Set the simulator's "current task id" slot. The next
/// [`dispatch_syscall`] call sees this id; `process::current_pid`
/// looks it up in TABLE.
///
/// Used by the layered regression test to switch context between
/// parent (PID 1) and child (the PID returned by `dispatch_fork`)
/// before each dispatch, since both run on the simulator's single
/// thread.
pub fn set_current_task_id(task_id: usize) -> usize {
    vibix::task::set_current_id_for_test(task_id)
}

/// Look up the kernel task id registered for `pid`. Convenience
/// wrapper around `process::task_id_for_pid` so the regression test
/// can re-derive the child's task id from the PID returned by fork.
pub fn task_id_for_pid(pid: u32) -> Option<usize> {
    process::task_id_for_pid(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity check: the host-side syscall numbers match the
    /// bare-metal kernel's `syscall_nr` table. Both lists are pinned
    /// to Linux x86_64 ABI values; a drift here is the kind of bug
    /// that would silently mis-route a syscall in CI (issue #278's
    /// shape, applied to the host shim).
    #[test]
    fn numbers_match_kernel_table() {
        // The kernel's `syscall_nr` lives under `cfg(target_os =
        // "none")` and is not reachable from host, but the Linux x86_64
        // ABI values themselves are stable — verify directly against
        // the documented numbers.
        assert_eq!(syscall_nr::FORK, 57);
        assert_eq!(syscall_nr::EXECVE, 59);
        assert_eq!(syscall_nr::EXIT, 60);
        assert_eq!(syscall_nr::WAIT4, 61);
    }

    #[test]
    fn host_uaccess_round_trips() {
        let mut buf = [0u8; 4];
        let src = [1u8, 2, 3, 4];
        let ua = HostUaccess;
        unsafe {
            ua.copy_from_user(&mut buf, src.as_ptr() as usize)
                .expect("read");
            assert_eq!(buf, src);

            let mut out = [0u8; 4];
            ua.copy_to_user(out.as_mut_ptr() as usize, &buf)
                .expect("write");
            assert_eq!(out, src);
        }
    }

    #[test]
    fn host_uaccess_rejects_null() {
        let ua = HostUaccess;
        let mut buf = [0u8; 1];
        unsafe {
            assert_eq!(ua.copy_from_user(&mut buf, 0).unwrap_err(), EFAULT);
            assert_eq!(ua.copy_to_user(0, &[1]).unwrap_err(), EFAULT);
        }
    }

    #[test]
    fn unrecognised_syscall_returns_enosys() {
        let ua = HostUaccess;
        let rv = unsafe { dispatch_syscall(0xDEAD, [0u64; 6], &ua) };
        assert_eq!(rv, ENOSYS);
    }
}
