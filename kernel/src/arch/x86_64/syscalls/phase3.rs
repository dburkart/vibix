//! Phase 3 syscalls for `std::thread` and `std::sync` (RFC 0009, issue #856).
//!
//! Implements: clone(56), futex(202), sched_yield(24), set_tid_address(218),
//! gettid(186), getppid(110).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use spin::Mutex;

use super::super::uaccess;

// ─── clone(2) flag bits ────────────────────────────────────────────────────

const CLONE_VM: u64 = 0x0000_0100;
const CLONE_FS: u64 = 0x0000_0200;
const CLONE_FILES: u64 = 0x0000_0400;
const CLONE_SIGHAND: u64 = 0x0000_0800;
const CLONE_THREAD: u64 = 0x0001_0000;
const CLONE_SETTLS: u64 = 0x0008_0000;
const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
const CLONE_SYSVSEM: u64 = 0x0004_0000;

/// The exact flag set we accept for pthread_create-style threads.
const CLONE_THREAD_FLAGS: u64 = CLONE_VM
    | CLONE_FS
    | CLONE_FILES
    | CLONE_SIGHAND
    | CLONE_THREAD
    | CLONE_SETTLS
    | CLONE_PARENT_SETTID
    | CLONE_CHILD_CLEARTID
    | CLONE_SYSVSEM;

// ─── futex(2) operations ──────────────────────────��────────────────────────

const FUTEX_WAIT: u32 = 0;
const FUTEX_WAKE: u32 = 1;
const FUTEX_PRIVATE_FLAG: u32 = 128;
// _PRIVATE variants are handled by stripping the flag in sys_futex.
#[allow(dead_code)]
const FUTEX_WAIT_PRIVATE: u32 = FUTEX_WAIT | FUTEX_PRIVATE_FLAG;
#[allow(dead_code)]
const FUTEX_WAKE_PRIVATE: u32 = FUTEX_WAKE | FUTEX_PRIVATE_FLAG;

// ─── futex wait-queue infrastructure ──────────────────��────────────────────

/// Global futex table: maps a virtual address (within the current address
/// space) to a WaitQueue. For FUTEX_PRIVATE the VA is sufficient as a key
/// since all threads in a process share the same address space.
///
/// For process-shared (non-PRIVATE) futexes we would need to resolve to a
/// physical address — for now the implementation uses VA, which is correct
/// because clone(CLONE_VM) threads share the same page tables.
static FUTEX_TABLE: Mutex<BTreeMap<usize, Vec<usize>>> = Mutex::new(BTreeMap::new());

// ─── per-task clear_child_tid pointer ────────────────────���─────────────────

/// Per-task `clear_child_tid` address, set by `set_tid_address` and
/// `clone(CLONE_CHILD_CLEARTID)`. On thread exit, the kernel writes 0
/// to this address and performs a futex wake on it.
///
/// Stored as a simple global keyed by task_id — threads are the only
/// callers, and each has a unique task_id.
static CLEAR_CHILD_TID: Mutex<BTreeMap<usize, usize>> = Mutex::new(BTreeMap::new());

// ─── syscall implementations ─────────────────────────��─────────────────────

/// `clone(flags, child_stack, parent_tidptr, child_tidptr, tls)` — create
/// a new thread sharing the caller's address space and fd table.
///
/// Only the exact flag combination used by glibc/musl `pthread_create` is
/// accepted; all other combinations return `-EINVAL`.
///
/// # Arguments (Linux x86_64 clone ABI)
/// - `flags` (rdi): clone flags OR'd with exit signal (low byte)
/// - `child_stack` (rsi): top of the child's user stack
/// - `parent_tidptr` (rdx): where to write child TID (CLONE_PARENT_SETTID)
/// - `child_tidptr` (r10): address for CLONE_CHILD_CLEARTID
/// - `tls` (r8): TLS descriptor / FS base for the new thread (CLONE_SETTLS)
///
/// Returns the child's TID (== PID in vibix's 1:1 model) to the parent,
/// and 0 to the child.
pub fn sys_clone(
    ctx: *mut crate::signal::SyscallReturnContext,
    flags: u64,
    child_stack: u64,
    parent_tidptr: u64,
    child_tidptr: u64,
    tls: u64,
) -> i64 {
    // The low byte of flags is the exit signal — mask it out for flag checks.
    let clone_flags = flags & !0xFF;

    // Only accept the exact pthread_create flag set.
    if clone_flags != CLONE_THREAD_FLAGS {
        return crate::fs::EINVAL;
    }

    // child_stack must be non-null for threads (unlike fork).
    if child_stack == 0 {
        return crate::fs::EINVAL;
    }

    // Validate parent_tidptr if CLONE_PARENT_SETTID.
    if clone_flags & CLONE_PARENT_SETTID != 0 && parent_tidptr != 0 {
        if let Err(e) = uaccess::check_user_range(parent_tidptr as usize, 4) {
            return e.as_errno();
        }
    }

    // Build the child's register context from the parent's saved state.
    // The child starts at the same RIP as the parent's return point but
    // with its own stack (child_stack) and rax=0 (clone return value).
    let regs = crate::fork_abi::ForkUserRegs {
        user_rip: unsafe { (*ctx).user_rip },
        user_rflags: unsafe { (*ctx).user_rflags },
        user_rsp: child_stack,
        user_rdi: unsafe { (*ctx).user_rdi },
        user_rsi: unsafe { (*ctx).user_rsi },
        user_rdx: unsafe { (*ctx).user_rdx },
        user_r10: unsafe { (*ctx).user_r10 },
        user_r8: unsafe { (*ctx).user_r8 },
        user_r9: unsafe { (*ctx).user_r9 },
        user_rbx: unsafe { (*ctx).user_rbx },
        user_rbp: unsafe { (*ctx).user_rbp },
        user_r12: unsafe { (*ctx).user_r12 },
        user_r13: unsafe { (*ctx).user_r13 },
        user_r14: unsafe { (*ctx).user_r14 },
        user_r15: unsafe { (*ctx).user_r15 },
    };

    // For CLONE_VM threads: share the parent's address space and fd table
    // (no CoW fork). Use clone_current_as_thread which shares Arc refs.
    let (child_task_id, child_task) = match crate::task::clone_current_as_thread(&regs, tls) {
        Ok(pair) => pair,
        Err(_) => return -12, // ENOMEM
    };

    // Register in the process table BEFORE making the child runnable so
    // that current_pid() returns a valid PID when the child runs (#921).
    let parent_pid = crate::process::current_pid();
    let child_tid = crate::process::register(child_task_id, parent_pid);
    crate::task::make_child_runnable(child_task);

    // CLONE_PARENT_SETTID: write child TID to parent's memory.
    if clone_flags & CLONE_PARENT_SETTID != 0 && parent_tidptr != 0 {
        let tid_val = child_tid as u32;
        let _ = unsafe { uaccess::copy_to_user(parent_tidptr as usize, &tid_val.to_ne_bytes()) };
    }

    // CLONE_CHILD_CLEARTID: record the pointer for the child's exit path.
    if clone_flags & CLONE_CHILD_CLEARTID != 0 && child_tidptr != 0 {
        CLEAR_CHILD_TID
            .lock()
            .insert(child_task_id, child_tidptr as usize);
    }

    child_tid as i64
}

/// `futex(uaddr, op, val, timeout, uaddr2, val3)` — fast userspace mutex.
///
/// Implements FUTEX_WAIT, FUTEX_WAKE, and their _PRIVATE variants.
pub fn sys_futex(uaddr: usize, op: u32, val: u32, _timeout: u64, _uaddr2: u64, _val3: u64) -> i64 {
    // Strip the PRIVATE flag for dispatch — private vs shared uses the
    // same VA-based lookup since all threads share the address space.
    let cmd = op & !FUTEX_PRIVATE_FLAG;

    match cmd {
        FUTEX_WAIT => futex_wait(uaddr, val),
        FUTEX_WAKE => futex_wake(uaddr, val),
        _ => -38, // ENOSYS
    }
}

/// FUTEX_WAIT: if `*uaddr == val`, block the calling thread on `uaddr`.
///
/// The value-check and enqueue are performed atomically under the
/// FUTEX_TABLE lock to prevent the TOCTOU race where a FUTEX_WAKE
/// fires between the value comparison and the enqueue.
fn futex_wait(uaddr: usize, expected: u32) -> i64 {
    // Validate the user pointer (4 bytes).
    if let Err(e) = uaccess::check_user_range(uaddr, 4) {
        return e.as_errno();
    }

    let tid = crate::task::current_id();

    // Hold the FUTEX_TABLE lock across the value read AND the enqueue
    // so that a concurrent FUTEX_WAKE cannot slip between them.
    {
        let mut table = FUTEX_TABLE.lock();

        // Read the current value from userspace.
        let mut buf = [0u8; 4];
        match unsafe { uaccess::copy_from_user(&mut buf, uaddr) } {
            Ok(()) => {}
            Err(e) => return e.as_errno(),
        }
        let current_val = u32::from_ne_bytes(buf);

        // If the value doesn't match, return EAGAIN (spurious wake).
        if current_val != expected {
            return -11; // EAGAIN
        }

        // Enqueue ourselves on this futex address.
        table.entry(uaddr).or_default().push(tid);
    }
    // Lock dropped before parking — we must not block while holding it.

    // Park. The wake side will call task::wake(tid).
    crate::task::block_current();

    // Remove ourselves from the table (in case of spurious wake).
    {
        let mut table = FUTEX_TABLE.lock();
        if let Some(waiters) = table.get_mut(&uaddr) {
            waiters.retain(|&id| id != tid);
            if waiters.is_empty() {
                table.remove(&uaddr);
            }
        }
    }

    0
}

/// FUTEX_WAKE: wake up to `val` threads waiting on `uaddr`.
fn futex_wake(uaddr: usize, val: u32) -> i64 {
    let mut woken = 0u32;
    let max_wake = if val == u32::MAX { u32::MAX } else { val };

    let mut table = FUTEX_TABLE.lock();
    if let Some(waiters) = table.get_mut(&uaddr) {
        while woken < max_wake {
            if let Some(tid) = waiters.pop() {
                crate::task::wake(tid);
                woken += 1;
            } else {
                break;
            }
        }
        if waiters.is_empty() {
            table.remove(&uaddr);
        }
    }

    woken as i64
}

/// `sched_yield()` — voluntarily give up the CPU timeslice.
///
/// Resets the current task's remaining slice to zero so the next
/// preempt_tick rotates it to the back of the ready queue. Returns 0
/// (always succeeds per POSIX).
pub fn sys_sched_yield() -> i64 {
    // Trigger an immediate reschedule by calling block+wake on ourselves,
    // or more simply, invoke the preempt path. The simplest correct
    // implementation: set slice to 0 and call preempt_tick which will
    // rotate us if a peer is ready, otherwise we continue.
    crate::task::yield_current();
    0
}

/// `set_tid_address(tidptr)` — store the clear_child_tid pointer.
///
/// Returns the caller's TID. The stored pointer will be used on thread
/// exit: the kernel writes 0 to `*tidptr` and does a futex_wake on it.
pub fn sys_set_tid_address(tidptr: usize) -> i64 {
    let task_id = crate::task::current_id();
    if tidptr != 0 {
        CLEAR_CHILD_TID.lock().insert(task_id, tidptr);
    } else {
        CLEAR_CHILD_TID.lock().remove(&task_id);
    }
    // Return the caller's TID. In vibix, TID == PID from the process table.
    crate::process::current_pid() as i64
}

/// Called from the task exit path to handle CLONE_CHILD_CLEARTID semantics.
///
/// If the exiting task has a registered `clear_child_tid` pointer:
/// 1. Write 0 to `*tidptr` in userspace.
/// 2. Perform a futex wake on that address (wakes one waiter).
///
/// This enables `pthread_join` which waits on the child's TID location
/// to become 0.
pub fn perform_clear_child_tid(task_id: usize) {
    let tidptr = CLEAR_CHILD_TID.lock().remove(&task_id);
    if let Some(addr) = tidptr {
        // Write 0 to the user address. Ignore errors (task may have
        // already unmapped the page).
        if uaccess::check_user_range(addr, 4).is_ok() {
            let zero = 0u32.to_ne_bytes();
            let _ = unsafe { uaccess::copy_to_user(addr, &zero) };
        }
        // Wake one waiter on this futex address (pthread_join polls here).
        futex_wake(addr, 1);
    }
}

/// `gettid()` — return the thread ID of the calling thread.
///
/// In vibix's 1:1 threading model, TID == PID for now.
pub fn sys_gettid() -> i64 {
    crate::process::current_pid() as i64
}

/// `getppid()` — return the parent process ID.
///
/// Returns 0 if the calling process has no parent (kernel task).
pub fn sys_getppid() -> i64 {
    let pid = crate::process::current_pid();
    if pid == 0 {
        return 0;
    }
    crate::process::parent_pid_of(pid) as i64
}
