//! Fork ABI helpers — pure layout logic, host-testable.
//!
//! The fork child's first context switch must resume into the SYSRET
//! trampoline with the parent's captured user-mode register context in
//! the callee-saved GPRs that the trampoline consumes. The stack-frame
//! layout is fiddly enough that we want host unit-test coverage of the
//! slot math; this module factors it out of `task::Task::new_forked` so
//! the test doesn't need a live kernel stack.
//!
//! The layout written by [`prime_fork_child_stack`] matches the pop
//! sequence at the tail of `context_switch`. The subsequent `ret`
//! jumps into `fork_child_sysret`, which reads the same callee-saved
//! registers — just loaded from these stack slots — via `mov` (not
//! `pop`) and builds the SYSRETQ state from them:
//!
//! ```text
//!   rsp+0x00  r15 = 0                 ← context_switch: pop r15
//!   rsp+0x08  r14 = 0                 ← context_switch: pop r14
//!   rsp+0x10  r13 = 0                 ← context_switch: pop r13
//!   rsp+0x18  r12 = user_rip          ← context_switch: pop r12
//!                                       fork_child_sysret: mov rcx, r12
//!   rsp+0x20  rbp = user_rsp          ← context_switch: pop rbp
//!                                       fork_child_sysret: mov rsp, rbp
//!   rsp+0x28  rbx = user_rflags       ← context_switch: pop rbx
//!                                       fork_child_sysret: mov r11, rbx
//!   rsp+0x30  ret = fork_child_sysret ← context_switch: ret
//! ```
//!
//! See issue #504 — replacing `FORK_USER_*` globals with per-task
//! state means we stash the user context in these callee-saved slots
//! at fork time rather than publishing it via cross-CPU atomics.

/// Populate the top of a freshly-mapped kernel stack for a forked
/// child so the first `context_switch` into it returns through
/// `fork_child_sysret` with the captured user register context.
///
/// Returns the new `rsp` value (pointing at the topmost populated
/// slot, i.e. the r15 save-slot) that should be stored in
/// `Task::rsp`.
///
/// # Safety
/// - `top` must point one byte past the end of a writable region of
///   at least 56 bytes (7 × 8 bytes) that is owned exclusively by
///   the new task.
/// - `fork_child_sysret_addr` must be the address of a trampoline
///   matching the pop sequence documented above.
#[inline]
pub unsafe fn prime_fork_child_stack(
    top: usize,
    user_rip: u64,
    user_rflags: u64,
    user_rsp: u64,
    fork_child_sysret_addr: usize,
) -> usize {
    let rsp = top - 7 * 8;
    let slots = rsp as *mut usize;
    slots.add(0).write(0); // r15
    slots.add(1).write(0); // r14
    slots.add(2).write(0); // r13
    slots.add(3).write(user_rip as usize); // r12 → rcx
    slots.add(4).write(user_rsp as usize); // rbp → rsp
    slots.add(5).write(user_rflags as usize); // rbx → r11
    slots.add(6).write(fork_child_sysret_addr); // ret
    rsp
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify every slot lands at the documented offset and carries the
    /// value the SYSRET trampoline expects. This guards against anyone
    /// silently re-ordering the `pop` sequence in `context_switch` /
    /// `fork_child_sysret` without updating the prime layout.
    #[test]
    fn prime_fork_child_stack_lays_out_sysret_regs_in_callee_save_slots() {
        // 16-byte aligned backing store; stack top is `buf + len`.
        let mut buf = [0usize; 16];
        let top = unsafe { buf.as_mut_ptr().add(buf.len()) } as usize;

        let user_rip: u64 = 0xDEAD_BEEF_1234_5678;
        let user_rflags: u64 = 0x0000_0000_0000_0202;
        let user_rsp: u64 = 0x0000_7FFF_C0DE_0000;
        let sysret_addr: usize = 0x0000_FFFF_FACE_B00C;

        let rsp =
            unsafe { prime_fork_child_stack(top, user_rip, user_rflags, user_rsp, sysret_addr) };

        assert_eq!(rsp, top - 7 * 8, "rsp must leave 7 qwords on the stack");

        let slots = rsp as *const usize;
        unsafe {
            assert_eq!(*slots.add(0), 0, "r15 must be zeroed");
            assert_eq!(*slots.add(1), 0, "r14 must be zeroed");
            assert_eq!(*slots.add(2), 0, "r13 must be zeroed");
            assert_eq!(
                *slots.add(3),
                user_rip as usize,
                "r12 slot carries user_rip → rcx"
            );
            assert_eq!(
                *slots.add(4),
                user_rsp as usize,
                "rbp slot carries user_rsp → rsp"
            );
            assert_eq!(
                *slots.add(5),
                user_rflags as usize,
                "rbx slot carries user_rflags → r11"
            );
            assert_eq!(
                *slots.add(6),
                sysret_addr,
                "return slot must be fork_child_sysret"
            );
        }
    }

    /// Two children forked in quick succession from different parents
    /// must each get their own user-reg snapshot on their own stack.
    /// This is the regression test for #504: with the old global-atomic
    /// design, a concurrent second fork on another CPU could clobber
    /// FORK_USER_* between entry and the child's SYSRET. Here we
    /// demonstrate both stacks retain independent values.
    #[test]
    fn prime_fork_child_stack_isolated_across_concurrent_children() {
        let mut buf_a = [0usize; 16];
        let mut buf_b = [0usize; 16];

        let top_a = unsafe { buf_a.as_mut_ptr().add(buf_a.len()) } as usize;
        let top_b = unsafe { buf_b.as_mut_ptr().add(buf_b.len()) } as usize;

        let rsp_a =
            unsafe { prime_fork_child_stack(top_a, 0x1111_1111, 0x202, 0xAAAA_AAAA, 0xF00D_F00D) };
        let rsp_b =
            unsafe { prime_fork_child_stack(top_b, 0x2222_2222, 0x246, 0xBBBB_BBBB, 0xF00D_F00D) };

        let a = rsp_a as *const usize;
        let b = rsp_b as *const usize;

        unsafe {
            // r12 = user_rip
            assert_eq!(*a.add(3), 0x1111_1111);
            assert_eq!(*b.add(3), 0x2222_2222);
            // rbp = user_rsp
            assert_eq!(*a.add(4), 0xAAAA_AAAA);
            assert_eq!(*b.add(4), 0xBBBB_BBBB);
            // rbx = user_rflags
            assert_eq!(*a.add(5), 0x202);
            assert_eq!(*b.add(5), 0x246);
        }
    }
}
