//! Fork ABI helpers — pure layout logic, host-testable.
//!
//! The fork child's first context switch must resume into the SYSRET
//! trampoline with the parent's full captured user-mode register set
//! restored — see #690 for why "full" matters: SysV treats `rbx`, `rbp`,
//! `r12`–`r15` as callee-saved across function calls, so any userspace
//! local the compiler holds in one of these across `sys_fork()` must
//! survive the syscall in the child too. The kernel cannot rely on
//! "callee-saved means we leave them alone": the child's first dispatch
//! into ring-3 happens via `fork_child_sysret`, not a paired ret with
//! the parent, so we have to publish the parent's values explicitly.
//!
//! The stack-frame layout is fiddly enough that we want host unit-test
//! coverage of the slot math; this module factors it out of
//! `task::Task::new_forked` so the test doesn't need a live kernel
//! stack.
//!
//! The layout written by [`prime_fork_child_stack`] matches:
//!   1. The pop sequence at the tail of `context_switch` (which loads
//!      rbx/rbp/r12-r15 directly with their final user values).
//!   2. The `mov`/`pop` sequence at the head of `fork_child_sysret`,
//!      which loads rcx/r11 (RIP/RFLAGS for SYSRETQ), the syscall-arg
//!      registers (rdi/rsi/rdx/r10/r8/r9 — though by SysV they aren't
//!      callee-saved, restoring them lets a userspace fork wrapper
//!      observe a deterministic register state in both parent and
//!      child paths), and finally rsp.
//!
//! Stack layout (low addr → high; `rsp` after context_switch's `ret`
//! pops the trampoline address points at user_rip slot):
//!
//! ```text
//!   rsp+0x00  r15 = user_r15          ← context_switch: pop r15
//!   rsp+0x08  r14 = user_r14          ← context_switch: pop r14
//!   rsp+0x10  r13 = user_r13          ← context_switch: pop r13
//!   rsp+0x18  r12 = user_r12          ← context_switch: pop r12
//!   rsp+0x20  rbp = user_rbp          ← context_switch: pop rbp
//!   rsp+0x28  rbx = user_rbx          ← context_switch: pop rbx
//!   rsp+0x30  ret = fork_child_sysret ← context_switch: ret
//!   rsp+0x38  user_rip                \   fork_child_sysret reads
//!   rsp+0x40  user_rflags             |   these to build the SYSRETQ
//!   rsp+0x48  user_rsp                |   state plus the user
//!   rsp+0x50  user_rdi                |   syscall-arg registers, then
//!   rsp+0x58  user_rsi                |   issues SYSRETQ.
//!   rsp+0x60  user_rdx                |
//!   rsp+0x68  user_r10                |
//!   rsp+0x70  user_r8                 |
//!   rsp+0x78  user_r9                 /
//! ```
//!
//! See issue #504 — replacing `FORK_USER_*` globals with per-task
//! state means we stash the user context in these slots at fork time
//! rather than publishing it via cross-CPU atomics. Issue #690
//! extended the slot set from the original 3 (rip, rsp, rflags) +
//! placeholders to the full 13-GPR set (callee-saved + arg regs).

/// Snapshot of every user GPR the FORK syscall path needs to publish
/// to the child. Bundled as a single struct so the priming function
/// signature stays readable at the call site (and so adding more
/// registers later — e.g. for clone3-style thread spawn — is a single
/// edit).
#[derive(Clone, Copy, Debug, Default)]
pub struct ForkUserRegs {
    pub user_rip: u64,
    pub user_rflags: u64,
    pub user_rsp: u64,
    pub user_rdi: u64,
    pub user_rsi: u64,
    pub user_rdx: u64,
    pub user_r10: u64,
    pub user_r8: u64,
    pub user_r9: u64,
    pub user_rbx: u64,
    pub user_rbp: u64,
    pub user_r12: u64,
    pub user_r13: u64,
    pub user_r14: u64,
    pub user_r15: u64,
}

/// Total bytes of stack consumed by [`prime_fork_child_stack`].
///
/// 7 qwords for the `context_switch` callee-saved frame + return slot,
/// plus 9 qwords for the user GPRs `fork_child_sysret` consumes
/// (3 SYSRETQ regs + 6 arg regs).
pub const FORK_PRIME_BYTES: usize = (7 + 9) * 8;

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
///   at least [`FORK_PRIME_BYTES`] that is owned exclusively by the
///   new task.
/// - `fork_child_sysret_addr` must be the address of a trampoline
///   matching the documented layout above.
#[inline]
pub unsafe fn prime_fork_child_stack(
    top: usize,
    regs: &ForkUserRegs,
    fork_child_sysret_addr: usize,
) -> usize {
    let rsp = top - FORK_PRIME_BYTES;
    let slots = rsp as *mut usize;
    // context_switch pops these in low→high order
    slots.add(0).write(regs.user_r15 as usize); // pop r15
    slots.add(1).write(regs.user_r14 as usize); // pop r14
    slots.add(2).write(regs.user_r13 as usize); // pop r13
    slots.add(3).write(regs.user_r12 as usize); // pop r12
    slots.add(4).write(regs.user_rbp as usize); // pop rbp
    slots.add(5).write(regs.user_rbx as usize); // pop rbx
    slots.add(6).write(fork_child_sysret_addr); // ret → fork_child_sysret
                                                // fork_child_sysret consumes these via pop / [rsp+N] mov (see asm)
    slots.add(7).write(regs.user_rip as usize); // → rcx (SYSRETQ RIP)
    slots.add(8).write(regs.user_rflags as usize); // → r11 (SYSRETQ RFLAGS)
    slots.add(9).write(regs.user_rsp as usize); // → rsp (SYSRETQ user RSP)
    slots.add(10).write(regs.user_rdi as usize); // → rdi
    slots.add(11).write(regs.user_rsi as usize); // → rsi
    slots.add(12).write(regs.user_rdx as usize); // → rdx
    slots.add(13).write(regs.user_r10 as usize); // → r10
    slots.add(14).write(regs.user_r8 as usize); // → r8
    slots.add(15).write(regs.user_r9 as usize); // → r9
    rsp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_regs() -> ForkUserRegs {
        ForkUserRegs {
            user_rip: 0xDEAD_BEEF_1234_5678,
            user_rflags: 0x0000_0000_0000_0202,
            user_rsp: 0x0000_7FFF_C0DE_0000,
            user_rdi: 0x1111_1111_1111_1111,
            user_rsi: 0x2222_2222_2222_2222,
            user_rdx: 0x3333_3333_3333_3333,
            user_r10: 0xAAAA_AAAA_AAAA_AAAA,
            user_r8: 0x8888_8888_8888_8888,
            user_r9: 0x9999_9999_9999_9999,
            user_rbx: 0xBBBB_BBBB_BBBB_BBBB,
            user_rbp: 0xBDBD_BDBD_BDBD_BDBD,
            user_r12: 0xC0C0_C0C0_C0C0_C0C0,
            user_r13: 0xD0D0_D0D0_D0D0_D0D0,
            user_r14: 0xE0E0_E0E0_E0E0_E0E0,
            user_r15: 0xF0F0_F0F0_F0F0_F0F0,
        }
    }

    /// Verify every slot lands at the documented offset and carries the
    /// value the SYSRET trampoline expects. This guards against anyone
    /// silently re-ordering the `pop` sequence in `context_switch` /
    /// `fork_child_sysret` without updating the prime layout.
    #[test]
    fn prime_fork_child_stack_lays_out_sysret_regs_in_callee_save_slots() {
        // Backing store sized for the full prime frame; stack top is
        // `buf + len`.
        let mut buf = [0usize; 32];
        let top = unsafe { buf.as_mut_ptr().add(buf.len()) } as usize;

        let regs = sample_regs();
        let sysret_addr: usize = 0x0000_FFFF_FACE_B00C;

        let rsp = unsafe { prime_fork_child_stack(top, &regs, sysret_addr) };

        assert_eq!(
            rsp,
            top - FORK_PRIME_BYTES,
            "rsp must leave FORK_PRIME_BYTES on the stack"
        );

        let slots = rsp as *const usize;
        unsafe {
            // context_switch pop slots
            assert_eq!(*slots.add(0), regs.user_r15 as usize, "r15 slot");
            assert_eq!(*slots.add(1), regs.user_r14 as usize, "r14 slot");
            assert_eq!(*slots.add(2), regs.user_r13 as usize, "r13 slot");
            assert_eq!(*slots.add(3), regs.user_r12 as usize, "r12 slot");
            assert_eq!(*slots.add(4), regs.user_rbp as usize, "rbp slot");
            assert_eq!(*slots.add(5), regs.user_rbx as usize, "rbx slot");
            assert_eq!(*slots.add(6), sysret_addr, "ret slot");
            // fork_child_sysret consumes these
            assert_eq!(*slots.add(7), regs.user_rip as usize, "user_rip slot");
            assert_eq!(*slots.add(8), regs.user_rflags as usize, "user_rflags slot");
            assert_eq!(*slots.add(9), regs.user_rsp as usize, "user_rsp slot");
            assert_eq!(*slots.add(10), regs.user_rdi as usize, "user_rdi slot");
            assert_eq!(*slots.add(11), regs.user_rsi as usize, "user_rsi slot");
            assert_eq!(*slots.add(12), regs.user_rdx as usize, "user_rdx slot");
            assert_eq!(*slots.add(13), regs.user_r10 as usize, "user_r10 slot");
            assert_eq!(*slots.add(14), regs.user_r8 as usize, "user_r8 slot");
            assert_eq!(*slots.add(15), regs.user_r9 as usize, "user_r9 slot");
        }
    }

    /// Two children forked in quick succession from different parents
    /// must each get their own user-reg snapshot on their own stack.
    /// This is the regression test for #504: with the old global-atomic
    /// design, a concurrent second fork on another CPU could clobber
    /// FORK_USER_* between entry and the child's SYSRET. Here we
    /// demonstrate both stacks retain independent values across the
    /// extended #690 slot set too.
    #[test]
    fn prime_fork_child_stack_isolated_across_concurrent_children() {
        let mut buf_a = [0usize; 32];
        let mut buf_b = [0usize; 32];

        let top_a = unsafe { buf_a.as_mut_ptr().add(buf_a.len()) } as usize;
        let top_b = unsafe { buf_b.as_mut_ptr().add(buf_b.len()) } as usize;

        let mut a_regs = sample_regs();
        a_regs.user_rip = 0x1111_1111;
        a_regs.user_rsp = 0xAAAA_AAAA;
        a_regs.user_rbx = 0xA1A1_A1A1;
        a_regs.user_r15 = 0xAFAF_AFAF;

        let mut b_regs = sample_regs();
        b_regs.user_rip = 0x2222_2222;
        b_regs.user_rsp = 0xBBBB_BBBB;
        b_regs.user_rbx = 0xB1B1_B1B1;
        b_regs.user_r15 = 0xBFBF_BFBF;

        let rsp_a = unsafe { prime_fork_child_stack(top_a, &a_regs, 0xF00D_F00D) };
        let rsp_b = unsafe { prime_fork_child_stack(top_b, &b_regs, 0xF00D_F00D) };

        let a = rsp_a as *const usize;
        let b = rsp_b as *const usize;

        unsafe {
            assert_eq!(*a.add(0), 0xAFAF_AFAF, "child A r15 slot");
            assert_eq!(*b.add(0), 0xBFBF_BFBF, "child B r15 slot");
            assert_eq!(*a.add(5), 0xA1A1_A1A1, "child A rbx slot");
            assert_eq!(*b.add(5), 0xB1B1_B1B1, "child B rbx slot");
            assert_eq!(*a.add(7), 0x1111_1111, "child A user_rip slot");
            assert_eq!(*b.add(7), 0x2222_2222, "child B user_rip slot");
            assert_eq!(*a.add(9), 0xAAAA_AAAA, "child A user_rsp slot");
            assert_eq!(*b.add(9), 0xBBBB_BBBB, "child B user_rsp slot");
        }
    }
}
