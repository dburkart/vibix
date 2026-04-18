//! Signal frame layout and push/restore helpers.
//!
//! The `SigFrame` layout matches the Linux x86_64 `rt_sigframe` so that a
//! userspace `sigreturn(2)` trampoline compiled against musl or glibc works
//! without modification.
//!
//! ## Layout
//!
//! ```text
//! SigFrame (#[repr(C, align(16))]):
//!   pretcode:  u64          — points at the sigreturn syscall stub
//!   sig:       u32          — signal number
//!   _pad:      u32
//!   info:      [u8; 128]    — struct siginfo (si_signo + padding)
//!   uc_flags:  u64
//!   uc_link:   u64
//!   uc_stack:  [u64; 3]     — ss_sp, ss_flags, ss_size
//!   gregs:     [u64; 23]    — mcontext_t gregs (see GREGS_* constants)
//!   uc_sigmask: u64         — saved signal mask
//!   _reserved: [u8; 8]     — alignment / future use
//!   fpstate:   u64          — NULL (FPU state not saved; known limitation)
//! ```
//!
//! Total size: 8+4+4+128+8+8+24+184+8+8+8 = 392 bytes.
//! The struct is 16-byte aligned; user RSP is aligned down before subtracting
//! `size_of::<SigFrame>()`.
//!
//! ## mcontext_t `gregs` field order
//!
//! Linux x86_64 `<sys/ucontext.h>` defines `greg_t gregs[NGREG]` where
//! `NGREG=23`.  The field order (0-indexed) is:
//!
//! ```
//!  0:R8  1:R9   2:R10  3:R11  4:R12  5:R13  6:R14  7:R15
//!  8:RDI 9:RSI 10:RBP 11:RBX 12:RDX 13:RAX 14:RCX 15:RSP
//! 16:RIP 17:EFLAGS 18:CS 19:GS 20:FS 21:ERR 22:TRAPNO
//! ```
//!
//! We save RIP, RFLAGS, and RSP (indices 16, 17, 15) and — for SA_RESTART
//! correctness after a user handler runs — the six Linux syscall arg
//! registers plus the syscall number (RAX, RDI, RSI, RDX, R10, R8, R9).
//! Without those, a signal delivered to a user handler on an ERESTARTSYS
//! path would restart the syscall with whatever the handler left in those
//! registers. See issue #522.  The remaining gregs slots are zero-filled.
//!
//! Mapping of the Linux syscall ABI onto gregs indices:
//!   RAX (syscall nr) → 13, RDI (a0) → 8, RSI (a1) → 9, RDX (a2) → 12,
//!   R10 (a3) → 2,   R8  (a4) → 0, R9  (a5) → 1.

use core::mem;

/// Index of key registers in `SigFrame::gregs`.
const REG_R8: usize = 0;
const REG_R9: usize = 1;
const REG_R10: usize = 2;
const REG_RDI: usize = 8;
const REG_RSI: usize = 9;
const REG_RDX: usize = 12;
const REG_RAX: usize = 13;
const REG_RSP: usize = 15;
const REG_RIP: usize = 16;
const REG_EFLAGS: usize = 17;

/// Inline sigreturn trampoline: `mov rax, 15; syscall`.  This is written into
/// `pretcode` and executed by the signal handler epilogue (if the handler
/// returns normally rather than calling `sigreturn` directly).
///
/// Bytes: `48 C7 C0 0F 00 00 00 0F 05`
const SIGRETURN_TRAMPOLINE: [u8; 9] = [
    0x48, 0xC7, 0xC0, 0x0F, 0x00, 0x00, 0x00, // mov rax, 15
    0x0F, 0x05, // syscall
];

/// The signal frame pushed on the user stack before entering the handler.
///
/// Must be #[repr(C)] so field offsets are stable and match the Linux ABI.
/// 16-byte alignment matches the x86_64 ABI requirement for the stack just
/// before a CALL instruction.
#[repr(C, align(16))]
pub struct SigFrame {
    /// Return address: points at the inline `sigreturn` trampoline stored
    /// in `trampoline_code`.  Placed here so the handler can `ret` into it.
    pub pretcode: u64,
    /// Signal number (1-indexed).
    pub sig: u32,
    pub _pad: u32,
    /// Minimal `struct siginfo` — only `si_signo` is filled.
    pub info: [u8; 128],
    // --- ucontext_t fields ---
    pub uc_flags: u64,
    pub uc_link: u64,
    /// `stack_t uc_stack`: ss_sp, ss_flags, ss_size.
    pub uc_stack: [u64; 3],
    /// `mcontext_t` gregs — 23 × 8 bytes.
    pub gregs: [u64; 23],
    /// Saved signal mask (restored by sigreturn).
    pub uc_sigmask: u64,
    pub _reserved: [u8; 8],
    /// Pointer to saved FPU state.  Always NULL in this implementation.
    pub fpstate: u64,
    /// Inline sigreturn trampoline code.
    pub trampoline_code: [u8; 9],
    pub _trampoline_pad: [u8; 7],
}

/// Compile-time size assertion: the frame must be a multiple of 16 bytes.
const _: () = assert!(mem::size_of::<SigFrame>() % 16 == 0);

/// Recovered register state from a `SigFrame`.
///
/// `syscall_regs` carries the seven Linux x86_64 syscall registers
/// (RAX, RDI, RSI, RDX, R10, R8, R9) that were live on the interrupted
/// SYSCALL instruction, so `sigreturn(2)` can replay an SA_RESTART-ed
/// syscall with its original number and arguments. On all other return
/// paths these values are unused; the caller writes them into the
/// task's `SyscallReturnContext` regardless so the single asm-trampoline
/// restore branch handles both "bare restart" and
/// "restart-from-sigreturn". See issue #522.
pub struct RestoredRegs {
    pub rip: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub saved_mask: u64,
    pub syscall_regs: SavedSyscallRegs,
}

/// The seven Linux x86_64 syscall registers preserved across a
/// signal-handler round-trip so `sigreturn(2)` can restart an
/// SA_RESTART-ed syscall with its original number and args (issue #522).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SavedSyscallRegs {
    /// RAX — syscall number at SYSCALL entry.
    pub rax: u64,
    /// RDI — a0.
    pub rdi: u64,
    /// RSI — a1.
    pub rsi: u64,
    /// RDX — a2.
    pub rdx: u64,
    /// R10 — a3.
    pub r10: u64,
    /// R8 — a4.
    pub r8: u64,
    /// R9 — a5.
    pub r9: u64,
}

/// Push a `SigFrame` onto the user stack at `user_rsp` and return the new
/// (lower) user RSP.
///
/// The frame is aligned so that RSP is `8 mod 16` at handler entry (x86-64
/// ABI: RSP must be `8 mod 16` at `CALL`/function entry; the handler
/// receives control via the `pretcode` return-address slot, so no extra
/// adjustment is needed).
///
/// Returns `Ok(new_rsp)` or `Err(())` if the frame could not be written (bad
/// user pointer).
///
/// # Safety
/// Writes to user VA via `uaccess::copy_to_user`.
pub unsafe fn push_signal_frame(
    user_rsp: u64,
    sig: u8,
    saved_rip: u64,
    saved_rflags: u64,
    saved_mask: u64,
    syscall_regs: SavedSyscallRegs,
) -> Result<u64, ()> {
    use crate::arch::x86_64::uaccess;

    // Align the frame bottom to 16 bytes, then subtract 8 so that RSP is
    // `8 mod 16` at handler entry (x86-64 ABI requirement at CALL).
    let frame_size = mem::size_of::<SigFrame>() as u64;
    let frame_top = user_rsp.checked_sub(frame_size).ok_or(())?;
    let frame_addr = (frame_top & !15u64).wrapping_sub(8);

    // Validate the user address range before writing.
    if uaccess::check_user_range(frame_addr as usize, frame_size as usize).is_err() {
        return Err(());
    }

    // Build the frame in kernel memory, then copy it to user space.
    let mut frame = SigFrame {
        pretcode: frame_addr + mem::offset_of!(SigFrame, trampoline_code) as u64,
        sig: sig as u32,
        _pad: 0,
        info: [0u8; 128],
        uc_flags: 0,
        uc_link: 0,
        uc_stack: [0u64; 3],
        gregs: [0u64; 23],
        uc_sigmask: saved_mask,
        _reserved: [0u8; 8],
        fpstate: 0,
        trampoline_code: SIGRETURN_TRAMPOLINE,
        _trampoline_pad: [0u8; 7],
    };

    // Fill in siginfo.si_signo.
    frame.info[..4].copy_from_slice(&(sig as u32).to_ne_bytes());

    // Save the interrupted register state into mcontext gregs.
    frame.gregs[REG_RIP] = saved_rip;
    frame.gregs[REG_EFLAGS] = saved_rflags;
    frame.gregs[REG_RSP] = user_rsp;

    // Save the Linux syscall-ABI registers so `sigreturn(2)` can replay
    // an SA_RESTART-ed syscall with the original (nr, a0..a5). Without
    // these, a user handler that clobbers any of rax/rdi/rsi/rdx/r10/r8/r9
    // would corrupt the restarted syscall (issue #522).
    frame.gregs[REG_RAX] = syscall_regs.rax;
    frame.gregs[REG_RDI] = syscall_regs.rdi;
    frame.gregs[REG_RSI] = syscall_regs.rsi;
    frame.gregs[REG_RDX] = syscall_regs.rdx;
    frame.gregs[REG_R10] = syscall_regs.r10;
    frame.gregs[REG_R8] = syscall_regs.r8;
    frame.gregs[REG_R9] = syscall_regs.r9;

    // Copy frame to user stack.
    let frame_bytes =
        core::slice::from_raw_parts(&frame as *const SigFrame as *const u8, frame_size as usize);
    uaccess::copy_to_user(frame_addr as usize, frame_bytes).map_err(|_| ())?;

    // The new user RSP points at `pretcode` (the bottom of the frame).
    Ok(frame_addr)
}

/// Push a `SigFrame` for a hardware fault (e.g. `#PF` SIGSEGV) onto the user
/// stack.  Same as [`push_signal_frame`] but additionally writes `fault_addr`
/// into `siginfo.si_addr` (bytes 16–23 of `info`) and sets `si_code` to
/// `SEGV_MAPERR` (1) at bytes 4–7 so the handler can inspect the faulting
/// address via `siginfo_t`.
///
/// Returns `Ok(new_rsp)` or `Err(())` on a bad user pointer.
///
/// # Safety
/// Writes to user VA via `uaccess::copy_to_user`.
pub unsafe fn push_fault_signal_frame(
    user_rsp: u64,
    sig: u8,
    saved_rip: u64,
    saved_rflags: u64,
    saved_mask: u64,
    fault_addr: u64,
) -> Result<u64, ()> {
    use crate::arch::x86_64::uaccess;

    let frame_size = mem::size_of::<SigFrame>() as u64;
    let frame_top = user_rsp.checked_sub(frame_size).ok_or(())?;
    let frame_addr = (frame_top & !15u64).wrapping_sub(8);

    if uaccess::check_user_range(frame_addr as usize, frame_size as usize).is_err() {
        return Err(());
    }

    let mut frame = SigFrame {
        pretcode: frame_addr + mem::offset_of!(SigFrame, trampoline_code) as u64,
        sig: sig as u32,
        _pad: 0,
        info: [0u8; 128],
        uc_flags: 0,
        uc_link: 0,
        uc_stack: [0u64; 3],
        gregs: [0u64; 23],
        uc_sigmask: saved_mask,
        _reserved: [0u8; 8],
        fpstate: 0,
        trampoline_code: SIGRETURN_TRAMPOLINE,
        _trampoline_pad: [0u8; 7],
    };

    // si_signo (bytes 0–3)
    frame.info[..4].copy_from_slice(&(sig as u32).to_ne_bytes());
    // si_code = SEGV_MAPERR=1 (bytes 4–7)
    frame.info[4..8].copy_from_slice(&1u32.to_ne_bytes());
    // si_addr (bytes 16–23)
    frame.info[16..24].copy_from_slice(&fault_addr.to_ne_bytes());

    frame.gregs[REG_RIP] = saved_rip;
    frame.gregs[REG_EFLAGS] = saved_rflags;
    frame.gregs[REG_RSP] = user_rsp;
    // Fault path does not resume an interrupted SYSCALL — the interrupted
    // code is user code at `saved_rip`, not a syscall. Leave the syscall
    // arg gregs as zero so a (malicious or defensive) sigreturn cannot
    // synthesize a SYSCALL-arg reload on the fault-recovery path.

    let frame_bytes =
        core::slice::from_raw_parts(&frame as *const SigFrame as *const u8, frame_size as usize);
    uaccess::copy_to_user(frame_addr as usize, frame_bytes).map_err(|_| ())?;

    Ok(frame_addr)
}

/// Restore register context from a `SigFrame` at `frame_addr` on the user
/// stack.
///
/// Returns the saved `[rip, rflags, rsp, saved_mask]` or `Err(())` if the
/// frame cannot be read.
///
/// # Safety
/// Reads from user VA via `uaccess::copy_from_user`.
pub unsafe fn restore_signal_frame(frame_addr: u64) -> Result<RestoredRegs, ()> {
    use crate::arch::x86_64::uaccess;

    let frame_size = mem::size_of::<SigFrame>();
    if uaccess::check_user_range(frame_addr as usize, frame_size).is_err() {
        return Err(());
    }

    // Read frame from user space into a kernel buffer.
    let mut frame = core::mem::MaybeUninit::<SigFrame>::uninit();
    let frame_bytes = core::slice::from_raw_parts_mut(frame.as_mut_ptr() as *mut u8, frame_size);
    uaccess::copy_from_user(frame_bytes, frame_addr as usize).map_err(|_| ())?;
    let frame = frame.assume_init();

    let rip = frame.gregs[REG_RIP];
    let rsp = frame.gregs[REG_RSP];

    // Reject kernel-space RIP or RSP — a compromised frame must not redirect
    // execution into the kernel.
    if uaccess::check_user_range(rip as usize, 1).is_err() {
        return Err(());
    }
    if uaccess::check_user_range(rsp as usize, 1).is_err() {
        return Err(());
    }

    Ok(RestoredRegs {
        rip,
        rflags: frame.gregs[REG_EFLAGS],
        rsp,
        saved_mask: frame.uc_sigmask,
        syscall_regs: SavedSyscallRegs {
            rax: frame.gregs[REG_RAX],
            rdi: frame.gregs[REG_RDI],
            rsi: frame.gregs[REG_RSI],
            rdx: frame.gregs[REG_RDX],
            r10: frame.gregs[REG_R10],
            r8: frame.gregs[REG_R8],
            r9: frame.gregs[REG_R9],
        },
    })
}

// ── Host-side unit tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigframe_size_is_multiple_of_16() {
        assert_eq!(mem::size_of::<SigFrame>() % 16, 0);
    }

    #[test]
    fn sigframe_pretcode_offset_is_zero() {
        // pretcode is the first field — handler `ret` jumps here.
        assert_eq!(mem::offset_of!(SigFrame, pretcode), 0);
    }

    #[test]
    fn trampoline_contains_sigreturn_syscall() {
        let f = SigFrame {
            pretcode: 0,
            sig: 0,
            _pad: 0,
            info: [0u8; 128],
            uc_flags: 0,
            uc_link: 0,
            uc_stack: [0u64; 3],
            gregs: [0u64; 23],
            uc_sigmask: 0,
            _reserved: [0u8; 8],
            fpstate: 0,
            trampoline_code: SIGRETURN_TRAMPOLINE,
            _trampoline_pad: [0u8; 7],
        };
        // First two bytes of the trampoline: REX.W prefix (0x48) + opcode for MOV RAX
        assert_eq!(f.trampoline_code[0], 0x48);
        assert_eq!(f.trampoline_code[1], 0xC7);
        // Last two bytes: syscall (0x0F 0x05)
        assert_eq!(f.trampoline_code[7], 0x0F);
        assert_eq!(f.trampoline_code[8], 0x05);
    }

    #[test]
    fn gregs_indices_are_in_range() {
        assert!(REG_RSP < 23);
        assert!(REG_RIP < 23);
        assert!(REG_EFLAGS < 23);
        // #522: syscall-arg register indices must all stay in range.
        assert!(REG_RAX < 23);
        assert!(REG_RDI < 23);
        assert!(REG_RSI < 23);
        assert!(REG_RDX < 23);
        assert!(REG_R10 < 23);
        assert!(REG_R8 < 23);
        assert!(REG_R9 < 23);
    }

    #[test]
    fn syscall_greg_indices_match_linux_abi() {
        // Linux x86_64 <sys/ucontext.h> REG_* ordering. Any drift here
        // would silently miswire which gregs slot holds which syscall
        // arg across the sigreturn boundary (issue #522).
        assert_eq!(REG_R8, 0);
        assert_eq!(REG_R9, 1);
        assert_eq!(REG_R10, 2);
        assert_eq!(REG_RDI, 8);
        assert_eq!(REG_RSI, 9);
        assert_eq!(REG_RDX, 12);
        assert_eq!(REG_RAX, 13);
    }

    #[test]
    fn syscall_greg_indices_are_pairwise_distinct() {
        // Guard against a typo that would collapse two fields onto the
        // same gregs slot — the unit test above pins each value, but an
        // explicit uniqueness check keeps the intent clear and the
        // failure mode obvious if someone ever edits the constants.
        let idxs = [
            REG_R8, REG_R9, REG_R10, REG_RDI, REG_RSI, REG_RDX, REG_RAX, REG_RSP, REG_RIP,
            REG_EFLAGS,
        ];
        for (i, a) in idxs.iter().enumerate() {
            for b in idxs.iter().skip(i + 1) {
                assert_ne!(a, b, "duplicate gregs index {a}");
            }
        }
    }
}
