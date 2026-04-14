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
//! We save RIP, RFLAGS, and RSP (indices 16, 17, 15) which are sufficient for
//! `sigreturn` to resume the interrupted code.  The others are zero-filled.

use core::mem;

/// Index of key registers in `SigFrame::gregs`.
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
pub struct RestoredRegs {
    pub rip: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub saved_mask: u64,
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

    // Copy frame to user stack.
    let frame_bytes =
        core::slice::from_raw_parts(&frame as *const SigFrame as *const u8, frame_size as usize);
    uaccess::copy_to_user(frame_addr as usize, frame_bytes).map_err(|_| ())?;

    // The new user RSP points at `pretcode` (the bottom of the frame).
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
    }
}
