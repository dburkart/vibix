//! Raw syscall interface for vibix.
//!
//! The `syscall!()` macro wraps inline x86_64 `syscall` assembly with the
//! correct clobber registers per the Linux x86_64 syscall convention (and
//! issue #531). The kernel does not preserve rdi/rsi/rdx/r8/r9/r10 across
//! a syscall, so every argument register is declared `inlateout` and rcx/r11
//! are clobbered by the CPU itself.

/// Issue a raw syscall.  Returns the value left in `rax` (negative values
/// encode `-errno`).
///
/// # Safety
///
/// The caller must ensure the syscall number and arguments are valid.
#[macro_export]
macro_rules! syscall {
    ($nr:expr) => {
        $crate::syscall::syscall0($nr as u64)
    };
    ($nr:expr, $a0:expr) => {
        $crate::syscall::syscall1($nr as u64, $a0 as u64)
    };
    ($nr:expr, $a0:expr, $a1:expr) => {
        $crate::syscall::syscall2($nr as u64, $a0 as u64, $a1 as u64)
    };
    ($nr:expr, $a0:expr, $a1:expr, $a2:expr) => {
        $crate::syscall::syscall3($nr as u64, $a0 as u64, $a1 as u64, $a2 as u64)
    };
    ($nr:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr) => {
        $crate::syscall::syscall4($nr as u64, $a0 as u64, $a1 as u64, $a2 as u64, $a3 as u64)
    };
    ($nr:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr) => {
        $crate::syscall::syscall5(
            $nr as u64, $a0 as u64, $a1 as u64, $a2 as u64, $a3 as u64, $a4 as u64,
        )
    };
    ($nr:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr) => {
        $crate::syscall::syscall6(
            $nr as u64, $a0 as u64, $a1 as u64, $a2 as u64, $a3 as u64, $a4 as u64, $a5 as u64,
        )
    };
}

#[inline(always)]
pub unsafe fn syscall0(nr: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr as i64 => ret,
        lateout("rcx") _,
        lateout("r11") _,
        lateout("rdx") _,
        lateout("rsi") _,
        lateout("rdi") _,
        lateout("r8") _,
        lateout("r9") _,
        lateout("r10") _,
        options(nostack, preserves_flags),
    );
    ret
}

#[inline(always)]
pub unsafe fn syscall1(nr: u64, a0: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr as i64 => ret,
        inlateout("rdi") a0 => _,
        lateout("rcx") _,
        lateout("r11") _,
        lateout("rdx") _,
        lateout("rsi") _,
        lateout("r8") _,
        lateout("r9") _,
        lateout("r10") _,
        options(nostack, preserves_flags),
    );
    ret
}

#[inline(always)]
pub unsafe fn syscall2(nr: u64, a0: u64, a1: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr as i64 => ret,
        inlateout("rdi") a0 => _,
        inlateout("rsi") a1 => _,
        lateout("rcx") _,
        lateout("r11") _,
        lateout("rdx") _,
        lateout("r8") _,
        lateout("r9") _,
        lateout("r10") _,
        options(nostack, preserves_flags),
    );
    ret
}

#[inline(always)]
pub unsafe fn syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr as i64 => ret,
        inlateout("rdi") a0 => _,
        inlateout("rsi") a1 => _,
        inlateout("rdx") a2 => _,
        lateout("rcx") _,
        lateout("r11") _,
        lateout("r8") _,
        lateout("r9") _,
        lateout("r10") _,
        options(nostack, preserves_flags),
    );
    ret
}

#[inline(always)]
pub unsafe fn syscall4(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr as i64 => ret,
        inlateout("rdi") a0 => _,
        inlateout("rsi") a1 => _,
        inlateout("rdx") a2 => _,
        inlateout("r10") a3 => _,
        lateout("rcx") _,
        lateout("r11") _,
        lateout("r8") _,
        lateout("r9") _,
        options(nostack, preserves_flags),
    );
    ret
}

#[inline(always)]
pub unsafe fn syscall5(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr as i64 => ret,
        inlateout("rdi") a0 => _,
        inlateout("rsi") a1 => _,
        inlateout("rdx") a2 => _,
        inlateout("r10") a3 => _,
        inlateout("r8") a4 => _,
        lateout("rcx") _,
        lateout("r11") _,
        lateout("r9") _,
        options(nostack, preserves_flags),
    );
    ret
}

#[inline(always)]
pub unsafe fn syscall6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr as i64 => ret,
        inlateout("rdi") a0 => _,
        inlateout("rsi") a1 => _,
        inlateout("rdx") a2 => _,
        inlateout("r10") a3 => _,
        inlateout("r8") a4 => _,
        inlateout("r9") a5 => _,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    ret
}
