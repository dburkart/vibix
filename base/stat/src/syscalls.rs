//! C-ABI syscall shims required by the vibix std fork.
//!
//! The in-repo std fork links against POSIX symbols (`close`, etc.) that are
//! not provided by a system libc on vibix. We supply them here via raw
//! syscall instructions, mirroring the approach in `base/sh/src/syscalls.rs`.

use core::arch::asm;

const SYS_CLOSE: u64 = 3;

extern "C" {
    fn __errno_location() -> *mut i32;
}

#[inline(always)]
unsafe fn raw1(nr: u64, a0: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => ret,
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
    }
    ret
}

/// Convert raw syscall return to C convention: on error set errno, return -1.
#[inline]
unsafe fn cvt(r: i64) -> i64 {
    if r < 0 {
        unsafe { *__errno_location() = (-r) as i32 };
        -1
    } else {
        r
    }
}

#[no_mangle]
pub unsafe extern "C" fn close(fd: i32) -> i32 {
    unsafe { cvt(raw1(SYS_CLOSE, fd as u64)) as i32 }
}
