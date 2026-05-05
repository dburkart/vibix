//! C-ABI syscall shims for the vibix shell.
//!
//! The shell modules (`exec.rs`, `redirect.rs`, `job.rs`) use `extern "C"`
//! blocks to call standard POSIX functions. On vibix these symbols are not
//! provided by a system libc; we implement them here using raw `syscall`
//! instructions, matching the Linux x86_64 ABI that the vibix kernel uses.
//!
//! Each function follows POSIX return conventions: -1 on error with errno
//! set.
//!
//! The errno TLS cell lives in the std fork's vibix_abi (already linked into
//! this binary via `-Z build-std`). We access it through the C-ABI
//! `__errno_location` symbol that vibix_abi exports.

use core::arch::asm;

// Syscall numbers (Linux x86_64 ABI, matching the vibix kernel).
const SYS_READ: u64 = 0;
const SYS_WRITE: u64 = 1;
const SYS_OPEN: u64 = 2;
const SYS_CLOSE: u64 = 3;
const SYS_SIGACTION: u64 = 13;
const SYS_ACCESS: u64 = 21;
const SYS_PIPE: u64 = 22;
const SYS_DUP: u64 = 32;
const SYS_DUP2: u64 = 33;
const SYS_GETPID: u64 = 39;
const SYS_FORK: u64 = 57;
const SYS_EXECVE: u64 = 59;
const SYS_WAIT4: u64 = 61;
const SYS_KILL: u64 = 62;
const SYS_FCNTL: u64 = 72;
const SYS_GETCWD: u64 = 79;
const SYS_CHDIR: u64 = 80;
const SYS_SETPGID: u64 = 109;

extern "C" {
    fn __errno_location() -> *mut i32;
}

/// Raw syscall with 0-3 args. Returns the raw kernel return value.
#[inline(always)]
unsafe fn raw0(nr: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => ret,
            lateout("rcx") _,
            lateout("r11") _,
            lateout("rdx") _,
            lateout("rdi") _,
            lateout("rsi") _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("r10") _,
            options(nostack, preserves_flags),
        );
    }
    ret
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

#[inline(always)]
unsafe fn raw2(nr: u64, a0: u64, a1: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => ret,
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
    }
    ret
}

#[inline(always)]
unsafe fn raw3(nr: u64, a0: u64, a1: u64, a2: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => ret,
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
    }
    ret
}

#[inline(always)]
unsafe fn raw4(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => ret,
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
pub unsafe extern "C" fn fork() -> i32 {
    unsafe { cvt(raw0(SYS_FORK)) as i32 }
}

#[no_mangle]
pub unsafe extern "C" fn wait4(pid: i32, wstatus: *mut i32, options: i32, rusage: *mut u8) -> i32 {
    unsafe {
        cvt(raw4(
            SYS_WAIT4,
            pid as u64,
            wstatus as u64,
            options as u64,
            rusage as u64,
        )) as i32
    }
}

#[no_mangle]
pub unsafe extern "C" fn kill(pid: i32, sig: i32) -> i32 {
    unsafe { cvt(raw2(SYS_KILL, pid as u64, sig as u64)) as i32 }
}

#[no_mangle]
pub unsafe extern "C" fn setpgid(pid: i32, pgid: i32) -> i32 {
    unsafe { cvt(raw2(SYS_SETPGID, pid as u64, pgid as u64)) as i32 }
}

#[no_mangle]
pub unsafe extern "C" fn sigaction(signum: i32, act: *const u8, oldact: *mut u8) -> i32 {
    unsafe { cvt(raw3(SYS_SIGACTION, signum as u64, act as u64, oldact as u64)) as i32 }
}

#[no_mangle]
pub unsafe extern "C" fn pipe(pipefd: *mut i32) -> i32 {
    unsafe { cvt(raw1(SYS_PIPE, pipefd as u64)) as i32 }
}

#[no_mangle]
pub unsafe extern "C" fn dup(oldfd: i32) -> i32 {
    unsafe { cvt(raw1(SYS_DUP, oldfd as u64)) as i32 }
}

#[no_mangle]
pub unsafe extern "C" fn dup2(oldfd: i32, newfd: i32) -> i32 {
    unsafe { cvt(raw2(SYS_DUP2, oldfd as u64, newfd as u64)) as i32 }
}

#[no_mangle]
pub unsafe extern "C" fn fcntl(fd: i32, cmd: i32, arg: u64) -> i32 {
    unsafe { cvt(raw3(SYS_FCNTL, fd as u64, cmd as u64, arg)) as i32 }
}

#[no_mangle]
pub unsafe extern "C" fn access(pathname: *const u8, mode: i32) -> i32 {
    unsafe { cvt(raw2(SYS_ACCESS, pathname as u64, mode as u64)) as i32 }
}

#[no_mangle]
pub unsafe extern "C" fn open(pathname: *const u8, flags: i32, mode: u32) -> i32 {
    unsafe { cvt(raw3(SYS_OPEN, pathname as u64, flags as u64, mode as u64)) as i32 }
}

#[no_mangle]
pub unsafe extern "C" fn close(fd: i32) -> i32 {
    unsafe { cvt(raw1(SYS_CLOSE, fd as u64)) as i32 }
}

#[no_mangle]
pub unsafe extern "C" fn write(fd: i32, buf: *const u8, count: usize) -> isize {
    unsafe { cvt(raw3(SYS_WRITE, fd as u64, buf as u64, count as u64)) as isize }
}

#[no_mangle]
pub unsafe extern "C" fn read(fd: i32, buf: *mut u8, count: usize) -> isize {
    unsafe { cvt(raw3(SYS_READ, fd as u64, buf as u64, count as u64)) as isize }
}

#[no_mangle]
pub unsafe extern "C" fn execve(
    pathname: *const u8,
    argv: *const *const u8,
    envp: *const *const u8,
) -> i32 {
    unsafe {
        cvt(raw3(
            SYS_EXECVE,
            pathname as u64,
            argv as u64,
            envp as u64,
        )) as i32
    }
}

#[no_mangle]
pub unsafe extern "C" fn getcwd(buf: *mut u8, size: usize) -> *mut u8 {
    let r = unsafe { raw2(SYS_GETCWD, buf as u64, size as u64) };
    if r < 0 {
        unsafe { *__errno_location() = (-r) as i32 };
        core::ptr::null_mut()
    } else {
        buf
    }
}

#[no_mangle]
pub unsafe extern "C" fn chdir(path: *const u8) -> i32 {
    unsafe { cvt(raw1(SYS_CHDIR, path as u64)) as i32 }
}

#[no_mangle]
pub unsafe extern "C" fn getpid() -> i32 {
    // getpid never fails, so no errno handling needed.
    unsafe { raw0(SYS_GETPID) as i32 }
}
