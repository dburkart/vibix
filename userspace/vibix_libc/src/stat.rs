//! File status operations: stat, fstat, lstat, chmod, chown.

use crate::helpers::syscall_ret;
use vibix_abi::syscall;

// Syscall numbers (Linux x86_64)
const SYS_STAT: u64 = 4;
const SYS_FSTAT: u64 = 5;
const SYS_LSTAT: u64 = 6;
const SYS_CHMOD: u64 = 90;
const SYS_CHOWN: u64 = 92;

/// Get file status by path.
///
/// # Safety
/// `pathname` must be a valid null-terminated C string; `statbuf` must point
/// to a valid `struct stat`-sized buffer.
#[no_mangle]
pub unsafe extern "C" fn stat(pathname: *const u8, statbuf: *mut u8) -> i32 {
    let ret = syscall!(SYS_STAT, pathname, statbuf);
    syscall_ret(ret) as i32
}

/// Get file status by fd.
///
/// # Safety
/// `statbuf` must point to a valid `struct stat`-sized buffer.
#[no_mangle]
pub unsafe extern "C" fn fstat(fd: i32, statbuf: *mut u8) -> i32 {
    let ret = syscall!(SYS_FSTAT, fd, statbuf);
    syscall_ret(ret) as i32
}

/// Get file status of a symlink (does not follow links).
///
/// # Safety
/// `pathname` must be a valid null-terminated C string; `statbuf` must point
/// to a valid `struct stat`-sized buffer.
#[no_mangle]
pub unsafe extern "C" fn lstat(pathname: *const u8, statbuf: *mut u8) -> i32 {
    let ret = syscall!(SYS_LSTAT, pathname, statbuf);
    syscall_ret(ret) as i32
}

/// Change file permissions.
///
/// # Safety
/// `pathname` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn chmod(pathname: *const u8, mode: u32) -> i32 {
    let ret = syscall!(SYS_CHMOD, pathname, mode);
    syscall_ret(ret) as i32
}

/// Change file owner and group.
///
/// # Safety
/// `pathname` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn chown(pathname: *const u8, owner: u32, group: u32) -> i32 {
    let ret = syscall!(SYS_CHOWN, pathname, owner, group);
    syscall_ret(ret) as i32
}
