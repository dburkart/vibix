//! File control operations: open, openat.

use crate::helpers::syscall_ret;
use vibix_abi::syscall;

// Syscall numbers (Linux x86_64)
const SYS_OPEN: u64 = 2;
const SYS_OPENAT: u64 = 257;

/// Open a file by path.
///
/// # Safety
/// `pathname` must be a valid null-terminated C string pointer.
#[no_mangle]
pub unsafe extern "C" fn open(pathname: *const u8, flags: i32, mode: u32) -> i32 {
    let ret = syscall!(SYS_OPEN, pathname, flags, mode);
    syscall_ret(ret) as i32
}

/// Open a file relative to a directory fd.
///
/// # Safety
/// `pathname` must be a valid null-terminated C string pointer.
#[no_mangle]
pub unsafe extern "C" fn openat(dirfd: i32, pathname: *const u8, flags: i32, mode: u32) -> i32 {
    let ret = syscall!(SYS_OPENAT, dirfd, pathname, flags, mode);
    syscall_ret(ret) as i32
}
