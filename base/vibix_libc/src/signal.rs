//! Signal operations: sigaction, kill.

use crate::helpers::syscall_ret;
use vibix_abi::syscall;

// Syscall numbers (Linux x86_64)
const SYS_SIGACTION: u64 = 13;
const SYS_KILL: u64 = 62;

/// Install or query a signal handler.
///
/// # Safety
/// `act` and `oldact` must be valid pointers to `sigaction` structs (or null).
#[no_mangle]
pub unsafe extern "C" fn sigaction(signum: i32, act: *const u8, oldact: *mut u8) -> i32 {
    let ret = syscall!(SYS_SIGACTION, signum, act, oldact);
    syscall_ret(ret) as i32
}

/// Send a signal to a process.
#[no_mangle]
pub unsafe extern "C" fn kill(pid: i32, sig: i32) -> i32 {
    let ret = syscall!(SYS_KILL, pid, sig);
    syscall_ret(ret) as i32
}
