//! Internal helpers for converting syscall return values to C-style returns.

use vibix_abi::errno::ERRNO;

/// Convert a raw syscall return (negative = -errno) into C return convention:
/// on success returns the non-negative value; on error sets ERRNO and returns -1.
#[inline]
pub(crate) fn syscall_ret(ret: i64) -> i64 {
    if ret < 0 {
        ERRNO.set((-ret) as i32);
        -1
    } else {
        ret
    }
}
