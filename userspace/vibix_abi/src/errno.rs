//! Thread-local errno storage.
//!
//! Each task gets its own `ERRNO` cell via TLS (epic #827). The kernel
//! allocates a fresh TLS block per task and sets `MSR_FS_BASE` to the TCB
//! pointer, so the compiler's `%fs:`-relative accesses work out of the box.

use core::cell::Cell;

/// Per-thread errno value.  Syscall wrappers store the positive error code
/// here when a raw syscall returns a negative value.
#[thread_local]
pub static ERRNO: Cell<i32> = Cell::new(0);

/// C-ABI-compatible accessor for errno's address.  This is what the libc
/// crate's `__errno_location` resolves to.
#[no_mangle]
pub extern "C" fn __errno_location() -> *mut i32 {
    ERRNO.as_ptr()
}
