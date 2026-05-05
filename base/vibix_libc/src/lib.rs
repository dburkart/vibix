//! `vibix_libc` -- C-ABI shim that exposes POSIX-like symbols backed by
//! vibix_abi syscall wrappers.
//!
//! Each `#[no_mangle] pub unsafe extern "C" fn` delegates to the raw syscall
//! via `vibix_abi::syscall!()`. On error, the function sets errno and returns
//! -1 (matching POSIX semantics).

#![no_std]

// The `syscall!` macro is used in submodules via `vibix_abi::syscall!`.

pub use vibix_abi::errno::ERRNO;

mod helpers;

pub mod errno;
pub mod fcntl;
pub mod stat;
pub mod unistd;

/// Re-export the defs crate types for convenience.
pub use vibix_abi;

/// Panic handler for the cdylib build. When vibix_libc is linked as a
/// shared library (cdylib), it needs its own panic handler. When linked
/// as an rlib into a binary, the binary provides the panic handler instead.
/// The `panic_handler` cfg is set by the build system when targeting cdylib.
#[cfg(all(not(test), feature = "panic-handler"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Abort via exit(134) — SIGABRT-like exit code.
    unsafe { vibix_abi::syscall!(60, 134) };
    loop {
        core::hint::spin_loop();
    }
}
