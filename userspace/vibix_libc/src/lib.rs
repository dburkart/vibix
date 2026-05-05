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
