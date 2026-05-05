//! `vibix_abi` -- the Rust ABI bridge between std's platform abstraction layer
//! and vibix syscalls.
//!
//! This crate provides the syscall macro, memory allocator, errno TLS, and
//! stdio wrappers that the std PAL calls into.

#![no_std]
#![feature(thread_local)]

pub mod alloc;
pub mod errno;
pub mod fs;
pub mod process;
pub mod stdio;
pub mod syscall;
