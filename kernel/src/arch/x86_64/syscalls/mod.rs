//! Grouped syscall implementations called from `syscall::syscall_dispatch`.
//!
//! Kept separate so that each subsystem (VFS, in the future: time, IPC, …)
//! lives in its own file and syscall.rs can stay focused on the trampoline
//! and register plumbing.

pub mod vfs;
