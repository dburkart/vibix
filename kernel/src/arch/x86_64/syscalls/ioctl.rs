//! `sys_ioctl(fd, cmd, arg)` — device-specific control syscall.
//!
//! Looks up the backing fd in the current task's fd table, clones the
//! `Arc<dyn FileBackend>`, and dispatches to `FileBackend::ioctl`. Most
//! backends inherit the trait default and return `-ENOTTY`; the tty-like
//! [`SerialBackend`](crate::fs::SerialBackend) handles the TC* family.

/// Shared `ioctl` body. Called from the `IOCTL` arm of `syscall_dispatch`.
pub unsafe fn sys_ioctl(fd: u64, cmd: u32, arg: usize) -> i64 {
    let fd = fd as u32;
    let backend = {
        let tbl = crate::task::current_fd_table();
        let b = match tbl.lock().get(fd) {
            Ok(b) => b,
            Err(e) => return e,
        };
        b
    };
    match backend.ioctl(cmd, arg) {
        Ok(rc) => rc,
        Err(e) => e,
    }
}
