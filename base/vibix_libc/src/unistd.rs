//! Unix-style operations: read, write, close, link, unlink, symlink, readlink,
//! mkdir, rmdir, rename, getcwd, chdir, fork, dup, dup2, pipe, access,
//! setpgid, wait4.

use crate::helpers::syscall_ret;
use vibix_abi::syscall;

// Syscall numbers (Linux x86_64)
const SYS_READ: u64 = 0;
const SYS_WRITE: u64 = 1;
const SYS_CLOSE: u64 = 3;
const SYS_ACCESS: u64 = 21;
const SYS_PIPE: u64 = 22;
const SYS_DUP: u64 = 32;
const SYS_DUP2: u64 = 33;
const SYS_FORK: u64 = 57;
const SYS_WAIT4: u64 = 61;
const SYS_GETCWD: u64 = 79;
const SYS_CHDIR: u64 = 80;
const SYS_RENAME: u64 = 82;
const SYS_MKDIR: u64 = 83;
const SYS_RMDIR: u64 = 84;
const SYS_LINK: u64 = 86;
const SYS_UNLINK: u64 = 87;
const SYS_SYMLINK: u64 = 88;
const SYS_READLINK: u64 = 89;
const SYS_SETPGID: u64 = 109;

/// Read from a file descriptor.
///
/// # Safety
/// `buf` must be a valid pointer to a buffer of at least `count` bytes.
#[no_mangle]
pub unsafe extern "C" fn read(fd: i32, buf: *mut u8, count: usize) -> isize {
    let ret = syscall!(SYS_READ, fd, buf, count);
    syscall_ret(ret) as isize
}

/// Write to a file descriptor.
///
/// # Safety
/// `buf` must be a valid pointer to a buffer of at least `count` bytes.
#[no_mangle]
pub unsafe extern "C" fn write(fd: i32, buf: *const u8, count: usize) -> isize {
    let ret = syscall!(SYS_WRITE, fd, buf, count);
    syscall_ret(ret) as isize
}

/// Close a file descriptor.
#[no_mangle]
pub unsafe extern "C" fn close(fd: i32) -> i32 {
    let ret = syscall!(SYS_CLOSE, fd);
    syscall_ret(ret) as i32
}

/// Create a hard link.
///
/// # Safety
/// Both path pointers must be valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn link(oldpath: *const u8, newpath: *const u8) -> i32 {
    let ret = syscall!(SYS_LINK, oldpath, newpath);
    syscall_ret(ret) as i32
}

/// Remove a file (unlink).
///
/// # Safety
/// `pathname` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn unlink(pathname: *const u8) -> i32 {
    let ret = syscall!(SYS_UNLINK, pathname);
    syscall_ret(ret) as i32
}

/// Create a symbolic link.
///
/// # Safety
/// Both path pointers must be valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn symlink(target: *const u8, linkpath: *const u8) -> i32 {
    let ret = syscall!(SYS_SYMLINK, target, linkpath);
    syscall_ret(ret) as i32
}

/// Read the target of a symbolic link.
///
/// # Safety
/// `pathname` must be a valid null-terminated C string; `buf` must point to
/// a buffer of at least `bufsiz` bytes.
#[no_mangle]
pub unsafe extern "C" fn readlink(pathname: *const u8, buf: *mut u8, bufsiz: usize) -> isize {
    let ret = syscall!(SYS_READLINK, pathname, buf, bufsiz);
    syscall_ret(ret) as isize
}

/// Create a directory.
///
/// # Safety
/// `pathname` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn mkdir(pathname: *const u8, mode: u32) -> i32 {
    let ret = syscall!(SYS_MKDIR, pathname, mode);
    syscall_ret(ret) as i32
}

/// Remove a directory.
///
/// # Safety
/// `pathname` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn rmdir(pathname: *const u8) -> i32 {
    let ret = syscall!(SYS_RMDIR, pathname);
    syscall_ret(ret) as i32
}

/// Rename a file.
///
/// # Safety
/// Both path pointers must be valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn rename(oldpath: *const u8, newpath: *const u8) -> i32 {
    let ret = syscall!(SYS_RENAME, oldpath, newpath);
    syscall_ret(ret) as i32
}

/// Get current working directory.
///
/// # Safety
/// `buf` must point to a buffer of at least `size` bytes.
#[no_mangle]
pub unsafe extern "C" fn getcwd(buf: *mut u8, size: usize) -> *mut u8 {
    let ret = syscall!(SYS_GETCWD, buf, size);
    if ret < 0 {
        vibix_abi::errno::ERRNO.set((-ret) as i32);
        core::ptr::null_mut()
    } else {
        buf
    }
}

/// Change working directory.
///
/// # Safety
/// `path` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn chdir(path: *const u8) -> i32 {
    let ret = syscall!(SYS_CHDIR, path);
    syscall_ret(ret) as i32
}

/// Fork the current process.
///
/// Returns 0 to the child, child PID to the parent, or -1 on error.
#[no_mangle]
pub unsafe extern "C" fn fork() -> i32 {
    let ret = syscall!(SYS_FORK);
    syscall_ret(ret) as i32
}

/// Duplicate a file descriptor.
#[no_mangle]
pub unsafe extern "C" fn dup(oldfd: i32) -> i32 {
    let ret = syscall!(SYS_DUP, oldfd);
    syscall_ret(ret) as i32
}

/// Duplicate a file descriptor to a specific number.
#[no_mangle]
pub unsafe extern "C" fn dup2(oldfd: i32, newfd: i32) -> i32 {
    let ret = syscall!(SYS_DUP2, oldfd, newfd);
    syscall_ret(ret) as i32
}

/// Create a pipe.
///
/// # Safety
/// `pipefd` must point to an array of two `i32` values.
#[no_mangle]
pub unsafe extern "C" fn pipe(pipefd: *mut i32) -> i32 {
    let ret = syscall!(SYS_PIPE, pipefd);
    syscall_ret(ret) as i32
}

/// Check file accessibility.
///
/// # Safety
/// `pathname` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn access(pathname: *const u8, mode: i32) -> i32 {
    let ret = syscall!(SYS_ACCESS, pathname, mode);
    syscall_ret(ret) as i32
}

/// Set process group ID.
#[no_mangle]
pub unsafe extern "C" fn setpgid(pid: i32, pgid: i32) -> i32 {
    let ret = syscall!(SYS_SETPGID, pid, pgid);
    syscall_ret(ret) as i32
}

/// Wait for a child process.
///
/// # Safety
/// `wstatus` must be a valid pointer to an `i32` (or null).
/// `rusage` must be a valid pointer or null.
#[no_mangle]
pub unsafe extern "C" fn wait4(pid: i32, wstatus: *mut i32, options: i32, rusage: *mut u8) -> i32 {
    let ret = syscall!(SYS_WAIT4, pid, wstatus, options, rusage);
    syscall_ret(ret) as i32
}
