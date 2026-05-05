//! Filesystem syscall wrappers for vibix.
//!
//! These provide safe-ish wrappers around the raw syscall interface for use by
//! std's filesystem implementation.

use crate::syscall;

// Syscall numbers (Linux x86_64 ABI).
const SYS_READ: u64 = 0;
const SYS_WRITE: u64 = 1;
const SYS_CLOSE: u64 = 3;
const SYS_STAT: u64 = 4;
const SYS_FSTAT: u64 = 5;
const SYS_LSTAT: u64 = 6;
const SYS_LSEEK: u64 = 8;
const SYS_IOCTL: u64 = 16;
const SYS_ACCESS: u64 = 21;
const SYS_DUP: u64 = 32;
const SYS_FCNTL: u64 = 72;
const SYS_FSYNC: u64 = 74;
const SYS_FTRUNCATE: u64 = 77;
const SYS_GETCWD: u64 = 79;
const SYS_CHDIR: u64 = 80;
const SYS_MKDIR: u64 = 83;
const SYS_RMDIR: u64 = 84;
const SYS_LINK: u64 = 86;
const SYS_UNLINK: u64 = 87;
const SYS_SYMLINK: u64 = 88;
const SYS_READLINK: u64 = 89;
const SYS_CHMOD: u64 = 90;
const SYS_FCHMOD: u64 = 91;
const SYS_CHOWN: u64 = 92;
const SYS_FCHOWN: u64 = 93;
const SYS_LCHOWN: u64 = 94;
const SYS_RENAME: u64 = 82;
const SYS_GETDENTS64: u64 = 217;
const SYS_OPENAT: u64 = 257;
const SYS_UTIMENSAT: u64 = 280;

// Open flags (Linux x86_64).
pub const O_RDONLY: i32 = 0;
pub const O_WRONLY: i32 = 1;
pub const O_RDWR: i32 = 2;
pub const O_CREAT: i32 = 0o100;
pub const O_EXCL: i32 = 0o200;
pub const O_TRUNC: i32 = 0o1000;
pub const O_APPEND: i32 = 0o2000;
pub const O_DIRECTORY: i32 = 0o200000;
pub const O_NOFOLLOW: i32 = 0o400000;
pub const O_CLOEXEC: i32 = 0o2000000;

// lseek whence values.
pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;

// AT_* constants.
pub const AT_FDCWD: i32 = -100;
pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;

// fcntl commands.
pub const F_DUPFD_CLOEXEC: i32 = 1030;

// Stat mode flags.
pub const S_IFMT: u32 = 0o170000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFBLK: u32 = 0o060000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFIFO: u32 = 0o010000;
pub const S_IFSOCK: u32 = 0o140000;

// d_type values for dirents.
pub const DT_UNKNOWN: u8 = 0;
pub const DT_DIR: u8 = 4;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;

/// Linux x86_64 stat structure.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub __pad0: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
    pub __unused: [i64; 3],
}

/// Linux dirent64 structure (variable-length).
#[repr(C)]
pub struct Dirent64 {
    pub d_ino: u64,
    pub d_off: i64,
    pub d_reclen: u16,
    pub d_type: u8,
    pub d_name: [u8; 0], // flexible array member
}

/// Timespec for utimensat.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

pub const UTIME_NOW: i64 = (1 << 30) - 1;
pub const UTIME_OMIT: i64 = (1 << 30) - 2;

/// Open a file relative to a directory fd.
#[inline]
pub unsafe fn openat(dirfd: i32, path: *const u8, flags: i32, mode: u32) -> i64 {
    syscall::syscall4(SYS_OPENAT, dirfd as u64, path as u64, flags as u64, mode as u64)
}

/// Read from a file descriptor.
#[inline]
pub unsafe fn read(fd: i32, buf: *mut u8, count: usize) -> i64 {
    syscall::syscall3(SYS_READ, fd as u64, buf as u64, count as u64)
}

/// Write to a file descriptor.
#[inline]
pub unsafe fn write(fd: i32, buf: *const u8, count: usize) -> i64 {
    syscall::syscall3(SYS_WRITE, fd as u64, buf as u64, count as u64)
}

/// Close a file descriptor.
#[inline]
pub unsafe fn close(fd: i32) -> i64 {
    syscall::syscall1(SYS_CLOSE, fd as u64)
}

/// Get file status.
#[inline]
pub unsafe fn fstat(fd: i32, statbuf: *mut Stat) -> i64 {
    syscall::syscall2(SYS_FSTAT, fd as u64, statbuf as u64)
}

/// Get file status by path.
#[inline]
pub unsafe fn stat(path: *const u8, statbuf: *mut Stat) -> i64 {
    syscall::syscall2(SYS_STAT, path as u64, statbuf as u64)
}

/// Get symbolic link status.
#[inline]
pub unsafe fn lstat(path: *const u8, statbuf: *mut Stat) -> i64 {
    syscall::syscall2(SYS_LSTAT, path as u64, statbuf as u64)
}

/// Reposition file offset.
#[inline]
pub unsafe fn lseek(fd: i32, offset: i64, whence: i32) -> i64 {
    syscall::syscall3(SYS_LSEEK, fd as u64, offset as u64, whence as u64)
}

/// Read directory entries.
#[inline]
pub unsafe fn getdents64(fd: i32, buf: *mut u8, count: usize) -> i64 {
    syscall::syscall3(SYS_GETDENTS64, fd as u64, buf as u64, count as u64)
}

/// Remove a file.
#[inline]
pub unsafe fn unlink(path: *const u8) -> i64 {
    syscall::syscall1(SYS_UNLINK, path as u64)
}

/// Create a directory.
#[inline]
pub unsafe fn mkdir(path: *const u8, mode: u32) -> i64 {
    syscall::syscall2(SYS_MKDIR, path as u64, mode as u64)
}

/// Remove a directory.
#[inline]
pub unsafe fn rmdir(path: *const u8) -> i64 {
    syscall::syscall1(SYS_RMDIR, path as u64)
}

/// Rename a file.
#[inline]
pub unsafe fn rename(old: *const u8, new: *const u8) -> i64 {
    syscall::syscall2(SYS_RENAME, old as u64, new as u64)
}

/// Create a hard link.
#[inline]
pub unsafe fn link(old: *const u8, new: *const u8) -> i64 {
    syscall::syscall2(SYS_LINK, old as u64, new as u64)
}

/// Create a symbolic link.
#[inline]
pub unsafe fn symlink(target: *const u8, linkpath: *const u8) -> i64 {
    syscall::syscall2(SYS_SYMLINK, target as u64, linkpath as u64)
}

/// Read the target of a symbolic link.
#[inline]
pub unsafe fn readlink(path: *const u8, buf: *mut u8, bufsiz: usize) -> i64 {
    syscall::syscall3(SYS_READLINK, path as u64, buf as u64, bufsiz as u64)
}

/// Change file mode.
#[inline]
pub unsafe fn chmod(path: *const u8, mode: u32) -> i64 {
    syscall::syscall2(SYS_CHMOD, path as u64, mode as u64)
}

/// Change file mode by fd.
#[inline]
pub unsafe fn fchmod(fd: i32, mode: u32) -> i64 {
    syscall::syscall2(SYS_FCHMOD, fd as u64, mode as u64)
}

/// Change file owner.
#[inline]
pub unsafe fn chown(path: *const u8, uid: u32, gid: u32) -> i64 {
    syscall::syscall3(SYS_CHOWN, path as u64, uid as u64, gid as u64)
}

/// Change file owner by fd.
#[inline]
pub unsafe fn fchown(fd: i32, uid: u32, gid: u32) -> i64 {
    syscall::syscall3(SYS_FCHOWN, fd as u64, uid as u64, gid as u64)
}

/// Change file owner (no symlink follow).
#[inline]
pub unsafe fn lchown(path: *const u8, uid: u32, gid: u32) -> i64 {
    syscall::syscall3(SYS_LCHOWN, path as u64, uid as u64, gid as u64)
}

/// Change file timestamps.
#[inline]
pub unsafe fn utimensat(dirfd: i32, path: *const u8, times: *const Timespec, flags: i32) -> i64 {
    syscall::syscall4(SYS_UTIMENSAT, dirfd as u64, path as u64, times as u64, flags as u64)
}

/// Truncate a file by fd.
#[inline]
pub unsafe fn ftruncate(fd: i32, length: i64) -> i64 {
    syscall::syscall2(SYS_FTRUNCATE, fd as u64, length as u64)
}

/// Sync file to disk.
#[inline]
pub unsafe fn fsync(fd: i32) -> i64 {
    syscall::syscall1(SYS_FSYNC, fd as u64)
}

/// Duplicate a file descriptor.
#[inline]
pub unsafe fn dup(fd: i32) -> i64 {
    syscall::syscall1(SYS_DUP, fd as u64)
}

/// fcntl operations.
#[inline]
pub unsafe fn fcntl(fd: i32, cmd: i32, arg: u64) -> i64 {
    syscall::syscall3(SYS_FCNTL, fd as u64, cmd as u64, arg)
}

/// Check file access.
#[inline]
pub unsafe fn access(path: *const u8, mode: i32) -> i64 {
    syscall::syscall2(SYS_ACCESS, path as u64, mode as u64)
}

/// Get current working directory.
#[inline]
pub unsafe fn getcwd(buf: *mut u8, size: usize) -> i64 {
    syscall::syscall2(SYS_GETCWD, buf as u64, size as u64)
}

/// Change current directory.
#[inline]
pub unsafe fn chdir(path: *const u8) -> i64 {
    syscall::syscall1(SYS_CHDIR, path as u64)
}

/// ioctl.
#[inline]
pub unsafe fn ioctl(fd: i32, request: u64, arg: u64) -> i64 {
    syscall::syscall3(SYS_IOCTL, fd as u64, request, arg)
}
