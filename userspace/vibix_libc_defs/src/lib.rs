//! `vibix_libc_defs` -- type definitions and constants for vibix matching the
//! Linux x86_64 ABI layout.
//!
//! This crate provides the struct layouts, type aliases, and constants that
//! the upstream `libc` and `nix` crates expect. All definitions match the
//! Linux x86_64 layout that vibix uses for its syscall ABI.

#![no_std]
#![allow(non_camel_case_types)]

// ============================================================================
// Primitive type aliases (Linux x86_64)
// ============================================================================

pub type c_char = i8;
pub type c_short = i16;
pub type c_int = i32;
pub type c_long = i64;
pub type c_longlong = i64;
pub type c_uchar = u8;
pub type c_ushort = u16;
pub type c_uint = u32;
pub type c_ulong = u64;
pub type c_ulonglong = u64;
pub type c_void = core::ffi::c_void;

pub type size_t = u64;
pub type ssize_t = i64;
pub type off_t = i64;
pub type pid_t = i32;
pub type uid_t = u32;
pub type gid_t = u32;
pub type mode_t = u32;
pub type dev_t = u64;
pub type ino_t = u64;
pub type nlink_t = u64;
pub type blksize_t = i64;
pub type blkcnt_t = i64;
pub type time_t = i64;
pub type suseconds_t = i64;
pub type clockid_t = i32;
pub type sighandler_t = size_t;

// ============================================================================
// struct stat (Linux x86_64 layout, 144 bytes)
// ============================================================================

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct stat {
    pub st_dev: dev_t,
    pub st_ino: ino_t,
    pub st_nlink: nlink_t,
    pub st_mode: mode_t,
    pub st_uid: uid_t,
    pub st_gid: gid_t,
    pub __pad0: c_int,
    pub st_rdev: dev_t,
    pub st_size: off_t,
    pub st_blksize: blksize_t,
    pub st_blocks: blkcnt_t,
    pub st_atime: time_t,
    pub st_atime_nsec: c_long,
    pub st_mtime: time_t,
    pub st_mtime_nsec: c_long,
    pub st_ctime: time_t,
    pub st_ctime_nsec: c_long,
    pub __unused: [c_long; 3],
}

// ============================================================================
// struct timespec
// ============================================================================

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct timespec {
    pub tv_sec: time_t,
    pub tv_nsec: c_long,
}

// ============================================================================
// struct timeval
// ============================================================================

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct timeval {
    pub tv_sec: time_t,
    pub tv_usec: suseconds_t,
}

// ============================================================================
// struct sigaction (Linux x86_64)
// ============================================================================

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sigaction {
    pub sa_handler: sighandler_t,
    pub sa_flags: c_ulong,
    pub sa_restorer: Option<extern "C" fn()>,
    pub sa_mask: sigset_t,
}

pub type sigset_t = c_ulong;

// ============================================================================
// struct dirent (getdents64 layout)
// ============================================================================

#[repr(C)]
#[derive(Copy, Clone)]
pub struct dirent64 {
    pub d_ino: ino_t,
    pub d_off: off_t,
    pub d_reclen: c_ushort,
    pub d_type: c_uchar,
    pub d_name: [c_char; 256],
}

// ============================================================================
// struct utsname
// ============================================================================

#[repr(C)]
#[derive(Copy, Clone)]
pub struct utsname {
    pub sysname: [c_char; 65],
    pub nodename: [c_char; 65],
    pub release: [c_char; 65],
    pub version: [c_char; 65],
    pub machine: [c_char; 65],
    pub domainname: [c_char; 65],
}

// ============================================================================
// struct iovec
// ============================================================================

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct iovec {
    pub iov_base: *mut c_void,
    pub iov_len: size_t,
}

// ============================================================================
// Open flags (Linux x86_64)
// ============================================================================

pub const O_RDONLY: c_int = 0o0;
pub const O_WRONLY: c_int = 0o1;
pub const O_RDWR: c_int = 0o2;
pub const O_CREAT: c_int = 0o100;
pub const O_EXCL: c_int = 0o200;
pub const O_NOCTTY: c_int = 0o400;
pub const O_TRUNC: c_int = 0o1000;
pub const O_APPEND: c_int = 0o2000;
pub const O_NONBLOCK: c_int = 0o4000;
pub const O_DSYNC: c_int = 0o10000;
pub const O_DIRECTORY: c_int = 0o200000;
pub const O_NOFOLLOW: c_int = 0o400000;
pub const O_CLOEXEC: c_int = 0o2000000;

pub const AT_FDCWD: c_int = -100;

// ============================================================================
// File mode bits
// ============================================================================

pub const S_IFMT: mode_t = 0o170000;
pub const S_IFSOCK: mode_t = 0o140000;
pub const S_IFLNK: mode_t = 0o120000;
pub const S_IFREG: mode_t = 0o100000;
pub const S_IFBLK: mode_t = 0o060000;
pub const S_IFDIR: mode_t = 0o040000;
pub const S_IFCHR: mode_t = 0o020000;
pub const S_IFIFO: mode_t = 0o010000;

pub const S_ISUID: mode_t = 0o4000;
pub const S_ISGID: mode_t = 0o2000;
pub const S_ISVTX: mode_t = 0o1000;

pub const S_IRWXU: mode_t = 0o700;
pub const S_IRUSR: mode_t = 0o400;
pub const S_IWUSR: mode_t = 0o200;
pub const S_IXUSR: mode_t = 0o100;

pub const S_IRWXG: mode_t = 0o070;
pub const S_IRGRP: mode_t = 0o040;
pub const S_IWGRP: mode_t = 0o020;
pub const S_IXGRP: mode_t = 0o010;

pub const S_IRWXO: mode_t = 0o007;
pub const S_IROTH: mode_t = 0o004;
pub const S_IWOTH: mode_t = 0o002;
pub const S_IXOTH: mode_t = 0o001;

// ============================================================================
// Errno constants
// ============================================================================

pub const EPERM: c_int = 1;
pub const ENOENT: c_int = 2;
pub const ESRCH: c_int = 3;
pub const EINTR: c_int = 4;
pub const EIO: c_int = 5;
pub const ENXIO: c_int = 6;
pub const E2BIG: c_int = 7;
pub const ENOEXEC: c_int = 8;
pub const EBADF: c_int = 9;
pub const ECHILD: c_int = 10;
pub const EAGAIN: c_int = 11;
pub const ENOMEM: c_int = 12;
pub const EACCES: c_int = 13;
pub const EFAULT: c_int = 14;
pub const ENOTBLK: c_int = 15;
pub const EBUSY: c_int = 16;
pub const EEXIST: c_int = 17;
pub const EXDEV: c_int = 18;
pub const ENODEV: c_int = 19;
pub const ENOTDIR: c_int = 20;
pub const EISDIR: c_int = 21;
pub const EINVAL: c_int = 22;
pub const ENFILE: c_int = 23;
pub const EMFILE: c_int = 24;
pub const ENOTTY: c_int = 25;
pub const ETXTBSY: c_int = 26;
pub const EFBIG: c_int = 27;
pub const ENOSPC: c_int = 28;
pub const ESPIPE: c_int = 29;
pub const EROFS: c_int = 30;
pub const EMLINK: c_int = 31;
pub const EPIPE: c_int = 32;
pub const EDOM: c_int = 33;
pub const ERANGE: c_int = 34;
pub const ENOSYS: c_int = 38;
pub const ENOTEMPTY: c_int = 39;
pub const ELOOP: c_int = 40;
pub const ENAMETOOLONG: c_int = 36;

// ============================================================================
// Syscall numbers (Linux x86_64)
// ============================================================================

pub const SYS_READ: u64 = 0;
pub const SYS_WRITE: u64 = 1;
pub const SYS_OPEN: u64 = 2;
pub const SYS_CLOSE: u64 = 3;
pub const SYS_STAT: u64 = 4;
pub const SYS_FSTAT: u64 = 5;
pub const SYS_LSTAT: u64 = 6;
pub const SYS_LSEEK: u64 = 8;
pub const SYS_MMAP: u64 = 9;
pub const SYS_MPROTECT: u64 = 10;
pub const SYS_MUNMAP: u64 = 11;
pub const SYS_IOCTL: u64 = 16;
pub const SYS_ACCESS: u64 = 21;
pub const SYS_DUP: u64 = 32;
pub const SYS_DUP2: u64 = 33;
pub const SYS_FORK: u64 = 57;
pub const SYS_EXECVE: u64 = 59;
pub const SYS_EXIT: u64 = 60;
pub const SYS_WAIT4: u64 = 61;
pub const SYS_KILL: u64 = 62;
pub const SYS_UNAME: u64 = 63;
pub const SYS_FCNTL: u64 = 72;
pub const SYS_GETCWD: u64 = 79;
pub const SYS_CHDIR: u64 = 80;
pub const SYS_RENAME: u64 = 82;
pub const SYS_MKDIR: u64 = 83;
pub const SYS_RMDIR: u64 = 84;
pub const SYS_LINK: u64 = 86;
pub const SYS_UNLINK: u64 = 87;
pub const SYS_SYMLINK: u64 = 88;
pub const SYS_READLINK: u64 = 89;
pub const SYS_CHMOD: u64 = 90;
pub const SYS_FCHMOD: u64 = 91;
pub const SYS_CHOWN: u64 = 92;
pub const SYS_FCHOWN: u64 = 93;
pub const SYS_LCHOWN: u64 = 94;
pub const SYS_GETUID: u64 = 102;
pub const SYS_GETGID: u64 = 104;
pub const SYS_GETEUID: u64 = 107;
pub const SYS_GETEGID: u64 = 108;
pub const SYS_OPENAT: u64 = 257;
pub const SYS_MKDIRAT: u64 = 258;
pub const SYS_NEWFSTATAT: u64 = 262;
pub const SYS_UNLINKAT: u64 = 263;
pub const SYS_RENAMEAT: u64 = 264;
pub const SYS_LINKAT: u64 = 265;
pub const SYS_SYMLINKAT: u64 = 266;
pub const SYS_READLINKAT: u64 = 267;
pub const SYS_FCHMODAT: u64 = 268;

// ============================================================================
// dirent d_type constants
// ============================================================================

pub const DT_UNKNOWN: c_uchar = 0;
pub const DT_FIFO: c_uchar = 1;
pub const DT_CHR: c_uchar = 2;
pub const DT_DIR: c_uchar = 4;
pub const DT_BLK: c_uchar = 6;
pub const DT_REG: c_uchar = 8;
pub const DT_LNK: c_uchar = 10;
pub const DT_SOCK: c_uchar = 12;

// ============================================================================
// Clock IDs
// ============================================================================

pub const CLOCK_REALTIME: clockid_t = 0;
pub const CLOCK_MONOTONIC: clockid_t = 1;
pub const CLOCK_PROCESS_CPUTIME_ID: clockid_t = 2;
pub const CLOCK_THREAD_CPUTIME_ID: clockid_t = 3;

// ============================================================================
// Helper macros for file type checks
// ============================================================================

#[inline]
pub const fn s_isreg(mode: mode_t) -> bool {
    (mode & S_IFMT) == S_IFREG
}

#[inline]
pub const fn s_isdir(mode: mode_t) -> bool {
    (mode & S_IFMT) == S_IFDIR
}

#[inline]
pub const fn s_islnk(mode: mode_t) -> bool {
    (mode & S_IFMT) == S_IFLNK
}

#[inline]
pub const fn s_ischr(mode: mode_t) -> bool {
    (mode & S_IFMT) == S_IFCHR
}

#[inline]
pub const fn s_isblk(mode: mode_t) -> bool {
    (mode & S_IFMT) == S_IFBLK
}

#[inline]
pub const fn s_isfifo(mode: mode_t) -> bool {
    (mode & S_IFMT) == S_IFIFO
}

#[inline]
pub const fn s_issock(mode: mode_t) -> bool {
    (mode & S_IFMT) == S_IFSOCK
}
