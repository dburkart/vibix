//! POSIX type aliases pinned to the Linux x86_64 syscall ABI.
//!
//! These aliases are the single source of truth for the width and
//! signedness of every scalar that crosses the kernel/userspace syscall
//! boundary. The VFS syscalls (`stat`, `openat`, `mknod`, `chmod`,
//! `chown`, `fchmodat`, `fchownat`) all touch `mode_t`, `dev_t`, and
//! the time fields — if a definition drifts, `struct stat` silently
//! becomes incompatible with any musl or glibc binary compiled against
//! `<sys/stat.h>`.
//!
//! The widths here match `arch/x86/include/uapi/asm/posix_types_64.h`
//! and `include/uapi/asm-generic/posix_types.h` in the Linux source.
//! They are **not** what POSIX itself specifies (POSIX only nails down
//! signedness, not width) — they are what Linux x86_64 has settled on
//! and what every userspace toolchain therefore assumes.
//!
//! Addresses reviewer US-A1 on RFC 0002.

// The Stat layout in the RFC is written with raw u32/u64/i64 literals.
// Anywhere that layout is implemented, prefer these aliases instead so a
// future widening (e.g. moving off_t to i64 on a 32-bit port) only has
// to touch this file.

/// File mode + permission bits (`S_IFMT | S_IRWXU | ...`).
///
/// Linux x86_64: `unsigned int` — 32 bits. Userspace `<sys/types.h>`
/// defines `mode_t` as `__mode_t`, which comes from
/// `<bits/types.h>` as `__U32_TYPE` on Linux glibc.
pub type mode_t = u32;

/// Device identifier (`st_dev`, `st_rdev`, `mknod(path, mode, dev)`).
///
/// Linux x86_64: `unsigned long` — 64 bits. Encoded as
/// `MKDEV(major, minor)` with 12-bit major and 20-bit minor, though
/// glibc exposes a larger 32/32 split via `gnu_dev_major`/`gnu_dev_minor`.
pub type dev_t = u64;

/// User identifier.
///
/// Linux x86_64: `unsigned int` — 32 bits. (Linux narrowed to 16 bits
/// historically but moved to 32 bits in 2.4 with the `_new` syscall
/// variants; the 64-bit ABI was born with 32-bit uids.)
pub type uid_t = u32;

/// Group identifier. Same width/signedness rationale as `uid_t`.
pub type gid_t = u32;

/// Signed file offset (`lseek`, `st_size`, `pread/pwrite`).
///
/// Linux x86_64: `long` — 64 bits signed. Negative values are used by
/// `lseek` to return errors, so the type must be signed. 32-bit Linux
/// uses `off_t = long = 32-bit` with a parallel `off64_t`; on x86_64
/// they coincide.
pub type off_t = i64;

/// Inode number (`st_ino`, `d_ino`).
///
/// Linux x86_64: `unsigned long` — 64 bits. 32-bit ABIs also expose an
/// `ino64_t` alias for filesystems that exceed 32-bit inode space.
pub type ino_t = u64;

/// Hard-link count (`st_nlink`).
///
/// Linux x86_64: `unsigned long` — 64 bits. POSIX only requires an
/// unsigned integer type; most BSDs use `u32`. Linux x86_64 picked 64
/// bits so aligning the `struct stat` field layout doesn't need padding.
pub type nlink_t = u64;

/// Filesystem "natural" I/O block size (`st_blksize`).
///
/// Linux x86_64: `long` — 64 bits signed. Signed because `statvfs` and
/// some legacy interfaces share this type with error-returning calls.
pub type blksize_t = i64;

/// 512-byte block count (`st_blocks`).
///
/// Linux x86_64: `long` — 64 bits signed. Holds the number of 512-byte
/// units actually allocated, which can differ from `st_size / 512` for
/// sparse files.
pub type blkcnt_t = i64;

/// Seconds since the Unix epoch (`st_atime`, `st_mtime`, `st_ctime`,
/// `time()`, `clock_gettime`).
///
/// Linux x86_64: `long` — 64 bits signed. Signed because pre-epoch
/// timestamps are representable; 64 bits sidesteps the Y2038 problem.
pub type time_t = i64;

// Compile-time pins so a drift in the alias type fails the build. Each
// assert compares the width (`size_of`) of the alias against the target
// Linux type on x86_64, so a later accidental edit to `mode_t = u16`
// (or similar) cannot silently change the ABI.
const _: () = assert!(core::mem::size_of::<mode_t>() == 4);
const _: () = assert!(core::mem::size_of::<dev_t>() == 8);
const _: () = assert!(core::mem::size_of::<uid_t>() == 4);
const _: () = assert!(core::mem::size_of::<gid_t>() == 4);
const _: () = assert!(core::mem::size_of::<off_t>() == 8);
const _: () = assert!(core::mem::size_of::<ino_t>() == 8);
const _: () = assert!(core::mem::size_of::<nlink_t>() == 8);
const _: () = assert!(core::mem::size_of::<blksize_t>() == 8);
const _: () = assert!(core::mem::size_of::<blkcnt_t>() == 8);
const _: () = assert!(core::mem::size_of::<time_t>() == 8);

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};

    /// Byte-widths match Linux x86_64 `<bits/types.h>` /
    /// `<asm/posix_types_64.h>`.
    #[test]
    fn widths_match_linux_x86_64() {
        assert_eq!(size_of::<mode_t>(), 4);
        assert_eq!(size_of::<dev_t>(), 8);
        assert_eq!(size_of::<uid_t>(), 4);
        assert_eq!(size_of::<gid_t>(), 4);
        assert_eq!(size_of::<off_t>(), 8);
        assert_eq!(size_of::<ino_t>(), 8);
        assert_eq!(size_of::<nlink_t>(), 8);
        assert_eq!(size_of::<blksize_t>(), 8);
        assert_eq!(size_of::<blkcnt_t>(), 8);
        assert_eq!(size_of::<time_t>(), 8);
    }

    /// Alignments match the widths; every type is naturally aligned so
    /// embedding them in a `#[repr(C)]` struct (like `Stat`) doesn't
    /// introduce surprise padding.
    #[test]
    fn alignments_are_natural() {
        assert_eq!(align_of::<mode_t>(), 4);
        assert_eq!(align_of::<dev_t>(), 8);
        assert_eq!(align_of::<uid_t>(), 4);
        assert_eq!(align_of::<gid_t>(), 4);
        assert_eq!(align_of::<off_t>(), 8);
        assert_eq!(align_of::<ino_t>(), 8);
        assert_eq!(align_of::<nlink_t>(), 8);
        assert_eq!(align_of::<blksize_t>(), 8);
        assert_eq!(align_of::<blkcnt_t>(), 8);
        assert_eq!(align_of::<time_t>(), 8);
    }

    /// Signedness is load-bearing for off_t/blksize_t/blkcnt_t/time_t
    /// because several syscalls return negative values through these
    /// types to signal errors or pre-epoch timestamps.
    #[test]
    fn signedness_is_load_bearing() {
        // Unsigned types have MIN == 0.
        assert_eq!(mode_t::MIN, 0);
        assert_eq!(dev_t::MIN, 0);
        assert_eq!(uid_t::MIN, 0);
        assert_eq!(gid_t::MIN, 0);
        assert_eq!(ino_t::MIN, 0);
        assert_eq!(nlink_t::MIN, 0);
        // Signed types have MIN < 0.
        assert!(off_t::MIN < 0);
        assert!(blksize_t::MIN < 0);
        assert!(blkcnt_t::MIN < 0);
        assert!(time_t::MIN < 0);
    }
}
