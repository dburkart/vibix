//! Phase 2 syscalls for Rust std (RFC 0009, issue #853).
//!
//! Implements: rename(82), renameat(264), pread64(17), pwrite64(18),
//! nanosleep(35), uname(63).

use super::super::uaccess;
use super::vfs::{AT_FDCWD};

/// `rename(oldpath, newpath)` — rename a file or directory.
///
/// Thin wrapper over [`renameat_impl`] with both dirfds set to `AT_FDCWD`.
pub fn sys_rename(oldpath: usize, newpath: usize) -> i64 {
    renameat_impl(AT_FDCWD, oldpath, AT_FDCWD, newpath)
}

/// `renameat(olddfd, oldpath, newdfd, newpath)` — rename relative to dirfds.
pub fn sys_renameat(olddfd: i32, oldpath: usize, newdfd: i32, newpath: usize) -> i64 {
    renameat_impl(olddfd, oldpath, newdfd, newpath)
}

/// Shared rename implementation.
fn renameat_impl(olddfd: i32, oldpath_uva: usize, newdfd: i32, newpath_uva: usize) -> i64 {
    use crate::fs::{ENOTDIR, EXDEV};

    // Copy paths from user space.
    let old_buf = match copy_user_path(oldpath_uva as u64) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let new_buf = match copy_user_path(newpath_uva as u64) {
        Ok(b) => b,
        Err(e) => return e,
    };

    let old_path = old_buf.as_slice();
    let new_path = new_buf.as_slice();

    // Resolve start dentries for *at semantics.
    let old_start = match super::vfs::resolve_dirfd(olddfd) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let new_start = match super::vfs::resolve_dirfd(newdfd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // Split into parent + leaf for both paths.
    let (old_parent_path, old_leaf) = match super::vfs::split_parent(old_path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (new_parent_path, new_leaf) = match super::vfs::split_parent(new_path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // Resolve old parent directory.
    let walk_cred = (*crate::task::current_credentials()).clone();
    let (old_parent_inode, _old_pnd) =
        match super::vfs::resolve_inode_at(old_start, old_parent_path, true, walk_cred.clone()) {
            Ok(v) => v,
            Err(e) => return e,
        };
    if old_parent_inode.kind != crate::fs::vfs::InodeKind::Dir {
        return ENOTDIR;
    }

    // Resolve new parent directory.
    let (new_parent_inode, _new_pnd) =
        match super::vfs::resolve_inode_at(new_start, new_parent_path, true, walk_cred) {
            Ok(v) => v,
            Err(e) => return e,
        };
    if new_parent_inode.kind != crate::fs::vfs::InodeKind::Dir {
        return ENOTDIR;
    }

    // Cross-device check: both parents must be on the same superblock.
    // Upgrade both Weak<SuperBlock> and compare Arc identity.
    let old_sb = match old_parent_inode.sb.upgrade() {
        Some(s) => s,
        None => return EXDEV,
    };
    let new_sb = match new_parent_inode.sb.upgrade() {
        Some(s) => s,
        None => return EXDEV,
    };
    if !alloc::sync::Arc::ptr_eq(&old_sb, &new_sb) {
        return EXDEV;
    }

    // Delegate to InodeOps::rename on the old parent.
    match old_parent_inode
        .ops
        .rename(&old_parent_inode, old_leaf, &new_parent_inode, new_leaf)
    {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// `pread64(fd, buf, count, offset)` — read at offset without changing file position.
pub fn sys_pread64(fd: u32, buf_uva: usize, count: usize, offset: i64) -> i64 {
    use crate::fs::{EINVAL, ESPIPE};

    if offset < 0 {
        return EINVAL;
    }

    if count == 0 {
        return 0;
    }

    if let Err(e) = uaccess::check_user_range(buf_uva, count) {
        return e.as_errno();
    }

    // Get the backend.
    let backend = {
        let tbl = crate::task::current_fd_table();
        let x = match tbl.lock().get(fd) {
            Ok(b) => b,
            Err(e) => return e,
        };
        x
    };

    // pread requires a seekable fd — get the VfsBackend.
    let vfs = match backend.as_vfs() {
        Some(v) => v,
        None => return ESPIPE,
    };

    // Read at the specified offset without modifying the file position.
    let mut chunk = [0u8; 256];
    let mut total: usize = 0;
    let off = offset as u64;

    while total < count {
        let n = core::cmp::min(chunk.len(), count - total);
        match vfs.open_file.ops.read(&vfs.open_file, &mut chunk[..n], off + total as u64) {
            Ok(0) => break, // EOF
            Ok(nread) => {
                match unsafe { uaccess::copy_to_user(buf_uva + total, &chunk[..nread]) } {
                    Ok(()) => {}
                    Err(e) => return e.as_errno(),
                }
                total += nread;
                if nread < n {
                    break; // short read
                }
            }
            Err(e) => {
                if total > 0 {
                    return total as i64;
                }
                return e;
            }
        }
    }
    total as i64
}

/// `pwrite64(fd, buf, count, offset)` — write at offset without changing file position.
pub fn sys_pwrite64(fd: u32, buf_uva: usize, count: usize, offset: i64) -> i64 {
    use crate::fs::{EINVAL, ESPIPE};

    if offset < 0 {
        return EINVAL;
    }

    if count == 0 {
        return 0;
    }

    if let Err(e) = uaccess::check_user_range(buf_uva, count) {
        return e.as_errno();
    }

    // Get the backend.
    let backend = {
        let tbl = crate::task::current_fd_table();
        let x = match tbl.lock().get(fd) {
            Ok(b) => b,
            Err(e) => return e,
        };
        x
    };

    // pwrite requires a seekable fd — get the VfsBackend.
    let vfs = match backend.as_vfs() {
        Some(v) => v,
        None => return ESPIPE,
    };

    // Write at the specified offset without modifying the file position.
    let mut chunk = [0u8; 256];
    let mut total: usize = 0;
    let off = offset as u64;

    while total < count {
        let n = core::cmp::min(chunk.len(), count - total);
        match unsafe { uaccess::copy_from_user(&mut chunk[..n], buf_uva + total) } {
            Ok(()) => {}
            Err(e) => return e.as_errno(),
        }
        match vfs.open_file.ops.write(&vfs.open_file, &chunk[..n], off + total as u64) {
            Ok(0) => break,
            Ok(nw) => {
                total += nw;
                if nw < n {
                    break; // short write
                }
            }
            Err(e) => {
                if total > 0 {
                    return total as i64;
                }
                return e;
            }
        }
    }
    total as i64
}

/// `nanosleep(req, rem)` — sleep for the specified duration.
///
/// `req` points to a `struct timespec { tv_sec: i64, tv_nsec: i64 }`.
/// `rem` (if non-null) receives the remaining time if interrupted (currently
/// always zeroed since vibix does not support signal-based interruption of
/// nanosleep yet).
pub fn sys_nanosleep(req: usize, rem: usize) -> i64 {
    use crate::fs::EINVAL;

    // Validate and read the request timespec (16 bytes).
    if let Err(e) = uaccess::check_user_range(req, 16) {
        return e.as_errno();
    }

    let mut buf = [0u8; 16];
    match unsafe { uaccess::copy_from_user(&mut buf, req) } {
        Ok(()) => {}
        Err(e) => return e.as_errno(),
    }

    let tv_sec = i64::from_ne_bytes(buf[..8].try_into().unwrap());
    let tv_nsec = i64::from_ne_bytes(buf[8..].try_into().unwrap());

    // Validate per POSIX: sec >= 0, 0 <= nsec < 1_000_000_000.
    if tv_sec < 0 || tv_nsec < 0 || tv_nsec >= 1_000_000_000 {
        return EINVAL;
    }

    // Convert to milliseconds (rounding up so we never sleep shorter than asked).
    let total_ns = tv_sec as u64 * 1_000_000_000 + tv_nsec as u64;
    if total_ns == 0 {
        return 0;
    }
    let ms = total_ns.div_ceil(1_000_000);

    crate::task::sleep_ms(ms);

    // If `rem` is non-null, write zero remaining time (no signal interruption yet).
    if rem != 0 {
        if uaccess::check_user_range(rem, 16).is_ok() {
            let zero = [0u8; 16];
            let _ = unsafe { uaccess::copy_to_user(rem, &zero) };
        }
    }

    0
}

/// `uname(buf)` — fill a `struct utsname` with system identification.
///
/// The Linux `utsname` struct has 6 fields of 65 bytes each (including NUL):
///   sysname, nodename, release, version, machine, domainname
/// Total size: 6 * 65 = 390 bytes.
pub fn sys_uname(buf: usize) -> i64 {
    const FIELD_LEN: usize = 65;
    const UTSNAME_SIZE: usize = FIELD_LEN * 6;

    if let Err(e) = uaccess::check_user_range(buf, UTSNAME_SIZE) {
        return e.as_errno();
    }

    let mut utsname = [0u8; UTSNAME_SIZE];

    // sysname
    copy_field(&mut utsname[0..FIELD_LEN], b"Vibix");
    // nodename (hostname)
    copy_field(&mut utsname[FIELD_LEN..FIELD_LEN * 2], b"vibix");
    // release
    copy_field(
        &mut utsname[FIELD_LEN * 2..FIELD_LEN * 3],
        b"0.1.0",
    );
    // version
    copy_field(
        &mut utsname[FIELD_LEN * 3..FIELD_LEN * 4],
        b"#1 SMP",
    );
    // machine
    copy_field(
        &mut utsname[FIELD_LEN * 4..FIELD_LEN * 5],
        b"x86_64",
    );
    // domainname
    copy_field(&mut utsname[FIELD_LEN * 5..FIELD_LEN * 6], b"(none)");

    match unsafe { uaccess::copy_to_user(buf, &utsname) } {
        Ok(()) => 0,
        Err(e) => e.as_errno(),
    }
}

/// Copy a NUL-terminated field into a fixed-size buffer.
fn copy_field(dst: &mut [u8], src: &[u8]) {
    let len = core::cmp::min(src.len(), dst.len() - 1);
    dst[..len].copy_from_slice(&src[..len]);
    // Rest is already zeroed (NUL terminator included).
}

/// Copy a user path into a heap buffer (mirrors the helper in vfs.rs).
fn copy_user_path(path_uva: u64) -> Result<alloc::vec::Vec<u8>, i64> {
    use alloc::vec::Vec;
    use crate::fs::vfs::path_walk::PATH_MAX;
    use super::super::syscall::copy_path_from_user_pub;

    let mut buf: Vec<u8> = Vec::new();
    if buf.try_reserve_exact(PATH_MAX + 1).is_err() {
        return Err(crate::fs::ENOMEM);
    }
    buf.resize(PATH_MAX + 1, 0);
    let len = unsafe { copy_path_from_user_pub(path_uva as usize, &mut buf) }?;
    buf.truncate(len);
    Ok(buf)
}
