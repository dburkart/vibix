//! vibix-specific extensions to primitives in the [`std::fs`] module.
//!
//! vibix uses the same stat layout as Linux x86_64, so these extensions
//! are identical.
//!
//! [`std::fs`]: crate::fs

#![stable(feature = "metadata_ext", since = "1.1.0")]

use crate::fs::{Metadata, Permissions};
use crate::io;
#[allow(deprecated)]
use crate::os::vibix::raw;
use crate::path::Path;
use crate::sys::{AsInner, FromInner};

/// OS-specific extensions to [`fs::Metadata`].
///
/// [`fs::Metadata`]: crate::fs::Metadata
#[stable(feature = "metadata_ext", since = "1.1.0")]
pub trait MetadataExt {
    #[stable(feature = "metadata_ext", since = "1.1.0")]
    #[deprecated(since = "1.8.0", note = "other methods of this trait are now preferred")]
    #[allow(deprecated)]
    fn as_raw_stat(&self) -> &raw::stat;
    #[stable(feature = "metadata_ext2", since = "1.8.0")]
    fn st_dev(&self) -> u64;
    #[stable(feature = "metadata_ext2", since = "1.8.0")]
    fn st_ino(&self) -> u64;
    #[stable(feature = "metadata_ext2", since = "1.8.0")]
    fn st_mode(&self) -> u32;
    #[stable(feature = "metadata_ext2", since = "1.8.0")]
    fn st_nlink(&self) -> u64;
    #[stable(feature = "metadata_ext2", since = "1.8.0")]
    fn st_uid(&self) -> u32;
    #[stable(feature = "metadata_ext2", since = "1.8.0")]
    fn st_gid(&self) -> u32;
    #[stable(feature = "metadata_ext2", since = "1.8.0")]
    fn st_rdev(&self) -> u64;
    #[stable(feature = "metadata_ext2", since = "1.8.0")]
    fn st_size(&self) -> u64;
    #[stable(feature = "metadata_ext2", since = "1.8.0")]
    fn st_atime(&self) -> i64;
    #[stable(feature = "metadata_ext2", since = "1.8.0")]
    fn st_atime_nsec(&self) -> i64;
    #[stable(feature = "metadata_ext2", since = "1.8.0")]
    fn st_mtime(&self) -> i64;
    #[stable(feature = "metadata_ext2", since = "1.8.0")]
    fn st_mtime_nsec(&self) -> i64;
    #[stable(feature = "metadata_ext2", since = "1.8.0")]
    fn st_ctime(&self) -> i64;
    #[stable(feature = "metadata_ext2", since = "1.8.0")]
    fn st_ctime_nsec(&self) -> i64;
    #[stable(feature = "metadata_ext2", since = "1.8.0")]
    fn st_blksize(&self) -> u64;
    #[stable(feature = "metadata_ext2", since = "1.8.0")]
    fn st_blocks(&self) -> u64;

    // Shorthand aliases matching std::os::unix::fs::MetadataExt
    #[stable(feature = "metadata_ext", since = "1.1.0")]
    fn dev(&self) -> u64 { self.st_dev() }
    #[stable(feature = "metadata_ext", since = "1.1.0")]
    fn ino(&self) -> u64 { self.st_ino() }
    #[stable(feature = "metadata_ext", since = "1.1.0")]
    fn mode(&self) -> u32 { self.st_mode() }
    #[stable(feature = "metadata_ext", since = "1.1.0")]
    fn nlink(&self) -> u64 { self.st_nlink() }
    #[stable(feature = "metadata_ext", since = "1.1.0")]
    fn uid(&self) -> u32 { self.st_uid() }
    #[stable(feature = "metadata_ext", since = "1.1.0")]
    fn gid(&self) -> u32 { self.st_gid() }
    #[stable(feature = "metadata_ext", since = "1.1.0")]
    fn rdev(&self) -> u64 { self.st_rdev() }
    #[stable(feature = "metadata_ext", since = "1.1.0")]
    fn size(&self) -> u64 { self.st_size() }
    #[stable(feature = "metadata_ext", since = "1.1.0")]
    fn atime(&self) -> i64 { self.st_atime() }
    #[stable(feature = "metadata_ext", since = "1.1.0")]
    fn atime_nsec(&self) -> i64 { self.st_atime_nsec() }
    #[stable(feature = "metadata_ext", since = "1.1.0")]
    fn mtime(&self) -> i64 { self.st_mtime() }
    #[stable(feature = "metadata_ext", since = "1.1.0")]
    fn mtime_nsec(&self) -> i64 { self.st_mtime_nsec() }
    #[stable(feature = "metadata_ext", since = "1.1.0")]
    fn ctime(&self) -> i64 { self.st_ctime() }
    #[stable(feature = "metadata_ext", since = "1.1.0")]
    fn ctime_nsec(&self) -> i64 { self.st_ctime_nsec() }
    #[stable(feature = "metadata_ext", since = "1.1.0")]
    fn blksize(&self) -> u64 { self.st_blksize() }
    #[stable(feature = "metadata_ext", since = "1.1.0")]
    fn blocks(&self) -> u64 { self.st_blocks() }
}

#[stable(feature = "metadata_ext", since = "1.1.0")]
impl MetadataExt for Metadata {
    #[allow(deprecated)]
    fn as_raw_stat(&self) -> &raw::stat {
        unsafe { &*(self.as_inner().stat_ref() as *const _ as *const raw::stat) }
    }
    fn st_dev(&self) -> u64 {
        self.as_inner().stat_ref().st_dev as u64
    }
    fn st_ino(&self) -> u64 {
        self.as_inner().stat_ref().st_ino as u64
    }
    fn st_mode(&self) -> u32 {
        self.as_inner().stat_ref().st_mode as u32
    }
    fn st_nlink(&self) -> u64 {
        self.as_inner().stat_ref().st_nlink as u64
    }
    fn st_uid(&self) -> u32 {
        self.as_inner().stat_ref().st_uid as u32
    }
    fn st_gid(&self) -> u32 {
        self.as_inner().stat_ref().st_gid as u32
    }
    fn st_rdev(&self) -> u64 {
        self.as_inner().stat_ref().st_rdev as u64
    }
    fn st_size(&self) -> u64 {
        self.as_inner().stat_ref().st_size as u64
    }
    fn st_atime(&self) -> i64 {
        self.as_inner().stat_ref().st_atime as i64
    }
    fn st_atime_nsec(&self) -> i64 {
        self.as_inner().stat_ref().st_atime_nsec as i64
    }
    fn st_mtime(&self) -> i64 {
        self.as_inner().stat_ref().st_mtime as i64
    }
    fn st_mtime_nsec(&self) -> i64 {
        self.as_inner().stat_ref().st_mtime_nsec as i64
    }
    fn st_ctime(&self) -> i64 {
        self.as_inner().stat_ref().st_ctime as i64
    }
    fn st_ctime_nsec(&self) -> i64 {
        self.as_inner().stat_ref().st_ctime_nsec as i64
    }
    fn st_blksize(&self) -> u64 {
        self.as_inner().stat_ref().st_blksize as u64
    }
    fn st_blocks(&self) -> u64 {
        self.as_inner().stat_ref().st_blocks as u64
    }
}

/// OS-specific extensions to [`fs::Permissions`].
///
/// [`fs::Permissions`]: crate::fs::Permissions
#[stable(feature = "fs_ext", since = "1.1.0")]
pub trait PermissionsExt {
    /// Returns the underlying raw `st_mode` bits.
    #[stable(feature = "fs_ext", since = "1.1.0")]
    fn mode(&self) -> u32;

    /// Sets the underlying raw bits.
    #[stable(feature = "fs_ext", since = "1.1.0")]
    fn set_mode(&mut self, mode: u32);

    /// Creates a new instance of `Permissions` from the given set of Unix permission bits.
    #[stable(feature = "fs_ext", since = "1.1.0")]
    fn from_mode(mode: u32) -> Self;
}

#[stable(feature = "fs_ext", since = "1.1.0")]
impl PermissionsExt for Permissions {
    fn mode(&self) -> u32 {
        self.as_inner().mode()
    }

    fn set_mode(&mut self, mode: u32) {
        *self = Permissions::from_inner(FromInner::from_inner(mode));
    }

    fn from_mode(mode: u32) -> Permissions {
        Permissions::from_inner(FromInner::from_inner(mode))
    }
}

/// Creates a new symbolic link on the filesystem.
///
/// The `link` path will be a symbolic link pointing to the `original` path.
#[stable(feature = "symlink", since = "1.1.0")]
pub fn symlink<P: AsRef<Path>, Q: AsRef<Path>>(original: P, link: Q) -> io::Result<()> {
    crate::sys::fs::symlink(original.as_ref(), link.as_ref())
}
