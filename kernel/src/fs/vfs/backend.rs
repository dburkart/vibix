//! `VfsBackend` — adapts [`OpenFile`] into the [`FileBackend`] interface.
//!
//! This is the bridge between the VFS layer (RFC 0002) and the per-process
//! file-descriptor table in [`crate::fs::FileDescTable`]. Each successful
//! `sys_open` wraps the resulting `Arc<OpenFile>` in a `VfsBackend`, which
//! is then stored as an `Arc<dyn FileBackend>` in the descriptor slot.
//!
//! ## POSIX open-file description semantics
//!
//! `FileDescTable::clone_for_fork` shallow-clones `Arc<FileDescription>`,
//! which in turn shallow-clones `Arc<dyn FileBackend>`. For a `VfsBackend`
//! that means the parent and child share the **same** `Arc<OpenFile>`,
//! including the same `offset` mutex — exactly the POSIX guarantee that
//! fork'd children share the open-file description with the parent.
//!
//! ## O_CLOEXEC
//!
//! The `O_CLOEXEC` flag lives on `FileDescription.flags`, not inside
//! `VfsBackend`. `FileDescTable::close_cloexec` inspects that field and
//! drops the `Arc<FileDescription>` (and thus the `VfsBackend` and
//! `OpenFile`) when the flag is set. No special handling is needed here.

use alloc::sync::Arc;

use crate::fs::FileBackend;

use super::open_file::OpenFile;

/// Wraps an [`OpenFile`] as a [`FileBackend`] for the fd-table.
///
/// `read` and `write` delegate to [`FileOps`](super::ops::FileOps) on the
/// `OpenFile`, advancing the shared file offset atomically under the
/// `OpenFile.offset` mutex so that concurrent calls from threads sharing the
/// same description serialise correctly.
pub struct VfsBackend {
    pub open_file: Arc<OpenFile>,
}

impl FileBackend for VfsBackend {
    /// Read up to `buf.len()` bytes from the current file offset.
    ///
    /// Advances the shared offset by the number of bytes actually read.
    /// Returns `Err(errno)` on I/O errors (e.g. `-EINVAL` for a
    /// non-readable file type, `-EPERM` etc. from the underlying `FileOps`).
    fn read(&self, buf: &mut [u8]) -> Result<usize, i64> {
        let mut off = self.open_file.offset.lock();
        let n = self.open_file.ops.read(&self.open_file, buf, *off)?;
        *off += n as u64;
        Ok(n)
    }

    /// Write `buf` at the current file offset.
    ///
    /// Advances the shared offset by the number of bytes written.
    /// Returns `Err(errno)` on I/O errors (e.g. `-EPERM` for a
    /// read-only filesystem).
    fn write(&self, buf: &[u8]) -> Result<usize, i64> {
        let mut off = self.open_file.offset.lock();
        let n = self.open_file.ops.write(&self.open_file, buf, *off)?;
        *off += n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::vfs::dentry::Dentry;
    use crate::fs::vfs::inode::{Inode, InodeKind, InodeMeta};
    use crate::fs::vfs::open_file::OpenFile;
    use crate::fs::vfs::ops::{FileOps, InodeOps, SetAttr, Stat, StatFs, SuperOps};
    use crate::fs::vfs::super_block::{SbActiveGuard, SbFlags, SuperBlock};
    use crate::fs::vfs::FsId;
    use crate::fs::{flags, FileDescTable, FileDescription};
    use alloc::sync::Arc;

    // -----------------------------------------------------------------------
    // Stubs
    // -----------------------------------------------------------------------

    struct StubInodeOps;
    impl InodeOps for StubInodeOps {
        fn getattr(&self, _inode: &Inode, _out: &mut Stat) -> Result<(), i64> {
            Ok(())
        }
        fn setattr(&self, _inode: &Inode, _attr: &SetAttr) -> Result<(), i64> {
            Ok(())
        }
    }

    struct StubSuperOps;
    impl SuperOps for StubSuperOps {
        fn root_inode(&self) -> Arc<Inode> {
            unreachable!("test stub")
        }
        fn statfs(&self) -> Result<StatFs, i64> {
            Ok(StatFs::default())
        }
        fn unmount(&self) -> Result<(), i64> {
            Ok(())
        }
    }

    /// A `FileOps` stub that fills `buf` with a repeated byte pattern on
    /// read and counts bytes written.
    struct CountingOps {
        fill_byte: u8,
    }

    impl FileOps for CountingOps {
        fn read(&self, _f: &OpenFile, buf: &mut [u8], _off: u64) -> Result<usize, i64> {
            for b in buf.iter_mut() {
                *b = self.fill_byte;
            }
            Ok(buf.len())
        }

        fn write(&self, _f: &OpenFile, buf: &[u8], _off: u64) -> Result<usize, i64> {
            Ok(buf.len())
        }
    }

    fn make_open_file(fill_byte: u8) -> Arc<OpenFile> {
        let sb = Arc::new(SuperBlock::new(
            FsId(42),
            Arc::new(StubSuperOps),
            "stub",
            512,
            SbFlags::default(),
        ));
        let inode = Arc::new(Inode::new(
            1,
            Arc::downgrade(&sb),
            Arc::new(StubInodeOps),
            Arc::new(CountingOps { fill_byte }),
            InodeKind::Reg,
            InodeMeta::default(),
        ));
        let dentry = Dentry::new_root(inode.clone());
        let file_ops: Arc<dyn FileOps> = Arc::new(CountingOps { fill_byte });
        let guard = SbActiveGuard::try_acquire(&sb).expect("guard");
        OpenFile::new(dentry, inode, file_ops, sb, 0, guard)
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[test]
    fn read_advances_offset() {
        let of = make_open_file(0xAB);
        let backend = VfsBackend {
            open_file: of.clone(),
        };
        let mut buf = [0u8; 4];
        let n = backend.read(&mut buf).expect("read must succeed");
        assert_eq!(n, 4);
        assert_eq!(buf, [0xABu8; 4]);
        assert_eq!(*of.offset.lock(), 4, "offset must advance by bytes read");
    }

    #[test]
    fn write_advances_offset() {
        let of = make_open_file(0);
        let backend = VfsBackend {
            open_file: of.clone(),
        };
        let data = b"hello";
        let n = backend.write(data).expect("write must succeed");
        assert_eq!(n, 5);
        assert_eq!(*of.offset.lock(), 5, "offset must advance by bytes written");
    }

    #[test]
    fn fork_shares_open_file_description() {
        // Build an fd table with a VfsBackend fd.
        let of = make_open_file(0xCD);
        let backend = Arc::new(VfsBackend {
            open_file: of.clone(),
        }) as Arc<dyn FileBackend>;
        let mut parent = FileDescTable::new();
        let desc = Arc::new(FileDescription { backend, flags: 0 });
        let fd = parent.alloc_fd(desc).expect("alloc_fd");

        // Fork — child shares the Arc<OpenFile>.
        let child = parent.clone_for_fork();

        // Read 3 bytes via the parent's fd.
        let parent_backend = parent.get(fd).expect("parent fd open");
        let mut buf = [0u8; 3];
        parent_backend.read(&mut buf).unwrap();

        // The shared offset must be visible to the child's backend.
        let child_backend = child.get(fd).expect("child fd open");
        // Downcast isn't available on dyn FileBackend, so we check the
        // underlying OpenFile offset directly via our `of` reference.
        assert_eq!(*of.offset.lock(), 3, "child sees parent's advanced offset");
        // Child can read 2 more bytes.
        let mut buf2 = [0u8; 2];
        child_backend.read(&mut buf2).unwrap();
        assert_eq!(*of.offset.lock(), 5, "offset advances further via child");
    }

    #[test]
    fn close_cloexec_drops_vfs_backend() {
        let of = make_open_file(0);
        let backend = Arc::new(VfsBackend {
            open_file: of.clone(),
        }) as Arc<dyn FileBackend>;
        let mut t = FileDescTable::new();
        let cloexec_desc = Arc::new(FileDescription {
            backend,
            flags: flags::O_CLOEXEC,
        });
        let fd = t.alloc_fd(cloexec_desc).expect("alloc_fd");

        // Allocate a non-cloexec fd too.
        struct NullBackend;
        impl FileBackend for NullBackend {
            fn read(&self, _: &mut [u8]) -> Result<usize, i64> {
                Ok(0)
            }
            fn write(&self, buf: &[u8]) -> Result<usize, i64> {
                Ok(buf.len())
            }
        }
        let null_desc = Arc::new(FileDescription {
            backend: Arc::new(NullBackend) as Arc<dyn FileBackend>,
            flags: 0,
        });
        let null_fd = t.alloc_fd(null_desc).expect("alloc null fd");

        t.close_cloexec();

        assert!(t.get(fd).is_err(), "O_CLOEXEC VfsBackend fd must be closed");
        assert!(t.get(null_fd).is_ok(), "non-cloexec fd must survive");
    }
}
