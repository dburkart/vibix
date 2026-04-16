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
use core::sync::atomic::Ordering;

use crate::fs::{flags as oflags, FileBackend, EINVAL, EOVERFLOW};

use super::open_file::OpenFile;
use super::ops::Whence;

/// Linux `lseek(2)` whence constants. Values pinned to the x86_64 ABI.
pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;

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
    fn as_vfs(&self) -> Option<&VfsBackend> {
        Some(self)
    }

    /// Read up to `buf.len()` bytes from the current file offset.
    ///
    /// Advances the shared offset by the number of bytes actually read.
    /// Returns `Err(errno)` on I/O errors (e.g. `-EINVAL` for a
    /// non-readable file type, `-EPERM` etc. from the underlying `FileOps`).
    fn read(&self, buf: &mut [u8]) -> Result<usize, i64> {
        let mut off = self.open_file.offset.lock();
        let n = self.open_file.ops.read(&self.open_file, buf, *off)?;
        *off = off.checked_add(n as u64).ok_or(EOVERFLOW)?;
        Ok(n)
    }

    /// Write `buf` at the current file offset.
    ///
    /// Advances the shared offset by the number of bytes written.
    /// Returns `Err(errno)` on I/O errors (e.g. `-EPERM` for a
    /// read-only filesystem).
    fn write(&self, buf: &[u8]) -> Result<usize, i64> {
        let mut off = self.open_file.offset.lock();
        // POSIX O_APPEND: under the offset mutex (which also serialises
        // writes through dup'd fds that share this open-file description),
        // snap the write position to end-of-file before dispatching.
        // Read the current O_APPEND state under the offset mutex. Using
        // Relaxed is safe: the mutex serialises writers through this open-
        // file description, so no acquire fence is needed to see the flag
        // a concurrent `fcntl(F_SETFL)` just published — the next write
        // picks it up, which is all POSIX guarantees.
        let write_off = if self.open_file.flags.load(Ordering::Relaxed) & oflags::O_APPEND != 0 {
            self.open_file.inode.meta.read().size
        } else {
            *off
        };
        let n = self.open_file.ops.write(&self.open_file, buf, write_off)?;
        *off = write_off.checked_add(n as u64).ok_or(EOVERFLOW)?;
        Ok(n)
    }

    /// Reposition the shared file offset.
    ///
    /// Maps the Linux `whence` integer to [`Whence`] (rejecting unknown
    /// values with `EINVAL`) and delegates to [`FileOps::seek`], which is
    /// responsible for acquiring `OpenFile.offset` and applying the
    /// filesystem's notion of file size for `SEEK_END`. Returns the new
    /// absolute offset as an `i64`, or `EOVERFLOW` if it does not fit.
    fn lseek(&self, off: i64, whence: i32) -> Result<i64, i64> {
        let w = match whence {
            SEEK_SET => Whence::Set,
            SEEK_CUR => Whence::Cur,
            SEEK_END => Whence::End,
            _ => return Err(EINVAL),
        };
        let new_off = self.open_file.ops.seek(&self.open_file, w, off)?;
        if new_off > i64::MAX as u64 {
            return Err(EOVERFLOW);
        }
        Ok(new_off as i64)
    }

    /// Read directory entries by delegating to [`FileOps::getdents`], using
    /// the shared `OpenFile.offset` as the resumption cookie.
    ///
    /// Non-directory inodes surface as `ENOTDIR` from the underlying ops.
    fn getdents64(&self, buf: &mut [u8]) -> Result<usize, i64> {
        let mut off = self.open_file.offset.lock();
        self.open_file.ops.getdents(&self.open_file, buf, &mut *off)
    }

    /// Propagate a `fcntl(F_SETFL)` update into the underlying `OpenFile`.
    ///
    /// CAS-swaps only `O_APPEND | O_NONBLOCK | O_ASYNC` into the shared
    /// `OpenFile.flags` atomic, preserving the access mode and creation-
    /// time bits. The matching bits on `FileDescription.flags` are already
    /// set by `FileDescTable::set_status_flags` — this hook exists so the
    /// `O_APPEND` check in `write` (which reads `OpenFile.flags`, not the
    /// description's copy) sees the new value on the very next write.
    fn set_flags(&self, new_flags: u32) {
        let mutable = oflags::O_APPEND | oflags::O_NONBLOCK | oflags::O_ASYNC;
        let mut cur = self.open_file.flags.load(Ordering::Relaxed);
        loop {
            let next = (cur & !mutable) | (new_flags & mutable);
            match self.open_file.flags.compare_exchange_weak(
                cur,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => cur = observed,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::vfs::dentry::Dentry;
    use crate::fs::vfs::inode::{Inode, InodeKind, InodeMeta};
    use crate::fs::vfs::open_file::OpenFile;
    use crate::fs::vfs::ops::Whence;
    use crate::fs::vfs::ops::{FileOps, InodeOps, SetAttr, Stat, StatFs, SuperOps};
    use crate::fs::vfs::super_block::{SbActiveGuard, SbFlags, SuperBlock};
    use crate::fs::vfs::FsId;
    use crate::fs::{flags, FileDescTable, FileDescription, EINVAL, EOVERFLOW, ESPIPE};
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};

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
        fn unmount(&self) {}
    }

    /// A `FileOps` stub that fills `buf` with a repeated byte pattern on
    /// read and counts bytes written.
    struct CountingOps {
        fill_byte: u8,
    }

    /// A `FileOps` stub whose `seek` mirrors ramfs (SEEK_SET absolute,
    /// SEEK_CUR relative, SEEK_END from a fixed `size`). Used to exercise
    /// `VfsBackend::lseek` end-to-end without pulling in ramfs.
    struct SeekableOps {
        size: u64,
    }

    impl FileOps for SeekableOps {
        fn seek(&self, f: &OpenFile, whence: Whence, off: i64) -> Result<u64, i64> {
            let mut cur = f.offset.lock();
            let new_off = match whence {
                Whence::Set => off,
                Whence::Cur => (*cur as i64).saturating_add(off),
                Whence::End => (self.size as i64).saturating_add(off),
            };
            if new_off < 0 {
                return Err(EINVAL);
            }
            *cur = new_off as u64;
            Ok(*cur)
        }
    }

    /// A `FileOps` stub whose `seek` returns an offset larger than
    /// `i64::MAX`, to exercise the `EOVERFLOW` path in `VfsBackend::lseek`.
    struct HugeSeekOps;
    impl FileOps for HugeSeekOps {
        fn seek(&self, _f: &OpenFile, _whence: Whence, _off: i64) -> Result<u64, i64> {
            Ok(u64::MAX)
        }
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

    fn make_open_file_with_ops(ops: Arc<dyn FileOps>) -> Arc<OpenFile> {
        make_open_file_with_ops_flags(ops, 0)
    }

    fn make_open_file_with_ops_flags(ops: Arc<dyn FileOps>, flags: u32) -> Arc<OpenFile> {
        make_open_file_with_ops_flags_meta(ops, flags, InodeMeta::default())
    }

    fn make_open_file_with_ops_flags_meta(
        ops: Arc<dyn FileOps>,
        flags: u32,
        meta: InodeMeta,
    ) -> Arc<OpenFile> {
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
            ops.clone(),
            InodeKind::Reg,
            meta,
        ));
        let dentry = Dentry::new_root(inode.clone());
        let guard = SbActiveGuard::try_acquire(&sb).expect("guard");
        OpenFile::new(dentry, inode, ops, sb.clone(), flags, guard)
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
        OpenFile::new(dentry, inode, file_ops, sb.clone(), 0, guard)
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
        let desc = Arc::new(FileDescription::new(backend, 0));
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
    fn lseek_set_absolute_offset() {
        let of = make_open_file_with_ops(Arc::new(SeekableOps { size: 100 }));
        let backend = VfsBackend {
            open_file: of.clone(),
        };
        assert_eq!(backend.lseek(42, SEEK_SET), Ok(42));
        assert_eq!(*of.offset.lock(), 42);
    }

    #[test]
    fn lseek_cur_advances_from_current() {
        let of = make_open_file_with_ops(Arc::new(SeekableOps { size: 100 }));
        *of.offset.lock() = 10;
        let backend = VfsBackend {
            open_file: of.clone(),
        };
        assert_eq!(backend.lseek(5, SEEK_CUR), Ok(15));
        assert_eq!(*of.offset.lock(), 15);
    }

    #[test]
    fn lseek_end_from_file_size() {
        let of = make_open_file_with_ops(Arc::new(SeekableOps { size: 100 }));
        let backend = VfsBackend {
            open_file: of.clone(),
        };
        assert_eq!(backend.lseek(-10, SEEK_END), Ok(90));
        assert_eq!(*of.offset.lock(), 90);
    }

    #[test]
    fn lseek_negative_result_returns_einval() {
        let of = make_open_file_with_ops(Arc::new(SeekableOps { size: 100 }));
        let backend = VfsBackend { open_file: of };
        assert_eq!(backend.lseek(-1, SEEK_SET), Err(EINVAL));
    }

    #[test]
    fn lseek_unknown_whence_returns_einval() {
        let of = make_open_file_with_ops(Arc::new(SeekableOps { size: 100 }));
        let backend = VfsBackend { open_file: of };
        assert_eq!(backend.lseek(0, 99), Err(EINVAL));
    }

    #[test]
    fn lseek_default_ops_seek_returns_espipe() {
        // CountingOps does not override `FileOps::seek`, so it inherits
        // the default ESPIPE — confirming that a FileOps lacking seek
        // surfaces ESPIPE end-to-end.
        let of = make_open_file(0);
        let backend = VfsBackend { open_file: of };
        assert_eq!(backend.lseek(0, SEEK_SET), Err(ESPIPE));
    }

    /// A `FileOps` stub that records the offset its `write` was called at.
    struct RecordingWriteOps {
        last_off: AtomicU64,
    }
    impl FileOps for RecordingWriteOps {
        fn write(&self, _f: &OpenFile, buf: &[u8], off: u64) -> Result<usize, i64> {
            self.last_off.store(off, Ordering::SeqCst);
            Ok(buf.len())
        }
    }

    #[test]
    fn write_without_o_append_uses_tracked_offset() {
        let ops = Arc::new(RecordingWriteOps {
            last_off: AtomicU64::new(0),
        });
        let of = make_open_file_with_ops_flags_meta(
            ops.clone(),
            0,
            InodeMeta {
                size: 100,
                ..Default::default()
            },
        );
        *of.offset.lock() = 7;
        let backend = VfsBackend {
            open_file: of.clone(),
        };
        backend.write(b"xyz").expect("write");
        assert_eq!(ops.last_off.load(Ordering::SeqCst), 7);
        assert_eq!(*of.offset.lock(), 10);
    }

    #[test]
    fn write_with_o_append_snaps_to_eof() {
        let ops = Arc::new(RecordingWriteOps {
            last_off: AtomicU64::new(0),
        });
        let of = make_open_file_with_ops_flags_meta(
            ops.clone(),
            flags::O_APPEND,
            InodeMeta {
                size: 100,
                ..Default::default()
            },
        );
        // Even if the tracked offset points elsewhere, O_APPEND must
        // dispatch the write at the current EOF.
        *of.offset.lock() = 0;
        let backend = VfsBackend {
            open_file: of.clone(),
        };
        backend.write(b"abcd").expect("write");
        assert_eq!(
            ops.last_off.load(Ordering::SeqCst),
            100,
            "O_APPEND must use inode size as write offset"
        );
        assert_eq!(*of.offset.lock(), 104, "offset advances from EOF by n");
    }

    #[test]
    fn lseek_overflow_returns_eoverflow() {
        let of = make_open_file_with_ops(Arc::new(HugeSeekOps));
        let backend = VfsBackend { open_file: of };
        assert_eq!(backend.lseek(0, SEEK_SET), Err(EOVERFLOW));
    }

    #[test]
    fn lseek_across_fork_shares_offset() {
        // Same offset mutex across parent/child → lseek on one side is
        // visible to the other, matching POSIX open-file-description sharing.
        let of = make_open_file_with_ops(Arc::new(SeekableOps { size: 100 }));
        let parent_backend = Arc::new(VfsBackend {
            open_file: of.clone(),
        }) as Arc<dyn FileBackend>;
        let mut parent = FileDescTable::new();
        let desc = Arc::new(FileDescription::new(parent_backend, 0));
        let fd = parent.alloc_fd(desc).expect("alloc_fd");
        let child = parent.clone_for_fork();

        parent.get(fd).unwrap().lseek(42, SEEK_SET).unwrap();
        assert_eq!(*of.offset.lock(), 42);
        // Child sees the same offset via its own fd — via the shared OpenFile.
        assert!(child.get(fd).is_ok());
        assert_eq!(*of.offset.lock(), 42);
    }

    #[test]
    fn set_flags_toggles_o_append_and_affects_next_write() {
        // Open without O_APPEND → first write lands at the tracked offset;
        // set_flags(O_APPEND) → next write snaps to EOF.
        let ops = Arc::new(RecordingWriteOps {
            last_off: AtomicU64::new(0),
        });
        let of = make_open_file_with_ops_flags_meta(
            ops.clone(),
            0,
            InodeMeta {
                size: 100,
                ..Default::default()
            },
        );
        *of.offset.lock() = 7;
        let backend = VfsBackend {
            open_file: of.clone(),
        };
        backend.write(b"xyz").expect("write");
        assert_eq!(ops.last_off.load(Ordering::SeqCst), 7);

        // Reset the offset, flip O_APPEND on via set_flags (the path
        // F_SETFL takes), and confirm the next write goes to EOF instead.
        *of.offset.lock() = 0;
        backend.set_flags(flags::O_APPEND);
        backend.write(b"abcd").expect("write");
        assert_eq!(
            ops.last_off.load(Ordering::SeqCst),
            100,
            "F_SETFL(O_APPEND) must make the next write snap to inode size"
        );
    }

    #[test]
    fn set_flags_preserves_access_mode_bits() {
        // Construct an OpenFile with O_RDWR | O_APPEND already set. A
        // set_flags call that only passes O_NONBLOCK must clear O_APPEND
        // (not in the new mask) but leave O_RDWR untouched.
        let ops = Arc::new(CountingOps { fill_byte: 0 });
        let of =
            make_open_file_with_ops_flags(ops, flags::O_RDWR | flags::O_APPEND | flags::O_CLOEXEC);
        let backend = VfsBackend {
            open_file: of.clone(),
        };
        backend.set_flags(flags::O_NONBLOCK);
        let post = of.flags.load(Ordering::Relaxed);
        assert_eq!(post & flags::O_ACCMODE, flags::O_RDWR, "access mode kept");
        assert_eq!(post & flags::O_APPEND, 0, "O_APPEND cleared");
        assert_eq!(
            post & flags::O_NONBLOCK,
            flags::O_NONBLOCK,
            "O_NONBLOCK set"
        );
        assert_eq!(
            post & flags::O_CLOEXEC,
            flags::O_CLOEXEC,
            "O_CLOEXEC is not a mutable status bit"
        );
    }

    #[test]
    fn set_status_flags_propagates_to_vfs_backend() {
        // End-to-end through FileDescTable: allocate a fd backed by
        // VfsBackend, call set_status_flags(O_APPEND), confirm
        // OpenFile.flags carries O_APPEND afterwards.
        let ops = Arc::new(RecordingWriteOps {
            last_off: AtomicU64::new(0),
        });
        let of = make_open_file_with_ops_flags_meta(
            ops.clone(),
            flags::O_RDWR,
            InodeMeta {
                size: 50,
                ..Default::default()
            },
        );
        let backend = Arc::new(VfsBackend {
            open_file: of.clone(),
        }) as Arc<dyn FileBackend>;
        let mut t = FileDescTable::new();
        let desc = Arc::new(FileDescription::new(backend, flags::O_RDWR));
        let fd = t.alloc_fd(desc).expect("alloc_fd");
        t.set_status_flags(fd, flags::O_APPEND)
            .expect("set_status_flags");
        // OpenFile.flags carries the updated status bits — not stale.
        let post = of.flags.load(Ordering::Relaxed);
        assert_eq!(post & flags::O_APPEND, flags::O_APPEND);
        assert_eq!(post & flags::O_ACCMODE, flags::O_RDWR, "access mode kept");
    }

    #[test]
    fn close_cloexec_drops_vfs_backend() {
        let of = make_open_file(0);
        let backend = Arc::new(VfsBackend {
            open_file: of.clone(),
        }) as Arc<dyn FileBackend>;
        let mut t = FileDescTable::new();
        let cloexec_desc = Arc::new(FileDescription::new(backend, 0));
        let fd = t
            .alloc_fd_with_flags(cloexec_desc, flags::O_CLOEXEC)
            .expect("alloc_fd");

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
        let null_desc = Arc::new(FileDescription::new(
            Arc::new(NullBackend) as Arc<dyn FileBackend>,
            0,
        ));
        let null_fd = t.alloc_fd(null_desc).expect("alloc null fd");

        t.close_cloexec();

        assert!(t.get(fd).is_err(), "O_CLOEXEC VfsBackend fd must be closed");
        assert!(t.get(null_fd).is_ok(), "non-cloexec fd must survive");
    }
}
