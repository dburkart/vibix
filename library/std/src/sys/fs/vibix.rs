//! Filesystem implementation for vibix.
//!
//! Backed by vibix_abi syscall wrappers around openat, read, write, fstat,
//! getdents64, lseek, close, rename, unlink, mkdir, rmdir, chmod, chown,
//! utimensat.

use crate::ffi::{CStr, OsStr, OsString};
use crate::fmt;
use crate::fs::TryLockError;
use crate::io::{self, BorrowedCursor, IoSlice, IoSliceMut, SeekFrom};
use crate::os::vibix::ffi::{OsStrExt, OsStringExt};
use crate::path::{Path, PathBuf};
use crate::sync::Arc;
pub use crate::sys::fs::common::Dir;
use crate::sys::helpers::run_path_with_cstr;
use crate::sys::time::SystemTime;
use crate::sys::unsupported;

use vibix_abi::fs::{
    self as vfs, AT_FDCWD, AT_SYMLINK_NOFOLLOW, DT_DIR, DT_LNK, DT_REG, DT_UNKNOWN, O_APPEND,
    O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY, SEEK_CUR,
    SEEK_END, SEEK_SET, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG, UTIME_NOW, UTIME_OMIT,
};

/// Convert a negative syscall return to an io::Error.
fn cvt(ret: i64) -> io::Result<i64> {
    if ret < 0 { Err(io::Error::from_raw_os_error(-ret as i32)) } else { Ok(ret) }
}

pub struct File {
    fd: i32,
}

impl Drop for File {
    fn drop(&mut self) {
        unsafe {
            vfs::close(self.fd);
        }
    }
}

#[derive(Clone)]
pub struct FileAttr {
    stat: vfs::Stat,
}

struct InnerReadDir {
    root: PathBuf,
    buf: Vec<u8>,
}

pub struct ReadDir {
    inner: Arc<InnerReadDir>,
    pos: usize,
}

pub struct DirEntry {
    root: PathBuf,
    ino: u64,
    type_: u8,
    name: OsString,
}

#[derive(Clone, Debug)]
pub struct OpenOptions {
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
    mode: u32,
}

#[derive(Copy, Clone, Debug)]
pub struct FileTimes {
    accessed: Option<SystemTime>,
    modified: Option<SystemTime>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FilePermissions {
    mode: u32,
}

#[derive(Copy, Clone, Eq, Debug)]
pub struct FileType {
    mode: u32,
}

impl PartialEq for FileType {
    fn eq(&self, other: &Self) -> bool {
        self.mode == other.mode
    }
}

impl core::hash::Hash for FileType {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.mode.hash(state);
    }
}

#[derive(Debug)]
pub struct DirBuilder {
    mode: u32,
}

// --- FileAttr ---

impl FileAttr {
    pub fn size(&self) -> u64 {
        self.stat.st_size as u64
    }

    pub fn perm(&self) -> FilePermissions {
        FilePermissions { mode: self.stat.st_mode & 0o7777 }
    }

    pub fn file_type(&self) -> FileType {
        FileType { mode: self.stat.st_mode & S_IFMT }
    }

    pub fn modified(&self) -> io::Result<SystemTime> {
        SystemTime::new(self.stat.st_mtime, self.stat.st_mtime_nsec)
    }

    pub fn accessed(&self) -> io::Result<SystemTime> {
        SystemTime::new(self.stat.st_atime, self.stat.st_atime_nsec)
    }

    pub fn created(&self) -> io::Result<SystemTime> {
        SystemTime::new(self.stat.st_ctime, self.stat.st_ctime_nsec)
    }
}

// --- FilePermissions ---

impl FilePermissions {
    pub fn readonly(&self) -> bool {
        self.mode & 0o222 == 0
    }

    pub fn set_readonly(&mut self, readonly: bool) {
        if readonly {
            self.mode &= !0o222;
        } else {
            self.mode |= 0o222;
        }
    }

    #[allow(dead_code)]
    pub fn mode(&self) -> u32 {
        self.mode
    }
}

// --- FileTimes ---

impl FileTimes {
    pub fn set_accessed(&mut self, t: SystemTime) {
        self.accessed = Some(t);
    }
    pub fn set_modified(&mut self, t: SystemTime) {
        self.modified = Some(t);
    }
}

impl Default for FileTimes {
    fn default() -> Self {
        FileTimes { accessed: None, modified: None }
    }
}

// --- FileType ---

impl FileType {
    pub fn is_dir(&self) -> bool {
        self.mode == S_IFDIR
    }
    pub fn is_file(&self) -> bool {
        self.mode == S_IFREG
    }
    pub fn is_symlink(&self) -> bool {
        self.mode == S_IFLNK
    }
}

// --- ReadDir ---

impl fmt::Debug for ReadDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.inner.root, f)
    }
}

impl Iterator for ReadDir {
    type Item = io::Result<DirEntry>;

    fn next(&mut self) -> Option<io::Result<DirEntry>> {
        loop {
            if self.pos >= self.inner.buf.len() {
                return None;
            }

            let buf = &self.inner.buf[self.pos..];
            if buf.len() < core::mem::size_of::<vfs::Dirent64>() + 1 {
                return None;
            }

            // Safety: buffer was filled by getdents64, dirent64 is repr(C).
            let dirent = unsafe { &*(buf.as_ptr() as *const vfs::Dirent64) };
            let reclen = dirent.d_reclen as usize;
            if reclen == 0 || self.pos + reclen > self.inner.buf.len() {
                return None;
            }

            self.pos += reclen;

            // The name starts after the fixed fields of dirent64.
            let name_offset = core::mem::offset_of!(vfs::Dirent64, d_name);
            let name_bytes = &buf[name_offset..reclen];
            // Find the null terminator.
            let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
            let name = OsString::from_vec(name_bytes[..name_len].to_vec());

            // Skip "." and ".."
            if name == "." || name == ".." {
                continue;
            }

            return Some(Ok(DirEntry {
                root: self.inner.root.clone(),
                ino: dirent.d_ino,
                type_: dirent.d_type,
                name,
            }));
        }
    }
}

// --- DirEntry ---

impl DirEntry {
    pub fn path(&self) -> PathBuf {
        self.root.join(self.file_name_os_str())
    }

    pub fn file_name(&self) -> OsString {
        self.file_name_os_str().to_os_string()
    }

    pub fn metadata(&self) -> io::Result<FileAttr> {
        lstat(&self.path())
    }

    pub fn file_type(&self) -> io::Result<FileType> {
        match self.type_ {
            DT_DIR => Ok(FileType { mode: S_IFDIR }),
            DT_REG => Ok(FileType { mode: S_IFREG }),
            DT_LNK => Ok(FileType { mode: S_IFLNK }),
            DT_UNKNOWN => {
                // Fall back to stat.
                self.metadata().map(|m| m.file_type())
            }
            _ => Ok(FileType { mode: 0 }),
        }
    }

    pub fn file_name_os_str(&self) -> &OsStr {
        self.name.as_os_str()
    }
}

// --- OpenOptions ---

impl OpenOptions {
    pub fn new() -> OpenOptions {
        OpenOptions {
            read: false,
            write: false,
            append: false,
            truncate: false,
            create: false,
            create_new: false,
            mode: 0o666,
        }
    }

    pub fn read(&mut self, read: bool) {
        self.read = read;
    }
    pub fn write(&mut self, write: bool) {
        self.write = write;
    }
    pub fn append(&mut self, append: bool) {
        self.append = append;
    }
    pub fn truncate(&mut self, truncate: bool) {
        self.truncate = truncate;
    }
    pub fn create(&mut self, create: bool) {
        self.create = create;
    }
    pub fn create_new(&mut self, create_new: bool) {
        self.create_new = create_new;
    }

    fn get_access_mode(&self) -> io::Result<i32> {
        match (self.read, self.write, self.append) {
            (true, false, false) => Ok(O_RDONLY),
            (false, true, false) => Ok(O_WRONLY),
            (true, true, false) => Ok(O_RDWR),
            (false, _, true) => Ok(O_WRONLY | O_APPEND),
            (true, _, true) => Ok(O_RDWR | O_APPEND),
            (false, false, false) => {
                Err(io::const_error!(io::ErrorKind::InvalidInput, "invalid access mode"))
            }
        }
    }

    fn get_creation_mode(&self) -> io::Result<i32> {
        match (self.write, self.append) {
            (true, false) => {}
            (false, false) => {
                if self.truncate || self.create || self.create_new {
                    return Err(io::const_error!(
                        io::ErrorKind::InvalidInput,
                        "invalid creation mode"
                    ));
                }
            }
            (_, true) => {
                if self.truncate && !self.create_new {
                    return Err(io::const_error!(
                        io::ErrorKind::InvalidInput,
                        "invalid creation mode"
                    ));
                }
            }
        }

        Ok(match (self.create, self.truncate, self.create_new) {
            (false, false, false) => 0,
            (true, false, false) => O_CREAT,
            (false, true, false) => O_TRUNC,
            (true, true, false) => O_CREAT | O_TRUNC,
            (_, _, true) => O_CREAT | O_EXCL,
        })
    }
}

// --- File ---

impl File {
    pub fn open(path: &Path, opts: &OpenOptions) -> io::Result<File> {
        run_path_with_cstr(path, &|path| File::open_c(path, opts))
    }

    fn open_c(path: &CStr, opts: &OpenOptions) -> io::Result<File> {
        let flags = opts.get_access_mode()? | opts.get_creation_mode()? | O_CLOEXEC;
        let mode = if flags & O_CREAT != 0 { opts.mode } else { 0 };
        let fd = cvt(unsafe { vfs::openat(AT_FDCWD, path.as_ptr() as *const u8, flags, mode) })?;
        Ok(File { fd: fd as i32 })
    }

    pub fn file_attr(&self) -> io::Result<FileAttr> {
        let mut stat = unsafe { core::mem::zeroed::<vfs::Stat>() };
        cvt(unsafe { vfs::fstat(self.fd, &mut stat) })?;
        Ok(FileAttr { stat })
    }

    pub fn fsync(&self) -> io::Result<()> {
        cvt(unsafe { vfs::fsync(self.fd) })?;
        Ok(())
    }

    pub fn datasync(&self) -> io::Result<()> {
        // vibix doesn't have fdatasync yet, fall back to fsync
        self.fsync()
    }

    pub fn lock(&self) -> io::Result<()> {
        unsupported()
    }

    pub fn lock_shared(&self) -> io::Result<()> {
        unsupported()
    }

    pub fn try_lock(&self) -> Result<(), TryLockError> {
        Err(TryLockError::Error(io::const_error!(
            io::ErrorKind::Unsupported,
            "file locking not supported on vibix yet"
        )))
    }

    pub fn try_lock_shared(&self) -> Result<(), TryLockError> {
        Err(TryLockError::Error(io::const_error!(
            io::ErrorKind::Unsupported,
            "file locking not supported on vibix yet"
        )))
    }

    pub fn unlock(&self) -> io::Result<()> {
        unsupported()
    }

    pub fn truncate(&self, size: u64) -> io::Result<()> {
        cvt(unsafe { vfs::ftruncate(self.fd, size as i64) })?;
        Ok(())
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let ret = cvt(unsafe { vfs::read(self.fd, buf.as_mut_ptr(), buf.len()) })?;
        Ok(ret as usize)
    }

    pub fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        // Read into the first non-empty buffer (no kernel readv yet).
        let buf = bufs.iter_mut().find(|b| !b.is_empty());
        match buf {
            Some(buf) => self.read(buf),
            None => Ok(0),
        }
    }

    pub fn is_read_vectored(&self) -> bool {
        false
    }

    pub fn read_buf(&self, mut cursor: BorrowedCursor<'_>) -> io::Result<()> {
        let ret = cvt(unsafe {
            vfs::read(self.fd, cursor.as_mut().as_mut_ptr() as *mut u8, cursor.capacity())
        })?;
        // SAFETY: Exactly `ret` bytes have been filled.
        unsafe { cursor.advance(ret as usize) };
        Ok(())
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let ret = cvt(unsafe { vfs::write(self.fd, buf.as_ptr(), buf.len()) })?;
        Ok(ret as usize)
    }

    pub fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        // Write the first non-empty buffer.
        let buf = bufs.iter().find(|b| !b.is_empty());
        match buf {
            Some(buf) => self.write(buf),
            None => Ok(0),
        }
    }

    pub fn is_write_vectored(&self) -> bool {
        false
    }

    #[inline]
    pub fn flush(&self) -> io::Result<()> {
        Ok(())
    }

    pub fn seek(&self, pos: SeekFrom) -> io::Result<u64> {
        let (whence, offset) = match pos {
            SeekFrom::Start(off) => (SEEK_SET, off as i64),
            SeekFrom::End(off) => (SEEK_END, off),
            SeekFrom::Current(off) => (SEEK_CUR, off),
        };
        let ret = cvt(unsafe { vfs::lseek(self.fd, offset, whence) })?;
        Ok(ret as u64)
    }

    pub fn size(&self) -> Option<io::Result<u64>> {
        Some(self.file_attr().map(|a| a.size()))
    }

    pub fn tell(&self) -> io::Result<u64> {
        self.seek(SeekFrom::Current(0))
    }

    pub fn duplicate(&self) -> io::Result<File> {
        let new_fd = cvt(unsafe { vfs::fcntl(self.fd, vfs::F_DUPFD_CLOEXEC, 0) })?;
        Ok(File { fd: new_fd as i32 })
    }

    pub fn set_permissions(&self, perm: FilePermissions) -> io::Result<()> {
        cvt(unsafe { vfs::fchmod(self.fd, perm.mode) })?;
        Ok(())
    }

    pub fn set_times(&self, times: FileTimes) -> io::Result<()> {
        let mut ts = [
            vfs::Timespec { tv_sec: 0, tv_nsec: UTIME_OMIT },
            vfs::Timespec { tv_sec: 0, tv_nsec: UTIME_OMIT },
        ];
        if let Some(accessed) = times.accessed {
            let (sec, nsec) = accessed.to_timespec();
            ts[0] = vfs::Timespec { tv_sec: sec, tv_nsec: nsec };
        }
        if let Some(modified) = times.modified {
            let (sec, nsec) = modified.to_timespec();
            ts[1] = vfs::Timespec { tv_sec: sec, tv_nsec: nsec };
        }
        // Use utimensat with empty path + AT_FDCWD trick won't work;
        // we need the /proc/self/fd/N path or a direct futimens.
        // For now, use the fd-based approach via utimensat with null path.
        // Actually, Linux allows utimensat(fd, NULL, ...) to operate on the fd.
        cvt(unsafe {
            vfs::utimensat(self.fd, core::ptr::null(), ts.as_ptr(), 0)
        })?;
        Ok(())
    }
}

impl fmt::Debug for File {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("File").field("fd", &self.fd).finish()
    }
}

// --- DirBuilder ---

impl DirBuilder {
    pub fn new() -> DirBuilder {
        DirBuilder { mode: 0o777 }
    }

    pub fn mkdir(&self, path: &Path) -> io::Result<()> {
        run_path_with_cstr(path, &|path| {
            cvt(unsafe { vfs::mkdir(path.as_ptr() as *const u8, self.mode) })?;
            Ok(())
        })
    }

    #[allow(dead_code)]
    pub fn set_mode(&mut self, mode: u32) {
        self.mode = mode;
    }
}

// --- Free functions ---

pub fn readdir(path: &Path) -> io::Result<ReadDir> {
    run_path_with_cstr(path, &|p| {
        let fd = cvt(unsafe {
            vfs::openat(AT_FDCWD, p.as_ptr() as *const u8, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0)
        })? as i32;

        let mut buf = Vec::new();
        let mut tmp = vec![0u8; 4096];
        loop {
            let n = cvt(unsafe { vfs::getdents64(fd, tmp.as_mut_ptr(), tmp.len()) })?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n as usize]);
        }
        unsafe { vfs::close(fd); }

        let root = path.to_path_buf();
        Ok(ReadDir { inner: Arc::new(InnerReadDir { root, buf }), pos: 0 })
    })
}

pub fn unlink(path: &Path) -> io::Result<()> {
    run_path_with_cstr(path, &|p| {
        cvt(unsafe { vfs::unlink(p.as_ptr() as *const u8) })?;
        Ok(())
    })
}

pub fn rename(old: &Path, new: &Path) -> io::Result<()> {
    run_path_with_cstr(old, &|old| {
        run_path_with_cstr(new, &|new| {
            cvt(unsafe { vfs::rename(old.as_ptr() as *const u8, new.as_ptr() as *const u8) })?;
            Ok(())
        })
    })
}

pub fn set_perm(path: &Path, perm: FilePermissions) -> io::Result<()> {
    run_path_with_cstr(path, &|p| {
        cvt(unsafe { vfs::chmod(p.as_ptr() as *const u8, perm.mode) })?;
        Ok(())
    })
}

pub fn set_times(path: &Path, times: FileTimes) -> io::Result<()> {
    run_path_with_cstr(path, &|p| {
        let ts = times_to_timespec(&times);
        cvt(unsafe {
            vfs::utimensat(AT_FDCWD, p.as_ptr() as *const u8, ts.as_ptr(), 0)
        })?;
        Ok(())
    })
}

pub fn set_times_nofollow(path: &Path, times: FileTimes) -> io::Result<()> {
    run_path_with_cstr(path, &|p| {
        let ts = times_to_timespec(&times);
        cvt(unsafe {
            vfs::utimensat(
                AT_FDCWD,
                p.as_ptr() as *const u8,
                ts.as_ptr(),
                AT_SYMLINK_NOFOLLOW,
            )
        })?;
        Ok(())
    })
}

pub fn rmdir(path: &Path) -> io::Result<()> {
    run_path_with_cstr(path, &|p| {
        cvt(unsafe { vfs::rmdir(p.as_ptr() as *const u8) })?;
        Ok(())
    })
}

pub fn remove_dir_all(path: &Path) -> io::Result<()> {
    crate::sys::fs::common::remove_dir_all(path)
}

pub fn readlink(path: &Path) -> io::Result<PathBuf> {
    run_path_with_cstr(path, &|p| {
        let mut buf = vec![0u8; 256];
        loop {
            let n =
                cvt(unsafe { vfs::readlink(p.as_ptr() as *const u8, buf.as_mut_ptr(), buf.len()) })?
                    as usize;
            if n < buf.len() {
                buf.truncate(n);
                return Ok(PathBuf::from(OsString::from_vec(buf)));
            }
            // Buffer was too small, double and retry.
            buf.resize(buf.len() * 2, 0);
        }
    })
}

pub fn symlink(original: &Path, link: &Path) -> io::Result<()> {
    run_path_with_cstr(original, &|original| {
        run_path_with_cstr(link, &|link| {
            cvt(unsafe {
                vfs::symlink(original.as_ptr() as *const u8, link.as_ptr() as *const u8)
            })?;
            Ok(())
        })
    })
}

pub fn link(src: &Path, dst: &Path) -> io::Result<()> {
    run_path_with_cstr(src, &|src| {
        run_path_with_cstr(dst, &|dst| {
            cvt(unsafe { vfs::link(src.as_ptr() as *const u8, dst.as_ptr() as *const u8) })?;
            Ok(())
        })
    })
}

pub fn stat(path: &Path) -> io::Result<FileAttr> {
    run_path_with_cstr(path, &|p| {
        let mut st = unsafe { core::mem::zeroed::<vfs::Stat>() };
        cvt(unsafe { vfs::stat(p.as_ptr() as *const u8, &mut st) })?;
        Ok(FileAttr { stat: st })
    })
}

pub fn lstat(path: &Path) -> io::Result<FileAttr> {
    run_path_with_cstr(path, &|p| {
        let mut st = unsafe { core::mem::zeroed::<vfs::Stat>() };
        cvt(unsafe { vfs::lstat(p.as_ptr() as *const u8, &mut st) })?;
        Ok(FileAttr { stat: st })
    })
}

pub fn canonicalize(path: &Path) -> io::Result<PathBuf> {
    // vibix does not have realpath; do a simple absolute-path resolution.
    let mut result = if path.is_absolute() {
        PathBuf::new()
    } else {
        crate::env::current_dir()?
    };
    for component in path.components() {
        match component {
            crate::path::Component::RootDir => {
                result.push("/");
            }
            crate::path::Component::ParentDir => {
                result.pop();
            }
            crate::path::Component::CurDir => {}
            crate::path::Component::Normal(c) => {
                result.push(c);
                // Check that the path component exists and resolve symlinks.
                let meta = lstat(&result)?;
                if meta.file_type().is_symlink() {
                    let target = readlink(&result)?;
                    result.pop();
                    if target.is_absolute() {
                        result = target;
                    } else {
                        result.push(target);
                    }
                }
            }
            crate::path::Component::Prefix(_) => unreachable!(),
        }
    }
    Ok(result)
}

pub fn copy(from: &Path, to: &Path) -> io::Result<u64> {
    crate::sys::fs::common::copy(from, to)
}

pub fn exists(path: &Path) -> io::Result<bool> {
    match stat(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

// --- Helpers ---

fn times_to_timespec(times: &FileTimes) -> [vfs::Timespec; 2] {
    let mut ts = [
        vfs::Timespec { tv_sec: 0, tv_nsec: UTIME_OMIT },
        vfs::Timespec { tv_sec: 0, tv_nsec: UTIME_OMIT },
    ];
    if let Some(accessed) = times.accessed {
        let (sec, nsec) = accessed.to_timespec();
        ts[0] = vfs::Timespec { tv_sec: sec, tv_nsec: nsec };
    }
    if let Some(modified) = times.modified {
        let (sec, nsec) = modified.to_timespec();
        ts[1] = vfs::Timespec { tv_sec: sec, tv_nsec: nsec };
    }
    ts
}
