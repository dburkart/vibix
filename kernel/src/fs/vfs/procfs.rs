//! `procfs` — synthetic filesystem mounted at `/proc`.
//!
//! Provides composable kernel-state data to userspace as virtual files,
//! following the Linux `/proc` convention.  Each entry synthesises its
//! content on every `read`; there is no backing storage.
//!
//! ## Initial entries
//!
//! | Path                    | Content                                |
//! |-------------------------|----------------------------------------|
//! | `/proc/uptime`          | seconds since boot, idle seconds       |
//! | `/proc/meminfo`         | `MemTotal`, `MemFree`, `MemAvailable`  |
//! | `/proc/cpuinfo`         | vendor, model, family, flags           |
//! | `/proc/version`         | kernel name + git SHA + build date     |
//! | `/proc/self/status`     | current task pid, ppid, state, uid … |
//! | `/proc/<pid>/cmdline`   | null-terminated argv of named task     |
//!
//! ## Directory listing
//!
//! `getdents64` on `/proc` yields the static entries plus one directory
//! per live pid.
//!
//! ## Inode numbering
//!
//! Static entries get sequential ino values from a per-mount base.
//! Per-pid directory and file inodes are computed deterministically:
//!   - `/proc/<pid>` directory: `ino_base + PID_DIR_INO_BASE + pid * 2`
//!   - `/proc/<pid>/cmdline`:   `ino_base + PID_DIR_INO_BASE + pid * 2 + 1`
//!
//! The `self` symlink is resolved by the directory ops to the calling
//! task's pid directory.

use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};

use super::inode::{Inode, InodeKind, InodeMeta};
use super::mount_table::alloc_fs_id;
use super::open_file::OpenFile;
use super::ops::{
    meta_into_stat, FileOps, FileSystem, InodeOps, MountSource, Stat, StatFs, SuperOps,
};
use super::super_block::{SbFlags, SuperBlock};
use super::MountFlags;

use crate::fs::{EISDIR, ENOENT};

const PROCFS_MAGIC: u64 = 0x9fa0; // matches Linux PROC_SUPER_MAGIC

// Ino slots for static entries within a mount's base.
const INO_ROOT: u64 = 0;
const INO_UPTIME: u64 = 1;
const INO_MEMINFO: u64 = 2;
const INO_CPUINFO: u64 = 3;
const INO_VERSION: u64 = 4;
const INO_SELF: u64 = 5; // "self" symlink-like directory
                         // Per-pid entries start here:
const PID_DIR_INO_BASE: u64 = 1024;

// ---------------------------------------------------------------------------
// Global per-mount ino allocator
// ---------------------------------------------------------------------------

static NEXT_INO_BASE: AtomicU64 = AtomicU64::new(0x1_0000);

fn alloc_ino_base() -> u64 {
    NEXT_INO_BASE.fetch_add(0x10_0000, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Content generators
// ---------------------------------------------------------------------------

/// Generate `/proc/uptime` content.
fn gen_uptime() -> String {
    let ns = crate::time::uptime_ns();
    let secs = ns / 1_000_000_000;
    let frac = (ns % 1_000_000_000) / 10_000_000; // centiseconds
                                                  // idle time = uptime (no idle task accounting yet)
    let mut s = String::with_capacity(32);
    let _ = write!(s, "{}.{:02} {}.{:02}\n", secs, frac, secs, frac);
    s
}

/// Generate `/proc/meminfo` content.
fn gen_meminfo() -> String {
    let mut s = String::with_capacity(128);
    #[cfg(target_os = "none")]
    {
        let total_bytes = crate::mem::total_usable_bytes();
        let free_frames = crate::mem::frame::free_frames() as u64;
        let free_bytes = free_frames * 4096;
        let total_kb = total_bytes / 1024;
        let free_kb = free_bytes / 1024;
        let _ = write!(s, "MemTotal:       {:>8} kB\n", total_kb);
        let _ = write!(s, "MemFree:        {:>8} kB\n", free_kb);
        let _ = write!(s, "MemAvailable:   {:>8} kB\n", free_kb);
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = write!(s, "MemTotal:              0 kB\n");
        let _ = write!(s, "MemFree:               0 kB\n");
        let _ = write!(s, "MemAvailable:          0 kB\n");
    }
    s
}

/// Generate `/proc/cpuinfo` content.
fn gen_cpuinfo() -> String {
    let mut s = String::with_capacity(256);
    let _ = write!(s, "processor\t: 0\n");
    let _ = write!(s, "model name\t: {}\n", crate::cpu::brand());

    // Emit detected feature flags.
    let _ = write!(s, "flags\t\t:");
    use crate::cpu::Feature;
    let flags: &[(Feature, &str)] = &[
        (Feature::Sse, "sse"),
        (Feature::Sse2, "sse2"),
        (Feature::Sse4_1, "sse4_1"),
        (Feature::Sse4_2, "sse4_2"),
        (Feature::Avx, "avx"),
        (Feature::Avx2, "avx2"),
        (Feature::Xsave, "xsave"),
        (Feature::Pat, "pat"),
        (Feature::Smep, "smep"),
        (Feature::Smap, "smap"),
        (Feature::Fsgsbase, "fsgsbase"),
        (Feature::Rdtscp, "rdtscp"),
        (Feature::Popcnt, "popcnt"),
        (Feature::Rdrand, "rdrand"),
        (Feature::Rdseed, "rdseed"),
        (Feature::Lzcnt, "lzcnt"),
    ];
    for &(feat, name) in flags {
        if crate::cpu::has(feat) {
            let _ = write!(s, " {}", name);
        }
    }
    let _ = write!(s, "\n");
    s
}

/// Generate `/proc/version` content.
fn gen_version() -> String {
    let mut s = String::with_capacity(128);
    let _ = write!(
        s,
        "{} version {} ({}) {}\n",
        crate::build_info::KERNEL_NAME,
        crate::build_info::RELEASE,
        crate::build_info::GIT_SHA,
        crate::build_info::BUILD_TIMESTAMP,
    );
    s
}

/// Which static proc entry does this file represent?
#[derive(Clone, Copy, Debug)]
enum ProcEntry {
    Uptime,
    Meminfo,
    Cpuinfo,
    Version,
}

/// Generate `/proc/self/status` (or `/proc/<pid>/status`) content.
///
/// Returns `Err(ENOENT)` when the pid no longer exists in the task table.
fn gen_status(pid: usize) -> Result<String, i64> {
    let mut s = String::with_capacity(256);
    let mut found = false;
    crate::task::for_each_task(|info| {
        if info.id == pid {
            found = true;
            let state_str = match info.state {
                crate::task::TaskStateView::Running => "R (running)",
                crate::task::TaskStateView::Ready => "R (ready)",
                crate::task::TaskStateView::Blocked => "S (sleeping)",
            };
            let _ = write!(s, "Name:\tvibix-task-{}\n", pid);
            let _ = write!(s, "State:\t{}\n", state_str);
            let _ = write!(s, "Pid:\t{}\n", pid);
            let _ = write!(s, "PPid:\t0\n"); // no ppid tracking yet
            let _ = write!(s, "Uid:\t0\t0\t0\t0\n");
            let _ = write!(s, "Gid:\t0\t0\t0\t0\n");
            let _ = write!(s, "Threads:\t1\n");
        }
    });
    if found {
        Ok(s)
    } else {
        Err(ENOENT)
    }
}

/// Generate `/proc/<pid>/cmdline` content (NUL-terminated).
///
/// Returns `Err(ENOENT)` when the pid no longer exists in the task table,
/// so the caller can surface the error rather than returning an empty read.
fn gen_cmdline(pid: usize) -> Result<Vec<u8>, i64> {
    // vibix does not yet track argv per task; return the task name
    // as a single NUL-terminated argument.
    let mut found = false;
    crate::task::for_each_task(|info| {
        if info.id == pid {
            found = true;
        }
    });
    if found {
        let mut v = Vec::new();
        let name = alloc::format!("vibix-task-{}", pid);
        v.extend_from_slice(name.as_bytes());
        v.push(0); // NUL terminator
        Ok(v)
    } else {
        Err(ENOENT)
    }
}

// ---------------------------------------------------------------------------
// Root-directory inode ops
// ---------------------------------------------------------------------------

/// InodeOps for the `/proc` directory. Static entries are looked up by
/// name; numeric names are resolved to per-pid sub-directories when the
/// pid exists in the task table.
struct ProcfsDirOps {
    ino_base: u64,
    uptime: Arc<Inode>,
    meminfo: Arc<Inode>,
    cpuinfo: Arc<Inode>,
    version: Arc<Inode>,
    sb: Weak<SuperBlock>,
}

impl ProcfsDirOps {
    /// Build an inode for `/proc/<pid>` on the fly.
    fn make_pid_dir(&self, pid: usize) -> Arc<Inode> {
        let ino = self.ino_base + PID_DIR_INO_BASE + (pid as u64) * 2;
        let ops = Arc::new(ProcPidDirOps {
            pid,
            ino_base: self.ino_base,
            sb: self.sb.clone(),
        });
        Arc::new(Inode::new(
            ino,
            self.sb.clone(),
            ops.clone() as Arc<dyn InodeOps>,
            ops as Arc<dyn FileOps>,
            InodeKind::Dir,
            InodeMeta {
                mode: 0o555,
                nlink: 2,
                blksize: 4096,
                ..Default::default()
            },
        ))
    }

    /// Check if a pid exists in the task table.
    fn pid_exists(pid: usize) -> bool {
        let mut found = false;
        crate::task::for_each_task(|info| {
            if info.id == pid {
                found = true;
            }
        });
        found
    }
}

impl InodeOps for ProcfsDirOps {
    fn lookup(&self, _dir: &Inode, name: &[u8]) -> Result<Arc<Inode>, i64> {
        match name {
            b"uptime" => Ok(self.uptime.clone()),
            b"meminfo" => Ok(self.meminfo.clone()),
            b"cpuinfo" => Ok(self.cpuinfo.clone()),
            b"version" => Ok(self.version.clone()),
            b"self" => {
                // "self" resolves to the current task's pid directory.
                // On the kernel target, read the running task's ID from
                // the scheduler. In host tests there is no scheduler, so
                // fall back to pid 0.
                #[cfg(target_os = "none")]
                let pid = {
                    let mut current_pid = 0usize;
                    crate::task::for_each_task(|info| {
                        if info.state == crate::task::TaskStateView::Running {
                            current_pid = info.id;
                        }
                    });
                    current_pid
                };
                #[cfg(not(target_os = "none"))]
                let pid = 0usize;
                Ok(self.make_pid_dir(pid))
            }
            _ => {
                // Try to parse as a numeric pid.
                let s = core::str::from_utf8(name).map_err(|_| ENOENT)?;
                let pid: usize = s.parse().map_err(|_| ENOENT)?;
                if Self::pid_exists(pid) {
                    Ok(self.make_pid_dir(pid))
                } else {
                    Err(ENOENT)
                }
            }
        }
    }

    fn getattr(&self, inode: &Inode, out: &mut Stat) -> Result<(), i64> {
        let sb = self.sb.upgrade().ok_or(ENOENT)?;
        let meta = inode.meta.read();
        meta_into_stat(&meta, inode.kind, sb.fs_id.0, inode.ino, out);
        Ok(())
    }
}

/// FileOps for the `/proc` root directory — getdents emits static entries
/// plus one directory per live pid.
struct ProcfsDirFileOps {
    ino_base: u64,
    uptime_ino: u64,
    meminfo_ino: u64,
    cpuinfo_ino: u64,
    version_ino: u64,
}

impl FileOps for ProcfsDirFileOps {
    fn read(&self, _f: &OpenFile, _buf: &mut [u8], _off: u64) -> Result<usize, i64> {
        Err(EISDIR)
    }

    #[allow(unused_assignments)]
    fn getdents(&self, f: &OpenFile, buf: &mut [u8], cookie: &mut u64) -> Result<usize, i64> {
        let dir_ino = f.inode.ino;
        let mut written = 0usize;
        let start = *cookie;

        // Collect live pids upfront so we have a stable snapshot.
        let mut pids = Vec::new();
        crate::task::for_each_task(|info| {
            pids.push(info.id);
        });

        let mut pos: u64 = 0;

        macro_rules! maybe_emit {
            ($ino:expr, $d_type:expr, $name:expr) => {{
                if pos >= start {
                    let consumed = emit_dirent(buf, written, $ino, pos + 1, $d_type, $name);
                    if consumed == 0 {
                        return Ok(written);
                    }
                    written += consumed;
                    *cookie = pos + 1;
                }
                pos += 1;
            }};
        }

        maybe_emit!(dir_ino, 4 /* DT_DIR */, b".");
        maybe_emit!(dir_ino, 4 /* DT_DIR */, b"..");
        maybe_emit!(self.uptime_ino, 8 /* DT_REG */, b"uptime");
        maybe_emit!(self.meminfo_ino, 8 /* DT_REG */, b"meminfo");
        maybe_emit!(self.cpuinfo_ino, 8 /* DT_REG */, b"cpuinfo");
        maybe_emit!(self.version_ino, 8 /* DT_REG */, b"version");
        maybe_emit!(self.ino_base + INO_SELF, 4 /* DT_DIR */, b"self");

        // Per-pid directories.
        for &pid in &pids {
            let pid_ino = self.ino_base + PID_DIR_INO_BASE + (pid as u64) * 2;
            let name = alloc::format!("{}", pid);
            maybe_emit!(pid_ino, 4 /* DT_DIR */, name.as_bytes());
        }

        Ok(written)
    }
}

// ---------------------------------------------------------------------------
// Static file inode ops (uptime, meminfo, cpuinfo, version)
// ---------------------------------------------------------------------------

struct ProcfsStaticOps {
    entry: ProcEntry,
    sb: Weak<SuperBlock>,
}

impl InodeOps for ProcfsStaticOps {
    fn getattr(&self, inode: &Inode, out: &mut Stat) -> Result<(), i64> {
        let sb = self.sb.upgrade().ok_or(ENOENT)?;
        let meta = inode.meta.read();
        meta_into_stat(&meta, inode.kind, sb.fs_id.0, inode.ino, out);
        Ok(())
    }
}

impl FileOps for ProcfsStaticOps {
    fn read(&self, _f: &OpenFile, buf: &mut [u8], off: u64) -> Result<usize, i64> {
        let content = match self.entry {
            ProcEntry::Uptime => gen_uptime(),
            ProcEntry::Meminfo => gen_meminfo(),
            ProcEntry::Cpuinfo => gen_cpuinfo(),
            ProcEntry::Version => gen_version(),
        };
        read_from_bytes(content.as_bytes(), buf, off)
    }
}

// ---------------------------------------------------------------------------
// Per-pid directory ops (/proc/<pid>/)
// ---------------------------------------------------------------------------

struct ProcPidDirOps {
    pid: usize,
    ino_base: u64,
    sb: Weak<SuperBlock>,
}

impl InodeOps for ProcPidDirOps {
    fn lookup(&self, _dir: &Inode, name: &[u8]) -> Result<Arc<Inode>, i64> {
        match name {
            b"status" => {
                let ino = self.ino_base + PID_DIR_INO_BASE + (self.pid as u64) * 2 + 1;
                let ops = Arc::new(ProcPidFileOps {
                    pid: self.pid,
                    kind: PidFileKind::Status,
                    sb: self.sb.clone(),
                });
                Ok(Arc::new(Inode::new(
                    ino,
                    self.sb.clone(),
                    ops.clone() as Arc<dyn InodeOps>,
                    ops as Arc<dyn FileOps>,
                    InodeKind::Reg,
                    InodeMeta {
                        mode: 0o444,
                        nlink: 1,
                        blksize: 4096,
                        ..Default::default()
                    },
                )))
            }
            b"cmdline" => {
                // Use a distinct ino — offset by a large amount to avoid
                // collisions with the status file.
                let ino = self.ino_base + PID_DIR_INO_BASE + 0x8_0000 + (self.pid as u64) * 2;
                let ops = Arc::new(ProcPidFileOps {
                    pid: self.pid,
                    kind: PidFileKind::Cmdline,
                    sb: self.sb.clone(),
                });
                Ok(Arc::new(Inode::new(
                    ino,
                    self.sb.clone(),
                    ops.clone() as Arc<dyn InodeOps>,
                    ops as Arc<dyn FileOps>,
                    InodeKind::Reg,
                    InodeMeta {
                        mode: 0o444,
                        nlink: 1,
                        blksize: 4096,
                        ..Default::default()
                    },
                )))
            }
            _ => Err(ENOENT),
        }
    }

    fn getattr(&self, inode: &Inode, out: &mut Stat) -> Result<(), i64> {
        let sb = self.sb.upgrade().ok_or(ENOENT)?;
        let meta = inode.meta.read();
        meta_into_stat(&meta, inode.kind, sb.fs_id.0, inode.ino, out);
        Ok(())
    }
}

impl FileOps for ProcPidDirOps {
    fn read(&self, _f: &OpenFile, _buf: &mut [u8], _off: u64) -> Result<usize, i64> {
        Err(EISDIR)
    }

    #[allow(unused_assignments)]
    fn getdents(&self, f: &OpenFile, buf: &mut [u8], cookie: &mut u64) -> Result<usize, i64> {
        let dir_ino = f.inode.ino;
        let mut written = 0usize;
        let start = *cookie;
        let mut pos: u64 = 0;

        let status_ino = self.ino_base + PID_DIR_INO_BASE + (self.pid as u64) * 2 + 1;
        let cmdline_ino = self.ino_base + PID_DIR_INO_BASE + 0x8_0000 + (self.pid as u64) * 2;

        macro_rules! maybe_emit {
            ($ino:expr, $d_type:expr, $name:expr) => {{
                if pos >= start {
                    let consumed = emit_dirent(buf, written, $ino, pos + 1, $d_type, $name);
                    if consumed == 0 {
                        return Ok(written);
                    }
                    written += consumed;
                    *cookie = pos + 1;
                }
                pos += 1;
            }};
        }

        maybe_emit!(dir_ino, 4 /* DT_DIR */, b".");
        maybe_emit!(dir_ino, 4 /* DT_DIR */, b"..");
        maybe_emit!(status_ino, 8 /* DT_REG */, b"status");
        maybe_emit!(cmdline_ino, 8 /* DT_REG */, b"cmdline");

        Ok(written)
    }
}

// ---------------------------------------------------------------------------
// Per-pid file ops (status, cmdline)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum PidFileKind {
    Status,
    Cmdline,
}

struct ProcPidFileOps {
    pid: usize,
    kind: PidFileKind,
    sb: Weak<SuperBlock>,
}

impl InodeOps for ProcPidFileOps {
    fn getattr(&self, inode: &Inode, out: &mut Stat) -> Result<(), i64> {
        let sb = self.sb.upgrade().ok_or(ENOENT)?;
        let meta = inode.meta.read();
        meta_into_stat(&meta, inode.kind, sb.fs_id.0, inode.ino, out);
        Ok(())
    }
}

impl FileOps for ProcPidFileOps {
    fn read(&self, _f: &OpenFile, buf: &mut [u8], off: u64) -> Result<usize, i64> {
        match self.kind {
            PidFileKind::Status => {
                let content = gen_status(self.pid)?;
                read_from_bytes(content.as_bytes(), buf, off)
            }
            PidFileKind::Cmdline => {
                let content = gen_cmdline(self.pid)?;
                read_from_bytes(&content, buf, off)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: read a slice into a user buffer with offset
// ---------------------------------------------------------------------------

fn read_from_bytes(data: &[u8], buf: &mut [u8], off: u64) -> Result<usize, i64> {
    let off = off as usize;
    if off >= data.len() {
        return Ok(0);
    }
    let remaining = &data[off..];
    let n = remaining.len().min(buf.len());
    buf[..n].copy_from_slice(&remaining[..n]);
    Ok(n)
}

// ---------------------------------------------------------------------------
// SuperOps impl
// ---------------------------------------------------------------------------

struct ProcfsSuperOps {
    sb: Weak<SuperBlock>,
}

impl SuperOps for ProcfsSuperOps {
    fn root_inode(&self) -> Arc<Inode> {
        self.sb
            .upgrade()
            .expect("procfs: SuperBlock dropped")
            .root
            .get()
            .expect("procfs: root not initialized")
            .clone()
    }

    fn statfs(&self) -> Result<StatFs, i64> {
        Ok(StatFs {
            f_type: PROCFS_MAGIC,
            f_bsize: 4096,
            f_namelen: super::NAME_MAX as u64,
            ..Default::default()
        })
    }

    fn unmount(&self) {}
}

// ---------------------------------------------------------------------------
// FileSystem factory
// ---------------------------------------------------------------------------

/// `ProcFs` — stateless factory; one `SuperBlock` per `mount()` call.
pub struct ProcFs;

impl FileSystem for ProcFs {
    fn name(&self) -> &'static str {
        "procfs"
    }

    fn mount(&self, _source: MountSource<'_>, _flags: MountFlags) -> Result<Arc<SuperBlock>, i64> {
        let fs_id = alloc_fs_id();
        let ino_base = alloc_ino_base();

        let sb = Arc::new_cyclic(|weak_sb: &Weak<SuperBlock>| {
            let mk_static = |ino_off: u64, entry: ProcEntry| -> Arc<Inode> {
                let ops = Arc::new(ProcfsStaticOps {
                    entry,
                    sb: weak_sb.clone(),
                });
                let meta = InodeMeta {
                    mode: 0o444,
                    nlink: 1,
                    blksize: 4096,
                    ..Default::default()
                };
                Arc::new(Inode::new(
                    ino_base + ino_off,
                    weak_sb.clone(),
                    ops.clone() as Arc<dyn InodeOps>,
                    ops as Arc<dyn FileOps>,
                    InodeKind::Reg,
                    meta,
                ))
            };

            let uptime_inode = mk_static(INO_UPTIME, ProcEntry::Uptime);
            let meminfo_inode = mk_static(INO_MEMINFO, ProcEntry::Meminfo);
            let cpuinfo_inode = mk_static(INO_CPUINFO, ProcEntry::Cpuinfo);
            let version_inode = mk_static(INO_VERSION, ProcEntry::Version);

            let root_dir_ops = Arc::new(ProcfsDirOps {
                ino_base,
                uptime: uptime_inode.clone(),
                meminfo: meminfo_inode.clone(),
                cpuinfo: cpuinfo_inode.clone(),
                version: version_inode.clone(),
                sb: weak_sb.clone(),
            });
            let root_file_ops = Arc::new(ProcfsDirFileOps {
                ino_base,
                uptime_ino: uptime_inode.ino,
                meminfo_ino: meminfo_inode.ino,
                cpuinfo_ino: cpuinfo_inode.ino,
                version_ino: version_inode.ino,
            });
            let root_meta = InodeMeta {
                mode: 0o555,
                nlink: 2,
                blksize: 4096,
                ..Default::default()
            };
            let root_inode = Arc::new(Inode::new(
                ino_base + INO_ROOT,
                weak_sb.clone(),
                root_dir_ops as Arc<dyn InodeOps>,
                root_file_ops as Arc<dyn FileOps>,
                InodeKind::Dir,
                root_meta,
            ));

            let super_ops = Arc::new(ProcfsSuperOps {
                sb: weak_sb.clone(),
            });
            let sb_inner = SuperBlock::new(
                fs_id,
                super_ops as Arc<dyn SuperOps>,
                "procfs",
                4096,
                SbFlags::default(),
            );
            sb_inner.root.call_once(|| root_inode);
            sb_inner
        });

        Ok(sb)
    }
}

// ---------------------------------------------------------------------------
// linux_dirent64 serialisation helper (mirrors devfs::emit_dirent)
// ---------------------------------------------------------------------------

fn emit_dirent(
    buf: &mut [u8],
    offset: usize,
    d_ino: u64,
    d_off: u64,
    d_type: u8,
    name: &[u8],
) -> usize {
    let header = 19usize;
    let raw = header + name.len() + 1;
    let reclen = (raw + 7) & !7;

    let dest = match buf.get_mut(offset..offset + reclen) {
        Some(s) => s,
        None => return 0,
    };

    dest.fill(0);
    dest[0..8].copy_from_slice(&d_ino.to_ne_bytes());
    dest[8..16].copy_from_slice(&d_off.to_ne_bytes());
    dest[16..18].copy_from_slice(&(reclen as u16).to_ne_bytes());
    dest[18] = d_type;
    dest[19..19 + name.len()].copy_from_slice(name);

    reclen
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::vfs::dentry::Dentry;
    use crate::fs::vfs::open_file::OpenFile;
    use crate::fs::vfs::super_block::SbActiveGuard;
    use crate::fs::vfs::{MountFlags, MountSource};

    fn make_procfs() -> Arc<SuperBlock> {
        ProcFs
            .mount(MountSource::None, MountFlags::default())
            .expect("procfs mount failed")
    }

    fn root_of(sb: &Arc<SuperBlock>) -> Arc<Inode> {
        sb.root.get().expect("root").clone()
    }

    fn open_inode(sb: &Arc<SuperBlock>, inode: Arc<Inode>) -> Arc<OpenFile> {
        let guard = SbActiveGuard::try_acquire(sb).expect("SbActiveGuard");
        let dentry = Dentry::new_root(inode.clone());
        OpenFile::new(
            dentry,
            inode.clone(),
            inode.file_ops.clone(),
            sb.clone(),
            0,
            guard,
        )
    }

    // ------------------------------------------------------------------
    // Mount / root
    // ------------------------------------------------------------------

    #[test]
    fn mount_gives_root_dir() {
        let sb = make_procfs();
        let root = root_of(&sb);
        assert_eq!(root.kind, InodeKind::Dir);
    }

    #[test]
    fn root_stat_mode_is_dir() {
        let sb = make_procfs();
        let root = root_of(&sb);
        let mut stat = Stat::default();
        root.ops.getattr(&root, &mut stat).expect("getattr");
        assert_eq!(stat.st_mode & 0xF000, 0o040_000); // S_IFDIR
    }

    // ------------------------------------------------------------------
    // Lookup
    // ------------------------------------------------------------------

    #[test]
    fn lookup_uptime() {
        let sb = make_procfs();
        let root = root_of(&sb);
        let uptime = root.ops.lookup(&root, b"uptime").expect("lookup uptime");
        assert_eq!(uptime.kind, InodeKind::Reg);
    }

    #[test]
    fn lookup_meminfo() {
        let sb = make_procfs();
        let root = root_of(&sb);
        let meminfo = root.ops.lookup(&root, b"meminfo").expect("lookup meminfo");
        assert_eq!(meminfo.kind, InodeKind::Reg);
    }

    #[test]
    fn lookup_cpuinfo() {
        let sb = make_procfs();
        let root = root_of(&sb);
        let cpuinfo = root.ops.lookup(&root, b"cpuinfo").expect("lookup cpuinfo");
        assert_eq!(cpuinfo.kind, InodeKind::Reg);
    }

    #[test]
    fn lookup_version() {
        let sb = make_procfs();
        let root = root_of(&sb);
        let version = root.ops.lookup(&root, b"version").expect("lookup version");
        assert_eq!(version.kind, InodeKind::Reg);
    }

    #[test]
    fn lookup_missing_is_enoent() {
        let sb = make_procfs();
        let root = root_of(&sb);
        assert_eq!(root.ops.lookup(&root, b"nosuchfile"), Err(ENOENT));
    }

    // ------------------------------------------------------------------
    // Read static entries
    // ------------------------------------------------------------------

    #[test]
    fn read_uptime_contains_dot() {
        let sb = make_procfs();
        let root = root_of(&sb);
        let uptime = root.ops.lookup(&root, b"uptime").unwrap();
        let f = open_inode(&sb, uptime);
        let mut buf = [0u8; 256];
        let n = f.inode.file_ops.read(&f, &mut buf, 0).expect("read");
        assert!(n > 0);
        let content = core::str::from_utf8(&buf[..n]).expect("utf8");
        // Uptime format: "NNN.NN NNN.NN\n"
        assert!(content.contains('.'));
    }

    #[test]
    fn read_meminfo_contains_memtotal() {
        let sb = make_procfs();
        let root = root_of(&sb);
        let meminfo = root.ops.lookup(&root, b"meminfo").unwrap();
        let f = open_inode(&sb, meminfo);
        let mut buf = [0u8; 512];
        let n = f.inode.file_ops.read(&f, &mut buf, 0).expect("read");
        let content = core::str::from_utf8(&buf[..n]).expect("utf8");
        assert!(content.contains("MemTotal:"));
    }

    #[test]
    fn read_cpuinfo_contains_processor() {
        let sb = make_procfs();
        let root = root_of(&sb);
        let cpuinfo = root.ops.lookup(&root, b"cpuinfo").unwrap();
        let f = open_inode(&sb, cpuinfo);
        let mut buf = [0u8; 512];
        let n = f.inode.file_ops.read(&f, &mut buf, 0).expect("read");
        let content = core::str::from_utf8(&buf[..n]).expect("utf8");
        assert!(content.contains("processor"));
    }

    #[test]
    fn read_version_contains_vibix() {
        let sb = make_procfs();
        let root = root_of(&sb);
        let version = root.ops.lookup(&root, b"version").unwrap();
        let f = open_inode(&sb, version);
        let mut buf = [0u8; 512];
        let n = f.inode.file_ops.read(&f, &mut buf, 0).expect("read");
        let content = core::str::from_utf8(&buf[..n]).expect("utf8");
        assert!(content.contains("vibix"));
    }

    #[test]
    fn read_with_offset_returns_suffix() {
        let sb = make_procfs();
        let root = root_of(&sb);
        let version = root.ops.lookup(&root, b"version").unwrap();
        let f = open_inode(&sb, version);
        let mut buf1 = [0u8; 512];
        let n1 = f.inode.file_ops.read(&f, &mut buf1, 0).expect("read");
        let mut buf2 = [0u8; 512];
        let n2 = f.inode.file_ops.read(&f, &mut buf2, 5).expect("read");
        assert_eq!(n2, n1 - 5);
        assert_eq!(&buf1[5..n1], &buf2[..n2]);
    }

    #[test]
    fn read_past_end_returns_zero() {
        let sb = make_procfs();
        let root = root_of(&sb);
        let version = root.ops.lookup(&root, b"version").unwrap();
        let f = open_inode(&sb, version);
        let mut buf = [0u8; 512];
        let n = f.inode.file_ops.read(&f, &mut buf, 10000).expect("read");
        assert_eq!(n, 0);
    }

    // ------------------------------------------------------------------
    // getdents — static entries
    // ------------------------------------------------------------------

    #[test]
    fn getdents_has_static_entries() {
        let sb = make_procfs();
        let root = root_of(&sb);
        let f = open_inode(&sb, root);
        let mut buf = [0u8; 2048];
        let mut cookie = 0u64;
        let n = f
            .inode
            .file_ops
            .getdents(&f, &mut buf, &mut cookie)
            .expect("getdents");
        assert!(n > 0);
        // At minimum we have: . .. uptime meminfo cpuinfo version self
        // plus any live pids. Cookie should be >= 7.
        assert!(
            cookie >= 7,
            "expected at least 7 entries, got cookie={}",
            cookie
        );
    }

    // ------------------------------------------------------------------
    // statfs
    // ------------------------------------------------------------------

    #[test]
    fn statfs_returns_procfs_magic() {
        let sb = make_procfs();
        let stats = sb.ops.statfs().expect("statfs");
        assert_eq!(stats.f_type, PROCFS_MAGIC);
    }

    // ------------------------------------------------------------------
    // distinct mounts
    // ------------------------------------------------------------------

    #[test]
    fn two_mounts_have_distinct_root_inos() {
        let sb1 = make_procfs();
        let sb2 = make_procfs();
        let r1 = root_of(&sb1);
        let r2 = root_of(&sb2);
        assert_ne!(r1.ino, r2.ino);
    }

    // ------------------------------------------------------------------
    // read_from_bytes helper
    // ------------------------------------------------------------------

    #[test]
    fn read_from_bytes_basic() {
        let data = b"hello world";
        let mut buf = [0u8; 5];
        let n = read_from_bytes(data, &mut buf, 0).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"hello");
    }

    #[test]
    fn read_from_bytes_offset() {
        let data = b"hello world";
        let mut buf = [0u8; 20];
        let n = read_from_bytes(data, &mut buf, 6).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"world");
    }

    #[test]
    fn read_from_bytes_past_end() {
        let data = b"hi";
        let mut buf = [0u8; 20];
        let n = read_from_bytes(data, &mut buf, 100).unwrap();
        assert_eq!(n, 0);
    }
}
