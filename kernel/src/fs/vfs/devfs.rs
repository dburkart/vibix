//! `devfs` — synthetic character-device filesystem mounted at `/dev`.
//!
//! Implements RFC 0002 item 8/15. Provides the four standard character
//! devices userspace expects:
//!
//! | Path            | major | minor | Behaviour |
//! |-----------------|-------|-------|-----------|
//! | `/dev/null`     | 1     | 3     | reads return EOF; writes consume silently |
//! | `/dev/zero`     | 1     | 5     | reads fill with 0x00; writes consume silently |
//! | `/dev/console`  | 5     | 1     | reads/writes go through COM1 serial |
//! | `/dev/tty`      | 5     | 0     | alias for `/dev/console` |
//!
//! The device set is fixed at mount time, so the directory inode uses a
//! simple `match` lookup rather than a `BTreeMap`.
//!
//! ## Inode numbering
//!
//! Inode numbers are assigned per-mount from a global atomic base so
//! that two simultaneous mounts get distinct `st_ino` values:
//!
//! | Inode | ino offset |
//! |-------|-----------|
//! | root  | base + 0  |
//! | null  | base + 1  |
//! | zero  | base + 2  |
//! | console | base + 3 |
//! | tty   | base + 4  |
//!
//! ## Locking
//!
//! The filesystem is read-only from the VFS perspective (no create/unlink/
//! rename). All device state is either stateless (null, zero) or
//! delegated to the serial singleton which manages its own lock, so
//! devfs carries no per-inode locks beyond what `Inode` itself provides.

use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicU64, Ordering};

use super::inode::{Inode, InodeKind, InodeMeta};
use super::mount_table::alloc_fs_id;
use super::open_file::OpenFile;
use super::ops::{
    meta_into_stat, FileOps, FileSystem, InodeOps, MountSource, Stat, StatFs, SuperOps,
};
use super::super_block::{SbFlags, SuperBlock};
use super::MountFlags;

use crate::fs::{EAGAIN, EISDIR, ENOENT};

// DEVFS_MAGIC — not in the Linux set but chosen to be distinct.
const DEVFS_MAGIC: u64 = 0x1373;

/// Linux `makedev(major, minor)` — encodes into the same 64-bit field
/// that userspace reads from `st_rdev`.
const fn makedev(major: u64, minor: u64) -> u64 {
    ((major & 0xfff) << 8) | (minor & 0xff) | ((minor & !0xff) << 12) | ((major & !0xfff) << 32)
}

// ---------------------------------------------------------------------------
// Global per-mount ino allocator
// ---------------------------------------------------------------------------

/// Each `DevFs::mount()` call grabs a base that is a multiple of 8,
/// then assigns inodes at base+0 … base+4.  Guarantees no two mounts
/// share ino values.
static NEXT_INO_BASE: AtomicU64 = AtomicU64::new(8);

fn alloc_ino_base() -> u64 {
    NEXT_INO_BASE.fetch_add(8, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Device kind tag
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DevKind {
    Null,
    Zero,
    Console,
    Tty,
}

// ---------------------------------------------------------------------------
// Root-directory inode ops
// ---------------------------------------------------------------------------

/// `InodeOps` for the `/dev` directory.  The child set is fixed; we
/// store the four device `Arc<Inode>` values directly.
struct DevfsDirOps {
    null: Arc<Inode>,
    zero: Arc<Inode>,
    console: Arc<Inode>,
    tty: Arc<Inode>,
    sb: Weak<SuperBlock>,
}

impl InodeOps for DevfsDirOps {
    fn lookup(&self, _dir: &Inode, name: &[u8]) -> Result<Arc<Inode>, i64> {
        match name {
            b"null" => Ok(self.null.clone()),
            b"zero" => Ok(self.zero.clone()),
            b"console" => Ok(self.console.clone()),
            b"tty" => Ok(self.tty.clone()),
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

/// `FileOps` for the `/dev` directory — emits `.`, `..`, and the four
/// device entries via the `linux_dirent64` wire format.
struct DevfsDirFileOps {
    null_ino: u64,
    zero_ino: u64,
    console_ino: u64,
    tty_ino: u64,
}

impl FileOps for DevfsDirFileOps {
    fn read(&self, _f: &OpenFile, _buf: &mut [u8], _off: u64) -> Result<usize, i64> {
        Err(EISDIR)
    }

    #[allow(unused_assignments)]
    fn getdents(&self, f: &OpenFile, buf: &mut [u8], cookie: &mut u64) -> Result<usize, i64> {
        // cookie = count of virtual entries already consumed.
        // Absolute positions: 0 = ".",  1 = "..",  2 = null,  3 = zero,
        //                     4 = console,  5 = tty.
        let dir_ino = f.inode.ino;
        let mut written = 0usize;
        let start = *cookie;

        // Emit entry at absolute position `pos` if it hasn't been consumed yet.
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
        maybe_emit!(self.null_ino, 2 /* DT_CHR */, b"null");
        maybe_emit!(self.zero_ino, 2 /* DT_CHR */, b"zero");
        maybe_emit!(self.console_ino, 2 /* DT_CHR */, b"console");
        maybe_emit!(self.tty_ino, 2 /* DT_CHR */, b"tty");

        Ok(written)
    }
}

// ---------------------------------------------------------------------------
// Device inode ops
// ---------------------------------------------------------------------------

/// `InodeOps` + `FileOps` carrier for a single character device.
struct DevfsDevOps {
    kind: DevKind,
    sb: Weak<SuperBlock>,
}

impl InodeOps for DevfsDevOps {
    fn getattr(&self, inode: &Inode, out: &mut Stat) -> Result<(), i64> {
        let sb = self.sb.upgrade().ok_or(ENOENT)?;
        let meta = inode.meta.read();
        meta_into_stat(&meta, inode.kind, sb.fs_id.0, inode.ino, out);
        Ok(())
    }
}

impl FileOps for DevfsDevOps {
    fn read(&self, _f: &OpenFile, buf: &mut [u8], _off: u64) -> Result<usize, i64> {
        match self.kind {
            DevKind::Null => Ok(0), // EOF
            DevKind::Zero => {
                buf.fill(0);
                Ok(buf.len())
            }
            DevKind::Console | DevKind::Tty => {
                // Non-blocking drain from the COM1 RX ring.
                for (i, byte) in buf.iter_mut().enumerate() {
                    match crate::serial::try_read_byte() {
                        Some(b) => *byte = b,
                        None => {
                            return if i == 0 { Err(EAGAIN) } else { Ok(i) };
                        }
                    }
                }
                Ok(buf.len())
            }
        }
    }

    fn write(&self, _f: &OpenFile, buf: &[u8], _off: u64) -> Result<usize, i64> {
        match self.kind {
            DevKind::Null | DevKind::Zero => Ok(buf.len()), // sink
            DevKind::Console | DevKind::Tty => {
                serial_write_bytes(buf);
                Ok(buf.len())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SuperOps impl
// ---------------------------------------------------------------------------

struct DevfsSuperOps {
    sb: Weak<SuperBlock>,
}

impl SuperOps for DevfsSuperOps {
    fn root_inode(&self) -> Arc<Inode> {
        self.sb
            .upgrade()
            .expect("devfs: SuperBlock dropped")
            .root
            .get()
            .expect("devfs: root not initialized")
            .clone()
    }

    fn statfs(&self) -> Result<StatFs, i64> {
        Ok(StatFs {
            f_type: DEVFS_MAGIC,
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

/// `DevFs` — stateless factory; one global instance, one `SuperBlock`
/// per `mount()` call.
pub struct DevFs;

impl FileSystem for DevFs {
    fn name(&self) -> &'static str {
        "devfs"
    }

    fn mount(&self, _source: MountSource<'_>, _flags: MountFlags) -> Result<Arc<SuperBlock>, i64> {
        let fs_id = alloc_fs_id();
        let ino_base = alloc_ino_base();

        let sb = Arc::new_cyclic(|weak_sb: &Weak<SuperBlock>| {
            // Allocate all five inodes up front so the root dir ops can
            // hold strong references to the four device inodes.

            let mk_dev = |ino: u64, kind: DevKind, rdev: u64| -> Arc<Inode> {
                let ops = Arc::new(DevfsDevOps {
                    kind,
                    sb: weak_sb.clone(),
                });
                let meta = InodeMeta {
                    mode: 0o666,
                    nlink: 1,
                    rdev,
                    blksize: 4096,
                    ..Default::default()
                };
                Arc::new(Inode::new(
                    ino,
                    weak_sb.clone(),
                    ops.clone() as Arc<dyn InodeOps>,
                    ops as Arc<dyn FileOps>,
                    InodeKind::Chr,
                    meta,
                ))
            };

            let null_inode = mk_dev(ino_base + 1, DevKind::Null, makedev(1, 3));
            let zero_inode = mk_dev(ino_base + 2, DevKind::Zero, makedev(1, 5));
            let console_inode = mk_dev(ino_base + 3, DevKind::Console, makedev(5, 1));
            let tty_inode = mk_dev(ino_base + 4, DevKind::Tty, makedev(5, 0));

            let root_dir_ops = Arc::new(DevfsDirOps {
                null: null_inode.clone(),
                zero: zero_inode.clone(),
                console: console_inode.clone(),
                tty: tty_inode.clone(),
                sb: weak_sb.clone(),
            });
            let root_file_ops = Arc::new(DevfsDirFileOps {
                null_ino: null_inode.ino,
                zero_ino: zero_inode.ino,
                console_ino: console_inode.ino,
                tty_ino: tty_inode.ino,
            });
            let root_meta = InodeMeta {
                mode: 0o555,
                nlink: 2,
                blksize: 4096,
                ..Default::default()
            };
            let root_inode = Arc::new(Inode::new(
                ino_base,
                weak_sb.clone(),
                root_dir_ops as Arc<dyn InodeOps>,
                root_file_ops as Arc<dyn FileOps>,
                InodeKind::Dir,
                root_meta,
            ));

            let super_ops = Arc::new(DevfsSuperOps {
                sb: weak_sb.clone(),
            });
            let sb_inner = SuperBlock::new(
                fs_id,
                super_ops as Arc<dyn SuperOps>,
                "devfs",
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
// linux_dirent64 serialisation helper (mirrors ramfs::emit_dirent)
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
// Serial write helper (mirrors fs::mod::serial_write_bytes — must be
// duplicated here because that function is private to fs::mod)
// ---------------------------------------------------------------------------

fn serial_write_bytes(buf: &[u8]) {
    const COM1_DATA: u16 = 0x3F8;
    const COM1_LSR: u16 = 0x3F8 + 5;
    for &b in buf {
        unsafe {
            loop {
                let lsr: u8;
                core::arch::asm!(
                    "in al, dx",
                    out("al") lsr,
                    in("dx") COM1_LSR,
                    options(nomem, nostack, preserves_flags),
                );
                if lsr & 0x20 != 0 {
                    break;
                }
            }
            core::arch::asm!(
                "out dx, al",
                in("dx") COM1_DATA,
                in("al") b,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
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

    fn make_devfs() -> Arc<SuperBlock> {
        DevFs
            .mount(MountSource::None, MountFlags::default())
            .expect("devfs mount failed")
    }

    fn root_of(sb: &Arc<SuperBlock>) -> Arc<Inode> {
        sb.root.get().expect("root").clone()
    }

    fn open_inode(sb: &Arc<SuperBlock>, inode: Arc<Inode>) -> OpenFile {
        let guard = SbActiveGuard::try_acquire(sb).expect("SbActiveGuard");
        let dentry = Dentry::new_root(inode.clone());
        OpenFile::new(dentry, inode, sb.clone(), guard)
    }

    // ------------------------------------------------------------------
    // Mount / root
    // ------------------------------------------------------------------

    #[test]
    fn mount_gives_root_dir() {
        let sb = make_devfs();
        let root = root_of(&sb);
        assert_eq!(root.kind, InodeKind::Dir);
    }

    #[test]
    fn root_stat_mode_is_dir() {
        let sb = make_devfs();
        let root = root_of(&sb);
        let mut stat = Stat::default();
        root.ops.getattr(&root, &mut stat).expect("getattr");
        assert_eq!(stat.st_mode & 0xF000, 0o040_000); // S_IFDIR
    }

    // ------------------------------------------------------------------
    // Lookup
    // ------------------------------------------------------------------

    #[test]
    fn lookup_null() {
        let sb = make_devfs();
        let root = root_of(&sb);
        let null = root.ops.lookup(&root, b"null").expect("lookup null");
        assert_eq!(null.kind, InodeKind::Chr);
    }

    #[test]
    fn lookup_zero() {
        let sb = make_devfs();
        let root = root_of(&sb);
        let zero = root.ops.lookup(&root, b"zero").expect("lookup zero");
        assert_eq!(zero.kind, InodeKind::Chr);
    }

    #[test]
    fn lookup_console() {
        let sb = make_devfs();
        let root = root_of(&sb);
        let con = root.ops.lookup(&root, b"console").expect("lookup console");
        assert_eq!(con.kind, InodeKind::Chr);
    }

    #[test]
    fn lookup_tty() {
        let sb = make_devfs();
        let root = root_of(&sb);
        let tty = root.ops.lookup(&root, b"tty").expect("lookup tty");
        assert_eq!(tty.kind, InodeKind::Chr);
    }

    #[test]
    fn lookup_missing_is_enoent() {
        let sb = make_devfs();
        let root = root_of(&sb);
        assert_eq!(root.ops.lookup(&root, b"nosuchdev"), Err(ENOENT));
    }

    // ------------------------------------------------------------------
    // rdev / st_mode
    // ------------------------------------------------------------------

    #[test]
    fn null_rdev() {
        let sb = make_devfs();
        let root = root_of(&sb);
        let null = root.ops.lookup(&root, b"null").unwrap();
        let mut stat = Stat::default();
        null.ops.getattr(&null, &mut stat).unwrap();
        assert_eq!(stat.st_rdev, makedev(1, 3));
        assert_eq!(stat.st_mode & 0xF000, 0o020_000); // S_IFCHR
    }

    #[test]
    fn zero_rdev() {
        let sb = make_devfs();
        let root = root_of(&sb);
        let zero = root.ops.lookup(&root, b"zero").unwrap();
        let mut stat = Stat::default();
        zero.ops.getattr(&zero, &mut stat).unwrap();
        assert_eq!(stat.st_rdev, makedev(1, 5));
    }

    #[test]
    fn console_rdev() {
        let sb = make_devfs();
        let root = root_of(&sb);
        let con = root.ops.lookup(&root, b"console").unwrap();
        let mut stat = Stat::default();
        con.ops.getattr(&con, &mut stat).unwrap();
        assert_eq!(stat.st_rdev, makedev(5, 1));
    }

    #[test]
    fn tty_rdev() {
        let sb = make_devfs();
        let root = root_of(&sb);
        let tty = root.ops.lookup(&root, b"tty").unwrap();
        let mut stat = Stat::default();
        tty.ops.getattr(&tty, &mut stat).unwrap();
        assert_eq!(stat.st_rdev, makedev(5, 0));
    }

    // ------------------------------------------------------------------
    // /dev/null read/write
    // ------------------------------------------------------------------

    #[test]
    fn null_read_is_eof() {
        let sb = make_devfs();
        let root = root_of(&sb);
        let null = root.ops.lookup(&root, b"null").unwrap();
        let f = open_inode(&sb, null);
        let mut buf = [0xffu8; 16];
        assert_eq!(f.inode.file_ops.read(&f, &mut buf, 0), Ok(0));
    }

    #[test]
    fn null_write_is_accepted() {
        let sb = make_devfs();
        let root = root_of(&sb);
        let null = root.ops.lookup(&root, b"null").unwrap();
        let f = open_inode(&sb, null);
        assert_eq!(f.inode.file_ops.write(&f, b"hello", 0), Ok(5));
    }

    // ------------------------------------------------------------------
    // /dev/zero read/write
    // ------------------------------------------------------------------

    #[test]
    fn zero_read_fills_zeros() {
        let sb = make_devfs();
        let root = root_of(&sb);
        let zero = root.ops.lookup(&root, b"zero").unwrap();
        let f = open_inode(&sb, zero);
        let mut buf = [0xffu8; 16];
        let n = f.inode.file_ops.read(&f, &mut buf, 0).expect("read");
        assert_eq!(n, 16);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn zero_write_is_accepted() {
        let sb = make_devfs();
        let root = root_of(&sb);
        let zero = root.ops.lookup(&root, b"zero").unwrap();
        let f = open_inode(&sb, zero);
        assert_eq!(f.inode.file_ops.write(&f, b"anything", 0), Ok(8));
    }

    // ------------------------------------------------------------------
    // ino stability
    // ------------------------------------------------------------------

    #[test]
    fn ino_stable_across_lookups() {
        let sb = make_devfs();
        let root = root_of(&sb);
        let a = root.ops.lookup(&root, b"null").unwrap();
        let b = root.ops.lookup(&root, b"null").unwrap();
        assert_eq!(a.ino, b.ino);
    }

    // ------------------------------------------------------------------
    // getdents
    // ------------------------------------------------------------------

    #[test]
    fn getdents_lists_six_entries() {
        // Expect: ".", "..", "null", "zero", "console", "tty"
        let sb = make_devfs();
        let root = root_of(&sb);
        let f = open_inode(&sb, root);
        let mut buf = [0u8; 512];
        let mut cookie = 0u64;
        let n = f
            .inode
            .file_ops
            .getdents(&f, &mut buf, &mut cookie)
            .expect("getdents");
        assert!(n > 0);
        assert_eq!(cookie, 6);
    }

    // ------------------------------------------------------------------
    // statfs
    // ------------------------------------------------------------------

    #[test]
    fn statfs_returns_devfs_magic() {
        let sb = make_devfs();
        let stats = sb.ops.statfs().expect("statfs");
        assert_eq!(stats.f_type, DEVFS_MAGIC);
    }

    // ------------------------------------------------------------------
    // distinct mounts get distinct inos
    // ------------------------------------------------------------------

    #[test]
    fn two_mounts_have_distinct_root_inos() {
        let sb1 = make_devfs();
        let sb2 = make_devfs();
        let r1 = root_of(&sb1);
        let r2 = root_of(&sb2);
        assert_ne!(r1.ino, r2.ino);
    }
}
