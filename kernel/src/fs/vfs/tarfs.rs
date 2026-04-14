//! `tarfs` — read-only USTAR archive filesystem (RFC 0002 item 7/15).
//!
//! Mounts a tarball out of a static byte slice (the Limine ramdisk
//! module) and serves its contents through the VFS. The archive is
//! parsed once at mount time into an in-memory directory tree; no
//! page cache, no writes, no modification timestamps beyond what the
//! archive carries.
//!
//! USTAR layout: 512-byte header blocks interleaved with 512-byte
//! data blocks padded to the block boundary. Two consecutive zero
//! blocks (or EOF) terminate the archive. We accept both USTAR
//! (`ustar\0` magic) and GNU tar (`ustar  \0`) variants, and fall
//! back to v7 when no magic is present.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use super::inode::{Inode, InodeKind, InodeMeta};
use super::mount_table::alloc_fs_id;
use super::open_file::OpenFile;
use super::ops::{
    meta_into_stat, FileOps, FileSystem, InodeOps, MountSource, SetAttr, Stat, StatFs, SuperOps,
    Whence,
};
use super::super_block::{SbFlags, SuperBlock};
use super::MountFlags;
use crate::fs::{EINVAL, ENOENT, ENOTDIR};

const BLOCK: usize = 512;

/// Parsed contents of a single inode, keyed by `ino` in `TarSuper.nodes`.
enum NodeData {
    Dir { children: BTreeMap<Vec<u8>, u64> },
    Reg { offset: usize, len: usize },
    Link { target: Vec<u8> },
}

struct TarNode {
    kind: InodeKind,
    meta: InodeMeta,
    data: NodeData,
}

/// Per-mount state. The byte slice is `'static` (Limine ramdisk
/// module lives for the kernel's life) or borrowed from a test
/// fixture; either way we keep it as `(base, len)` so raw reads
/// don't require carrying a lifetime through every trait impl.
///
/// Unsafe `Send + Sync` impl: `base..base+len` is read-only, is
/// never mutated through this pointer, and aliasing is fine because
/// we only ever `copy_from_slice` out of it.
pub struct TarSuper {
    fs_id: u64,
    nodes: Vec<TarNode>,
    base: *const u8,
    len: usize,
    /// Back-reference to the owning `TarFs` so `unmount` can clear the
    /// `mounted` latch. `Weak` breaks the `TarFs → Arc<SuperBlock> →
    /// TarSuper → TarFs` cycle.
    owner: Weak<TarFs>,
}

unsafe impl Send for TarSuper {}
unsafe impl Sync for TarSuper {}

impl TarSuper {
    fn slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.base, self.len) }
    }

    fn node(&self, ino: u64) -> Result<&TarNode, i64> {
        let idx = ino as usize;
        if idx == 0 || idx >= self.nodes.len() {
            return Err(ENOENT);
        }
        Ok(&self.nodes[idx])
    }
}

impl SuperOps for TarSuper {
    fn root_inode(&self) -> Arc<Inode> {
        // Tests and the mount path both call `call_once` on
        // `sb.root` directly, so the generic VFS code path never
        // reaches here. Driver-internal callers should use the
        // published root dentry instead.
        unreachable!("tarfs pre-populates sb.root at mount time");
    }

    fn statfs(&self) -> Result<StatFs, i64> {
        Ok(StatFs {
            f_type: 0x7461_7266, // 'tarf'
            f_bsize: BLOCK as u64,
            f_blocks: (self.len / BLOCK) as u64,
            f_bfree: 0,
            f_bavail: 0,
            f_files: self.nodes.len().saturating_sub(1) as u64,
            f_ffree: 0,
            f_namelen: super::NAME_MAX as u64,
        })
    }

    fn unmount(&self) {
        // Release the single-mount latch on the owning TarFs so a
        // subsequent mount of the same instance can succeed. If the
        // owner is already gone the latch is irrelevant.
        if let Some(fs) = self.owner.upgrade() {
            fs.mounted.store(false, Ordering::SeqCst);
        }
    }
}

/// Shared `InodeOps` implementation for every tarfs inode. The
/// concrete behaviour branches on `dir.kind` and the backing node's
/// `NodeData`; we can't keep a per-inode trait object because VFS
/// stores ops behind `Arc<dyn InodeOps>` at construction time.
pub struct TarInodeOps {
    sb: Weak<TarSuper>,
}

impl TarInodeOps {
    fn super_(&self) -> Result<Arc<TarSuper>, i64> {
        self.sb.upgrade().ok_or(ENOENT)
    }
}

impl InodeOps for TarInodeOps {
    fn lookup(&self, dir: &Inode, name: &[u8]) -> Result<Arc<Inode>, i64> {
        if dir.kind != InodeKind::Dir {
            return Err(ENOTDIR);
        }
        let sup = self.super_()?;
        let node = sup.node(dir.ino)?;
        let children = match &node.data {
            NodeData::Dir { children } => children,
            _ => return Err(ENOTDIR),
        };
        let child_ino = children.get(name).copied().ok_or(ENOENT)?;
        build_inode(&sup, child_ino, dir.sb.clone())
    }

    fn getattr(&self, inode: &Inode, out: &mut Stat) -> Result<(), i64> {
        let sup = self.super_()?;
        let node = sup.node(inode.ino)?;
        let meta = node.meta;
        meta_into_stat(&meta, node.kind, sup.fs_id, inode.ino, out);
        Ok(())
    }

    fn setattr(&self, _inode: &Inode, _attr: &SetAttr) -> Result<(), i64> {
        // Read-only.
        Err(-30) // EROFS
    }

    fn readlink(&self, inode: &Inode, buf: &mut [u8]) -> Result<usize, i64> {
        let sup = self.super_()?;
        let node = sup.node(inode.ino)?;
        match &node.data {
            NodeData::Link { target } => {
                let n = core::cmp::min(buf.len(), target.len());
                buf[..n].copy_from_slice(&target[..n]);
                Ok(n)
            }
            _ => Err(EINVAL),
        }
    }
}

/// Shared `FileOps` for every tarfs inode.
pub struct TarFileOps {
    sb: Weak<TarSuper>,
}

impl TarFileOps {
    fn super_(&self) -> Result<Arc<TarSuper>, i64> {
        self.sb.upgrade().ok_or(ENOENT)
    }
}

impl FileOps for TarFileOps {
    fn read(&self, f: &OpenFile, buf: &mut [u8], off: u64) -> Result<usize, i64> {
        let sup = self.super_()?;
        let node = sup.node(f.inode.ino)?;
        let (offset, len) = match &node.data {
            NodeData::Reg { offset, len } => (*offset, *len),
            NodeData::Dir { .. } => return Err(-21), // EISDIR
            NodeData::Link { .. } => return Err(EINVAL),
        };
        if off as usize >= len {
            return Ok(0);
        }
        let remaining = len - off as usize;
        let n = core::cmp::min(buf.len(), remaining);
        let slice = sup.slice();
        buf[..n].copy_from_slice(&slice[offset + off as usize..][..n]);
        Ok(n)
    }

    fn seek(&self, _f: &OpenFile, whence: Whence, off: i64) -> Result<u64, i64> {
        // Only SEEK_SET is meaningful without an internal offset
        // here; lseek's real work happens in `OpenFile.offset`, so
        // we just validate and echo.
        match whence {
            Whence::Set if off >= 0 => Ok(off as u64),
            _ => Err(EINVAL),
        }
    }

    fn getdents(&self, f: &OpenFile, buf: &mut [u8], cookie: &mut u64) -> Result<usize, i64> {
        let sup = self.super_()?;
        let node = sup.node(f.inode.ino)?;
        let children = match &node.data {
            NodeData::Dir { children } => children,
            _ => return Err(ENOTDIR),
        };

        let start = *cookie as usize;
        let mut out = 0usize;
        for (idx, (name, &child_ino)) in children.iter().enumerate().skip(start) {
            let child_kind = sup.nodes[child_ino as usize].kind;
            let reclen = dirent_reclen(name.len());
            if out + reclen > buf.len() {
                break;
            }
            let entry = &mut buf[out..out + reclen];
            entry.fill(0);
            write_dirent(
                entry,
                child_ino,
                (idx as u64) + 1,
                reclen as u16,
                dtype_of(child_kind),
                name,
            );
            out += reclen;
            *cookie = (idx as u64) + 1;
        }
        Ok(out)
    }
}

/// `linux_dirent64` record length for a given name length, rounded
/// up to 8 bytes. Layout: u64 ino + u64 off + u16 reclen + u8 type +
/// name + NUL.
fn dirent_reclen(name_len: usize) -> usize {
    let base = 8 + 8 + 2 + 1 + name_len + 1;
    (base + 7) & !7
}

fn write_dirent(out: &mut [u8], ino: u64, off: u64, reclen: u16, dtype: u8, name: &[u8]) {
    out[0..8].copy_from_slice(&ino.to_le_bytes());
    out[8..16].copy_from_slice(&off.to_le_bytes());
    out[16..18].copy_from_slice(&reclen.to_le_bytes());
    out[18] = dtype;
    out[19..19 + name.len()].copy_from_slice(name);
    out[19 + name.len()] = 0;
    // Tail padding is zeroed by the caller (entry.fill(0)) before this call.
}

fn dtype_of(kind: InodeKind) -> u8 {
    match kind {
        InodeKind::Reg => 8,
        InodeKind::Dir => 4,
        InodeKind::Link => 10,
        InodeKind::Chr => 2,
        InodeKind::Blk => 6,
        InodeKind::Fifo => 1,
        InodeKind::Sock => 12,
    }
}

/// Construct a fresh `Arc<Inode>` for a tarfs entry. The VFS dentry
/// cache memoises the inode for the walk, so building one per
/// `lookup` call is cheap and avoids persistent Arc cycles between
/// the super-block and its inodes.
fn build_inode(sup: &Arc<TarSuper>, ino: u64, sb: Weak<SuperBlock>) -> Result<Arc<Inode>, i64> {
    let node = sup.node(ino)?;
    let ops: Arc<dyn InodeOps> = Arc::new(TarInodeOps {
        sb: Arc::downgrade(sup),
    });
    let file_ops: Arc<dyn FileOps> = Arc::new(TarFileOps {
        sb: Arc::downgrade(sup),
    });
    Ok(Arc::new(Inode::new(
        ino, sb, ops, file_ops, node.kind, node.meta,
    )))
}

// --- Parser ----------------------------------------------------------

#[derive(Default)]
struct RawEntry<'a> {
    name: Vec<u8>,
    typeflag: u8,
    size: u64,
    mode: u16,
    uid: u32,
    gid: u32,
    mtime: i64,
    linkname: &'a [u8],
}

/// Parse a single 512-byte header. Returns `Ok(None)` for a
/// zero-filled block (archive terminator) and `Err(EINVAL)` on
/// malformed fields.
fn parse_header(hdr: &[u8; BLOCK]) -> Result<Option<RawEntry<'_>>, i64> {
    if hdr.iter().all(|&b| b == 0) {
        return Ok(None);
    }
    if !checksum_ok(hdr) {
        return Err(EINVAL);
    }

    let name_raw = trim_nul(&hdr[0..100]);
    let prefix = trim_nul(&hdr[345..500]);
    let has_ustar = &hdr[257..263] == b"ustar\0" || &hdr[257..263] == b"ustar ";

    let mut name: Vec<u8> = Vec::new();
    if has_ustar && !prefix.is_empty() {
        name.extend_from_slice(prefix);
        name.push(b'/');
    }
    name.extend_from_slice(name_raw);

    let mode = parse_octal(&hdr[100..108])? as u16;
    let uid = parse_octal(&hdr[108..116])? as u32;
    let gid = parse_octal(&hdr[116..124])? as u32;
    let size = parse_octal(&hdr[124..136])?;
    let mtime = parse_octal(&hdr[136..148])? as i64;
    let typeflag = hdr[156];
    let linkname = trim_nul(&hdr[157..257]);

    Ok(Some(RawEntry {
        name,
        typeflag,
        size,
        mode,
        uid,
        gid,
        mtime,
        linkname,
    }))
}

fn trim_nul(s: &[u8]) -> &[u8] {
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    &s[..end]
}

/// USTAR checksum: unsigned sum of every header byte with the 8-byte
/// chksum field replaced by spaces. GNU tar historically also
/// wrote/accepted a signed interpretation; accept either so we stay
/// compatible with archives produced by ancient tools.
fn checksum_ok(hdr: &[u8; BLOCK]) -> bool {
    let stored = match parse_octal(&hdr[148..156]) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let mut unsigned: u64 = 0;
    let mut signed: i64 = 0;
    for (i, &b) in hdr.iter().enumerate() {
        let byte = if (148..156).contains(&i) { b' ' } else { b };
        unsigned += byte as u64;
        signed += byte as i8 as i64;
    }
    unsigned == stored || signed == stored as i64
}

/// Parse a NUL/space-terminated octal ASCII field.
fn parse_octal(field: &[u8]) -> Result<u64, i64> {
    let mut acc: u64 = 0;
    let mut saw_digit = false;
    for &b in field {
        match b {
            b'0'..=b'7' => {
                acc = acc.checked_mul(8).ok_or(EINVAL)?;
                acc = acc.checked_add((b - b'0') as u64).ok_or(EINVAL)?;
                saw_digit = true;
            }
            0 | b' ' => {
                if saw_digit {
                    return Ok(acc);
                }
            }
            _ => return Err(EINVAL),
        }
    }
    Ok(acc)
}

/// Walk the archive and build the node table. Ino 0 is unused; ino
/// 1 is always the root directory (auto-created if the archive
/// doesn't include an explicit `./` entry).
fn build_nodes(bytes: &[u8]) -> Result<Vec<TarNode>, i64> {
    let mut nodes: Vec<TarNode> = Vec::new();
    // ino 0: sentinel.
    nodes.push(TarNode {
        kind: InodeKind::Dir,
        meta: InodeMeta::default(),
        data: NodeData::Dir {
            children: BTreeMap::new(),
        },
    });
    // ino 1: root.
    nodes.push(TarNode {
        kind: InodeKind::Dir,
        meta: InodeMeta {
            mode: 0o755,
            nlink: 2,
            ..Default::default()
        },
        data: NodeData::Dir {
            children: BTreeMap::new(),
        },
    });

    let mut off = 0usize;
    let mut zero_blocks = 0usize;
    while off + BLOCK <= bytes.len() {
        let hdr: &[u8; BLOCK] = bytes[off..off + BLOCK].try_into().map_err(|_| EINVAL)?;
        off += BLOCK;

        let entry = match parse_header(hdr)? {
            None => {
                zero_blocks += 1;
                if zero_blocks >= 2 {
                    break;
                }
                continue;
            }
            Some(e) => {
                zero_blocks = 0;
                e
            }
        };

        let data_off = off;
        let size = entry.size as usize;
        off += (size + BLOCK - 1) & !(BLOCK - 1);
        if off > bytes.len() {
            return Err(EINVAL);
        }

        // Skip entries whose typeflag we don't handle (hard link,
        // fifo, block/char device, pax extensions, GNU long-name).
        match entry.typeflag {
            b'0' | 0 => install_file(&mut nodes, &entry, data_off, size)?,
            b'5' => install_dir(&mut nodes, &entry)?,
            b'2' => install_symlink(&mut nodes, &entry)?,
            _ => continue,
        }
    }
    Ok(nodes)
}

/// Split a path into its parent-dir chain plus final component, and
/// return the parent's ino, auto-creating any missing intermediate
/// directories along the way. Trailing `/` is stripped (directory
/// entries commonly arrive as `a/b/`).
fn split_parent<'a>(
    nodes: &mut Vec<TarNode>,
    path: &'a [u8],
) -> Result<Option<(u64, &'a [u8])>, i64> {
    let path = if path.ends_with(b"/") {
        &path[..path.len() - 1]
    } else {
        path
    };
    if path.is_empty() || path == b"." {
        return Ok(None);
    }

    let mut parent: u64 = 1;
    let mut last_start = 0usize;
    let mut i = 0usize;
    while i < path.len() {
        if path[i] == b'/' {
            let comp = &path[last_start..i];
            if !comp.is_empty() && comp != b"." {
                parent = ensure_dir_child(nodes, parent, comp)?;
            }
            last_start = i + 1;
        }
        i += 1;
    }
    let final_comp = &path[last_start..];
    if final_comp.is_empty() || final_comp == b"." {
        Ok(None)
    } else {
        Ok(Some((parent, final_comp)))
    }
}

fn ensure_dir_child(nodes: &mut Vec<TarNode>, parent: u64, name: &[u8]) -> Result<u64, i64> {
    if let NodeData::Dir { children } = &nodes[parent as usize].data {
        if let Some(&ino) = children.get(name) {
            if nodes[ino as usize].kind != InodeKind::Dir {
                return Err(EINVAL);
            }
            return Ok(ino);
        }
    } else {
        return Err(EINVAL);
    }
    let new_ino = nodes.len() as u64;
    nodes.push(TarNode {
        kind: InodeKind::Dir,
        meta: InodeMeta {
            mode: 0o755,
            nlink: 2,
            ..Default::default()
        },
        data: NodeData::Dir {
            children: BTreeMap::new(),
        },
    });
    if let NodeData::Dir { children } = &mut nodes[parent as usize].data {
        children.insert(name.to_vec(), new_ino);
    }
    Ok(new_ino)
}

fn install_file(
    nodes: &mut Vec<TarNode>,
    entry: &RawEntry<'_>,
    data_off: usize,
    size: usize,
) -> Result<(), i64> {
    let (parent, name) = match split_parent(nodes, &entry.name)? {
        None => return Ok(()),
        Some(v) => v,
    };
    let name_vec = name.to_vec();
    let new_ino = nodes.len() as u64;
    nodes.push(TarNode {
        kind: InodeKind::Reg,
        meta: InodeMeta {
            mode: entry.mode & 0o7_777,
            uid: entry.uid,
            gid: entry.gid,
            size: size as u64,
            nlink: 1,
            mtime: super::Timespec {
                sec: entry.mtime,
                nsec: 0,
            },
            blksize: BLOCK as u32,
            blocks: ((size + 511) / BLOCK) as u64,
            ..Default::default()
        },
        data: NodeData::Reg {
            offset: data_off,
            len: size,
        },
    });
    if let NodeData::Dir { children } = &mut nodes[parent as usize].data {
        children.insert(name_vec, new_ino);
    } else {
        return Err(EINVAL);
    }
    Ok(())
}

fn install_dir(nodes: &mut Vec<TarNode>, entry: &RawEntry<'_>) -> Result<(), i64> {
    // Directories in USTAR carry their own entry after possibly
    // being implied by earlier child paths. `ensure_dir_child` does
    // the right thing either way.
    let (parent, name) = match split_parent(nodes, &entry.name)? {
        None => return Ok(()),
        Some(v) => v,
    };
    let ino = ensure_dir_child(nodes, parent, name)?;
    let meta = &mut nodes[ino as usize].meta;
    meta.mode = entry.mode & 0o7_777;
    meta.uid = entry.uid;
    meta.gid = entry.gid;
    meta.mtime = super::Timespec {
        sec: entry.mtime,
        nsec: 0,
    };
    Ok(())
}

fn install_symlink(nodes: &mut Vec<TarNode>, entry: &RawEntry<'_>) -> Result<(), i64> {
    let (parent, name) = match split_parent(nodes, &entry.name)? {
        None => return Ok(()),
        Some(v) => v,
    };
    let name_vec = name.to_vec();
    let new_ino = nodes.len() as u64;
    nodes.push(TarNode {
        kind: InodeKind::Link,
        meta: InodeMeta {
            mode: 0o777,
            uid: entry.uid,
            gid: entry.gid,
            size: entry.linkname.len() as u64,
            nlink: 1,
            mtime: super::Timespec {
                sec: entry.mtime,
                nsec: 0,
            },
            ..Default::default()
        },
        data: NodeData::Link {
            target: entry.linkname.to_vec(),
        },
    });
    if let NodeData::Dir { children } = &mut nodes[parent as usize].data {
        children.insert(name_vec, new_ino);
    } else {
        return Err(EINVAL);
    }
    Ok(())
}

// --- Public entry point ---------------------------------------------

/// Read-only USTAR archive driver.
///
/// Constructed once per kernel boot and handed to `mount_table::mount`.
/// The archive source is supplied via [`MountSource::Static`] for
/// test fixtures and [`MountSource::RamdiskModule`] for the live
/// kernel (wiring in #240).
pub struct TarFs {
    mounted: AtomicBool,
    /// Self-reference. Populated by [`TarFs::new_arc`] so the
    /// `TarSuper` produced by `mount` can hold a `Weak<TarFs>` and
    /// clear `mounted` from `unmount` without a reference cycle.
    self_ref: Weak<TarFs>,
}

impl TarFs {
    /// Construct a TarFs instance. `new_arc` is the canonical
    /// constructor — the filesystem is designed to live inside an
    /// `Arc` (registered with the mount table as `Arc<dyn FileSystem>`),
    /// and the self-reference feeds the back-pointer in each
    /// `TarSuper` so `unmount` can release the single-mount latch.
    pub fn new_arc() -> Arc<Self> {
        Arc::new_cyclic(|weak| Self {
            mounted: AtomicBool::new(false),
            self_ref: weak.clone(),
        })
    }
}

impl FileSystem for TarFs {
    fn name(&self) -> &'static str {
        "tarfs"
    }

    fn mount(&self, source: MountSource<'_>, _flags: MountFlags) -> Result<Arc<SuperBlock>, i64> {
        // Validate source and parse the archive *before* taking the
        // single-mount latch. An invalid source or malformed archive
        // must not burn the TarFs instance — see issue #274.
        let (base, len): (*const u8, usize) = match source {
            MountSource::Static(bytes) => (bytes.as_ptr(), bytes.len()),
            MountSource::RamdiskModule(p, n) => (p, n),
            _ => return Err(EINVAL),
        };

        let bytes = unsafe { core::slice::from_raw_parts(base, len) };
        let nodes = build_nodes(bytes)?;

        // Parsing succeeded — claim the single-mount latch.
        if self
            .mounted
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(crate::fs::EBUSY);
        }

        let super_ops: Arc<TarSuper> = Arc::new(TarSuper {
            fs_id: alloc_fs_id().0,
            nodes,
            base,
            len,
            owner: self.self_ref.clone(),
        });

        let sb = Arc::new(SuperBlock::new(
            super::FsId(super_ops.fs_id),
            super_ops.clone(),
            "tarfs",
            BLOCK as u32,
            SbFlags::RDONLY,
        ));

        let root_inode = build_inode(&super_ops, 1, Arc::downgrade(&sb))?;
        sb.root.call_once(|| root_inode);
        Ok(sb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::vfs::ops::FileSystem as _;

    fn make_header(
        name: &[u8],
        size: u64,
        typeflag: u8,
        linkname: &[u8],
        mode: u16,
    ) -> [u8; BLOCK] {
        let mut h = [0u8; BLOCK];
        let n = core::cmp::min(name.len(), 100);
        h[..n].copy_from_slice(&name[..n]);
        write_octal(&mut h[100..108], mode as u64, 7);
        write_octal(&mut h[108..116], 0, 7); // uid
        write_octal(&mut h[116..124], 0, 7); // gid
        write_octal(&mut h[124..136], size, 11);
        write_octal(&mut h[136..148], 0, 11); // mtime
        h[156] = typeflag;
        let ln = core::cmp::min(linkname.len(), 100);
        h[157..157 + ln].copy_from_slice(&linkname[..ln]);
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");

        // Checksum last: sum with the chksum field spaces.
        h[148..156].copy_from_slice(b"        ");
        let sum: u64 = h.iter().map(|&b| b as u64).sum();
        write_octal(&mut h[148..155], sum, 6);
        h[155] = 0;
        h
    }

    fn write_octal(out: &mut [u8], mut v: u64, digits: usize) {
        for i in (0..digits).rev() {
            out[i] = b'0' + (v & 0o7) as u8;
            v >>= 3;
        }
        if out.len() > digits {
            out[digits] = 0;
        }
    }

    fn pad_block(data: &[u8]) -> Vec<u8> {
        let mut v = Vec::from(data);
        let pad = (BLOCK - (v.len() % BLOCK)) % BLOCK;
        v.extend(core::iter::repeat(0).take(pad));
        v
    }

    fn build_archive() -> Vec<u8> {
        let mut archive: Vec<u8> = Vec::new();

        // Directory a/
        archive.extend_from_slice(&make_header(b"a/", 0, b'5', b"", 0o755));

        // Regular a/hello containing "world"
        archive.extend_from_slice(&make_header(b"a/hello", 5, b'0', b"", 0o644));
        archive.extend_from_slice(&pad_block(b"world"));

        // Symlink a/link -> hello
        archive.extend_from_slice(&make_header(b"a/link", 0, b'2', b"hello", 0o777));

        // Two zero blocks terminator.
        archive.extend_from_slice(&[0u8; BLOCK * 2]);
        archive
    }

    /// Leak a `Vec<u8>` into a `&'static [u8]` so it can be passed as
    /// `MountSource::Static` in tests. The memory is intentionally never freed
    /// (test process lifetime).
    fn leak_archive(v: Vec<u8>) -> &'static [u8] {
        alloc::boxed::Box::leak(v.into_boxed_slice())
    }

    #[test]
    fn parse_checksum_roundtrip() {
        let h = make_header(b"x", 0, b'0', b"", 0o644);
        assert!(checksum_ok(&h));
    }

    #[test]
    fn mount_and_lookup() {
        let archive = leak_archive(build_archive());
        let fs = TarFs::new_arc();
        let sb = fs
            .mount(MountSource::Static(archive), MountFlags::default())
            .expect("mount");

        let root = sb.root.get().expect("root").clone();
        assert_eq!(root.kind, InodeKind::Dir);

        let a_inode = root.ops.lookup(&root, b"a").expect("lookup a");
        assert_eq!(a_inode.kind, InodeKind::Dir);

        let hello = a_inode
            .ops
            .lookup(&a_inode, b"hello")
            .expect("lookup hello");
        assert_eq!(hello.kind, InodeKind::Reg);
        assert_eq!(hello.meta.read().size, 5);

        let link = a_inode.ops.lookup(&a_inode, b"link").expect("lookup link");
        assert_eq!(link.kind, InodeKind::Link);

        // Missing name.
        assert_eq!(a_inode.ops.lookup(&a_inode, b"nope").err(), Some(ENOENT));
    }

    #[test]
    fn read_file_contents() {
        let archive = leak_archive(build_archive());
        let fs = TarFs::new_arc();
        let sb = fs
            .mount(MountSource::Static(archive), MountFlags::default())
            .expect("mount");
        let root = sb.root.get().unwrap().clone();
        let a = root.ops.lookup(&root, b"a").unwrap();
        let hello = a.ops.lookup(&a, b"hello").unwrap();

        // Synthesise an OpenFile without going through the syscall
        // layer: FileOps::read only touches `f.inode.ino`.
        let of = OpenFile {
            dentry: super::super::dentry::Dentry::new_root(hello.clone()),
            inode: hello.clone(),
            offset: crate::sync::BlockingMutex::new(0),
            flags: 0,
            ops: hello.file_ops.clone(),
            sb: sb.clone(),
        };
        // Pin sb_active so Drop's fetch_sub doesn't underflow.
        sb.sb_active.fetch_add(1, Ordering::SeqCst);

        let mut buf = [0u8; 16];
        let n = hello.file_ops.read(&of, &mut buf, 0).expect("read");
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], b"world");

        let n = hello.file_ops.read(&of, &mut buf, 3).expect("read tail");
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], b"ld");

        let n = hello.file_ops.read(&of, &mut buf, 5).expect("read eof");
        assert_eq!(n, 0);
    }

    #[test]
    fn readlink_returns_target() {
        let archive = leak_archive(build_archive());
        let fs = TarFs::new_arc();
        let sb = fs
            .mount(MountSource::Static(archive), MountFlags::default())
            .expect("mount");
        let root = sb.root.get().unwrap().clone();
        let a = root.ops.lookup(&root, b"a").unwrap();
        let link = a.ops.lookup(&a, b"link").unwrap();

        let mut buf = [0u8; 16];
        let n = link.ops.readlink(&link, &mut buf).expect("readlink");
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], b"hello");
    }

    #[test]
    fn getdents_enumerates_children() {
        let archive = leak_archive(build_archive());
        let fs = TarFs::new_arc();
        let sb = fs
            .mount(MountSource::Static(archive), MountFlags::default())
            .expect("mount");
        let root = sb.root.get().unwrap().clone();
        let a = root.ops.lookup(&root, b"a").unwrap();

        let of = OpenFile {
            dentry: super::super::dentry::Dentry::new_root(a.clone()),
            inode: a.clone(),
            offset: crate::sync::BlockingMutex::new(0),
            flags: 0,
            ops: a.file_ops.clone(),
            sb: sb.clone(),
        };
        sb.sb_active.fetch_add(1, Ordering::SeqCst);

        let mut buf = [0u8; 256];
        let mut cookie: u64 = 0;
        let n = a
            .file_ops
            .getdents(&of, &mut buf, &mut cookie)
            .expect("getdents");
        assert!(n > 0);
        // Two entries: hello and link.
        assert!(cookie >= 2);
    }

    #[test]
    fn malformed_header_rejected() {
        let mut archive = Vec::new();
        // Valid magic + bogus size field that isn't octal.
        let mut hdr = make_header(b"bad", 0, b'0', b"", 0o644);
        hdr[124] = b'Z'; // garbage in the size field
                         // Rewrite checksum around the tampered size.
        hdr[148..156].copy_from_slice(b"        ");
        let sum: u64 = hdr.iter().map(|&b| b as u64).sum();
        write_octal(&mut hdr[148..155], sum, 6);
        hdr[155] = 0;
        archive.extend_from_slice(&hdr);
        archive.extend_from_slice(&[0u8; BLOCK * 2]);

        let fs = TarFs::new_arc();
        let r = fs.mount(
            MountSource::Static(leak_archive(archive)),
            MountFlags::default(),
        );
        assert!(r.is_err());
    }

    /// A failed archive parse must not burn the `mounted` latch —
    /// callers should be free to retry with a valid source.
    #[test]
    fn mount_failure_allows_remount() {
        // Bad archive (same shape as `malformed_header_rejected`).
        let mut bad = Vec::new();
        let mut hdr = make_header(b"bad", 0, b'0', b"", 0o644);
        hdr[124] = b'Z';
        hdr[148..156].copy_from_slice(b"        ");
        let sum: u64 = hdr.iter().map(|&b| b as u64).sum();
        write_octal(&mut hdr[148..155], sum, 6);
        hdr[155] = 0;
        bad.extend_from_slice(&hdr);
        bad.extend_from_slice(&[0u8; BLOCK * 2]);

        let fs = TarFs::new_arc();
        assert!(fs
            .mount(
                MountSource::Static(leak_archive(bad)),
                MountFlags::default(),
            )
            .is_err());

        // Retry with a good archive: must succeed.
        let good = leak_archive(build_archive());
        fs.mount(MountSource::Static(good), MountFlags::default())
            .expect("remount after failed parse must succeed");
    }

    /// An unsupported `MountSource` variant must not burn the latch
    /// either — validation happens before the CAS.
    #[test]
    fn wrong_source_variant_allows_remount() {
        let fs = TarFs::new_arc();
        // `MountSource::None` is not accepted by tarfs.
        assert!(fs.mount(MountSource::None, MountFlags::default()).is_err());

        let good = leak_archive(build_archive());
        fs.mount(MountSource::Static(good), MountFlags::default())
            .expect("remount after wrong source must succeed");
    }

    /// After `SuperOps::unmount` runs, the latch must be cleared so
    /// the filesystem can be mounted again.
    #[test]
    fn unmount_allows_remount() {
        let fs = TarFs::new_arc();
        let archive = leak_archive(build_archive());
        let sb = fs
            .mount(MountSource::Static(archive), MountFlags::default())
            .expect("first mount");
        sb.ops.unmount();

        let archive2 = leak_archive(build_archive());
        fs.mount(MountSource::Static(archive2), MountFlags::default())
            .expect("remount after unmount must succeed");
    }

    /// A deep file entry whose intermediate directories are absent from
    /// the archive must still be resolvable — `split_parent` auto-creates
    /// the missing `a/` and `a/b/` directory nodes.
    #[test]
    fn implicit_parent_dirs_are_auto_created() {
        let mut archive: Vec<u8> = Vec::new();
        // Only a file entry; no explicit "a/" or "a/b/" headers.
        archive.extend_from_slice(&make_header(b"a/b/c.txt", 3, b'0', b"", 0o644));
        archive.extend_from_slice(&pad_block(b"hey"));
        archive.extend_from_slice(&[0u8; BLOCK * 2]);

        let fs = TarFs::new_arc();
        let sb = fs
            .mount(
                MountSource::Static(leak_archive(archive)),
                MountFlags::default(),
            )
            .expect("mount deep-file archive");

        let root = sb.root.get().unwrap().clone();
        let a = root.ops.lookup(&root, b"a").expect("auto-created a/");
        assert_eq!(a.kind, InodeKind::Dir);
        let b = a.ops.lookup(&a, b"b").expect("auto-created a/b/");
        assert_eq!(b.kind, InodeKind::Dir);
        let c = b.ops.lookup(&b, b"c.txt").expect("a/b/c.txt");
        assert_eq!(c.kind, InodeKind::Reg);
        assert_eq!(c.meta.read().size, 3);
    }

    /// While a mount is live the latch must refuse a second mount.
    #[test]
    fn double_mount_returns_ebusy() {
        let fs = TarFs::new_arc();
        let archive = leak_archive(build_archive());
        let _sb = fs
            .mount(MountSource::Static(archive), MountFlags::default())
            .expect("first mount");

        let archive2 = leak_archive(build_archive());
        let r = fs.mount(MountSource::Static(archive2), MountFlags::default());
        assert_eq!(r.err(), Some(crate::fs::EBUSY));
    }
}
