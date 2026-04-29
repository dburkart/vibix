---
rfc: 0006
title: Demand-Paged File mmap and Page Cache for ext2
status: Draft
created: 2026-04-28
---

# RFC 0006: Demand-Paged File mmap and Page Cache for ext2

## Abstract

Introduce a unified, page-granular **page cache** keyed by
`(InodeId, page_index)`, hang it off `Inode`, and add a `FileOps::mmap`
hook so userspace `mmap(2)` of ext2-backed regular files completes
instead of returning `ENODEV`. File-backed VMAs are serviced lazily by a
new `FileObject : VmObject` whose `fault` consults the page cache and
synthesises reads through the existing block buffer cache. The same
machinery turns the existing eager ELF loader into a demand-paged
loader, retiring the `PT_INTERP → ENOEXEC` execve gate and unblocking
the dynamic-linker work tracked separately.

## Motivation

RFC 0004 (ext2, merged via epic #537) deferred three coupled features:
the page cache, file-backed mmap, and `PT_INTERP`. As of today
`sys_mmap` rejects every `fd != -1` with `ENODEV`
(`kernel/src/arch/x86_64/syscall.rs:1366`) and `execve` of any ELF with
a `PT_INTERP` returns `ENOEXEC` (RFC 0004 Workstream F). That blocks:

- Any userspace program that `mmap(MAP_SHARED)`s a configuration file,
  database, or shared memory region — POSIX-conformance tooling
  (pjdfstest itself, fsstress) trips on this immediately.
- Any non-static binary. musl's dynamic loader, glibc's `ld-linux.so`,
  busybox's dynamic build, and every distro ELF reach `PT_INTERP`.
- Memory-pressure response. The buffer cache today caches only block
  reads issued by `FileOps::read`; the kernel cannot reclaim file data
  for read-mostly workloads without losing it on the next read.
- A unified writeback story. `MAP_SHARED` writes need to land at the
  same checkpoint as `write(2)`-issued dirty buffers — without a page
  cache there is no place to track them.

The right shape for this is one design document, not three: every
question of cache layering, locking, and writeback ordering recurs
identically across mmap, read, and execve. RFC 0006 fixes the
architecture and lets the three downstream epics ship as execution-only
work.

## Background

### What vibix has today (2026-04-28)

- **Block buffer cache** (`kernel/src/block/cache.rs`, RFC 0004
  Workstream C). CLOCK-Pro replacement, `(DeviceId, u64)` key, four
  normative invariants:
  1. eviction never touches a buffer with `Arc::strong_count > 1` (any
     external caller pin);
  2. eviction never touches `DIRTY | LOCKED_IO`;
  3. `bread` returns `ENOMEM` rather than synchronously flushing dirty
     buffers during eviction;
  4. single-cache-entry: only one `BufferHead` ever exists per
     `(dev, blk)`.
- **Per-mount writeback daemon** (`kernel/src/block/writeback.rs`).
  Default 30 s cadence, joined by `SuperOps::unmount`, runs under an
  `SbActiveGuard` that pins the superblock during the flush and is
  released across the sleep.
- **`VmObject` trait** (`kernel/src/mem/vmobject.rs`). The polymorphism
  point for "what backs this VMA?". `AnonObject` is the only
  implementation today; the trait already exposes `fault(offset,
  access)`, `clone_private`, `frame_at`, `truncate_from_page`, and
  `evict_range`.
- **VMA tree** (`kernel/src/mem/vmatree.rs`). `Vma { start, end,
  prot_user, prot_pte, share, object, object_offset, vma_flags }`,
  `Share::{Private, Shared}`, no separate `VmaKind::Cow` enum — CoW is
  resolved at the PTE layer (W bit stripped after fork; the page-fault
  resolver invokes `cow_copy_and_remap`).
- **Page-fault dispatch** (`kernel/src/mem/pf.rs` + `arch/x86_64/idt`).
  Pure-logic gates run first; `VmObject::fault` is invoked from the
  IRQ-disabled handler today, which is fine for `AnonObject` but is the
  central concern of this RFC.
- **Eager ELF loader** (`kernel/src/mem/loader.rs`,
  `kernel/src/mem/elf.rs`). Walks `PT_LOAD`, allocates frames, copies
  through the HHDM, installs final-protection PTEs. No `PT_INTERP`
  support; `INTERP_LOAD_BASE = 0x4000_0000` is reserved for a future
  loader.
- **VFS `FileOps`** (`kernel/src/fs/vfs/ops.rs`). Today: `read`,
  `write`, `seek`, `getdents`, `ioctl`, `flush`, `fsync`, `open`,
  `release`. No `mmap` hook.

### Prior art surveyed

- **Linux page cache** (`mm/filemap.c`, `mm/page-writeback.c`, "address
  space operations"). One `struct page` per 4 KiB physical frame, hung
  off an `address_space` rooted at `struct inode`. `i_mapping` is the
  XArray-keyed by file `pgoff`. `readahead`, `readpage`/`readpages`,
  `writepage`, `set_page_dirty`, `release_folio`, `migrate_folio`. The
  buffer head layer (`fs/buffer.c`) maps page-sized cache entries onto
  block-sized device entries through the `buffer_head` chain — this is
  the "buffer cache as backing store" model in concrete form.
- **FreeBSD VFS / VM** — `vnode_pager`, the unified page/buffer cache
  driven by Yokota & Dyson 1995. `b_bufobj` and `vm_object` share
  pages directly; the buffer cache is a window onto the VM page cache,
  not a separate pool. Anchor for the "unified" alternative.
- **Mach VM** — Rashid et al. 1988, "Machine-Independent Virtual Memory
  Management for Paged Uniprocessor and Multiprocessor Architectures".
  External pagers, demand-pageable memory objects, the
  `vm_object → memory_object` split that Linux's `address_space`
  inherited. Anchor for the formal model: a memory object is a
  contract over `(offset → page)` plus a writeback channel, and the
  pager need not live in the kernel.
- **SerenityOS** — `Kernel/Memory/InodeVMObject.cpp`,
  `Kernel/Memory/SharedInodeVMObject.cpp`,
  `Kernel/Memory/PrivateInodeVMObject.cpp`. Closer in spirit to vibix:
  one `InodeVMObject` per inode, pages owned by the inode rather than
  by a global cache. Demonstrates that the unified-cache model is
  optional — a per-inode object reaches feature parity for read,
  mmap, and demand-paged execve without a global radix tree.
- **Redox** — uses a pager service in userspace; not directly applicable
  to vibix's monolithic model but useful for the
  external-pager-as-memory-object framing.
- **Pillai et al. 2014, "All File Systems Are Not Created Equal"
  (OSDI)** — the empirical work behind the writeback-ordering arguments
  in RFC 0004 §rename. Same crash-consistency frame applies to
  msync(2) / writepage ordering on `MAP_SHARED`.
- **Bonwick & Adams 2001, "Magazines and Vmem"** — per-CPU caching
  layer that anyone considering scaling the page cache hot path under
  SMP eventually re-reads. Out of scope for this RFC (vibix is
  uniprocessor); cited so the SMP follow-up has a starting point.
- **Intel SDM Vol. 3A §4.10 "Caching Translation Information"**, §11
  PAT/MTRR, §28 VMX page-walk paths. Relevant to `MAP_SHARED` writes
  on dirty PTE bookkeeping and to the TLB-shootdown story when the
  cache evicts a page that is mapped into multiple address spaces.

### What is missing in vibix

1. No structural place to put a page-cache entry. `Inode` has no
   `mapping` field; `BlockCache` is keyed on `(DeviceId, blk)`, not on
   `(InodeId, pgoff)`.
2. No page-grain replacement story. The buffer cache is block-sized
   (block size `<= 4 KiB` typical, `1 KiB` for the standard rootfs
   image during early bring-up).
3. No `FileOps::mmap`. Even if a cache existed, there is nowhere to
   plug the inode-specific "produce a `VmObject` for this open file"
   hook.
4. No demand-fault path that can wait. `VmObject::fault` is called from
   an IRQ-disabled context today. A file fault must:
   (a) drop locks + re-enable interrupts before issuing block I/O,
   (b) park on a wait-queue while the I/O completes,
   (c) resume the fault under a fresh lock acquisition.
   None of that exists for `AnonObject` because anonymous faults never
   block on a device.
5. No writeback for a page cache. The per-mount writeback daemon
   walks the buffer cache; it does not know about page-cache entries.

## Design

### Overview

Three layers, top to bottom:

```
┌─────────────────────────────────────────────────────────┐
│  Page-fault handler (mem/pf.rs + arch/x86_64/idt)        │
│   ↓ resolve()                                            │
│  VmObject::fault(offset, access)                         │
│    AnonObject (today)        FileObject (this RFC)       │
│                                ↓ get_or_read_page()      │
│  PageCache (per-Inode)                                   │
│    ├── pages: BTreeMap<pgoff, Arc<CachePage>>           │
│    ├── dirty: BTreeSet<pgoff>                           │
│    └── ops: Arc<dyn AddressSpaceOps>  ← per-FS impl     │
│                                ↓ readpage(buf, pgoff)    │
│  AddressSpaceOps::readpage / writepage                   │
│   ↓ bread / mark_dirty / sync_dirty_buffer               │
│  BlockCache  (RFC 0004 — unchanged)                      │
│   ↓ BlockDevice::read_at / write_at                      │
│  virtio-blk / future drivers                             │
└─────────────────────────────────────────────────────────┘
```

The page cache is **separate** from the buffer cache. They compose by
the page cache invoking `bread` on miss to assemble a 4 KiB page from
one or more block-sized buffers; the page cache then stops touching the
buffer cache until eviction or writeback. RFC 0004's four normative
buffer-cache invariants are unchanged and uncontested by this design
(see §"Cache layering trade-off" for why this layering wins over
unified or buffer-cache-as-backing-store).

### Key data structures

#### `CachePage`

One page-sized entry. Lives behind `Arc<CachePage>` so VMAs and the
cache index can each hold a strong reference without a parallel
refcount.

```rust
pub struct CachePage {
    /// Physical frame containing the cached file data. Refcounted via
    /// the existing `mem::refcount` machinery — the cache holds one
    /// reference; every PTE mapping it holds one more.
    pub phys: u64,

    /// Page index = file_offset / 4096.
    pub pgoff: u64,

    /// State bits — see `PG_*` below. AtomicU8 so reads in the fault
    /// hot path don't take any lock.
    pub state: AtomicU8,

    /// Wait-queue for the IN_FLIGHT handshake. A second fault on the
    /// same page parks here until the original reader publishes UPTODATE.
    pub wait: WaitQueue,
}

// State bits.
pub const PG_UPTODATE:   u8 = 1 << 0;  // contents reflect on-disk image
pub const PG_DIRTY:      u8 = 1 << 1;  // mutated since last writeback
pub const PG_IN_FLIGHT:  u8 = 1 << 2;  // I/O issued, not yet complete
pub const PG_WRITEBACK:  u8 = 1 << 3;  // in writepage(), do not re-dirty
pub const PG_LOCKED:     u8 = 1 << 4;  // exclusive serialization for fill
```

`PG_IN_FLIGHT` and `PG_LOCKED` are distinct on purpose: `PG_LOCKED`
serialises the cache-fill handshake (only one task fills any given
page); `PG_IN_FLIGHT` advertises that a `readpage` is presently
issuing block I/O so other tasks know to park rather than spin.

#### `PageCache`

Per-inode container. Owned by `Inode` (a new `mapping` field gated by
`#[cfg(feature = "page_cache")]` until the migration completes).

```rust
pub struct PageCache {
    /// Sparse page index. BTreeMap is the same data structure used by
    /// AnonObject today; we deliberately match its locking discipline.
    inner: BlockingMutex<PageCacheInner>,

    /// Per-FS hook for backing I/O. Set at inode construction.
    ops: Arc<dyn AddressSpaceOps>,

    /// File size at the moment of last truncate / read-of-i_size.
    /// Faults past this offset return VmFault::OutOfRange (SIGBUS).
    /// Updated under `inner.lock()` together with the cache index.
    i_size: AtomicU64,

    /// Back-pointer to the InodeId for writeback enqueue.
    inode_id: InodeId,
}

struct PageCacheInner {
    pages: BTreeMap<u64, Arc<CachePage>>,
    dirty: BTreeSet<u64>,
}
```

The mutex is the existing `BlockingMutex` used elsewhere in vibix
(sleeps the current task on contention; **never** spins across a block
I/O). All long-running work — the actual `bread` / `write_at` — is
performed with the mutex *dropped*, the page locked via `PG_LOCKED`,
and any waiters parked on `CachePage::wait`. See §"Locking and
fault-path orchestration".

#### `AddressSpaceOps`

The per-filesystem hook. Concrete impls live with the FS driver
(`fs/ext2/aops.rs` for the first one).

```rust
pub trait AddressSpaceOps: Send + Sync {
    /// Populate `buf` (always 4096 bytes) with the on-disk contents
    /// of file page `pgoff`. May block on block I/O. Returns
    /// `Ok(bytes_filled)`; pages past EOF are zero-filled by the
    /// caller — the impl returns `Ok(0)` in that case.
    fn readpage(&self, pgoff: u64, buf: &mut [u8; 4096]) -> Result<usize, i64>;

    /// Write `buf` (4096 bytes) back to the file at `pgoff`. May
    /// block. Synchronous from the caller's perspective; impls drive
    /// the buffer cache's `mark_dirty` + `sync_dirty_buffer` chain.
    fn writepage(&self, pgoff: u64, buf: &[u8; 4096]) -> Result<(), i64>;

    /// Optional readahead hint. Default: no-op. ext2's impl issues
    /// up to RA_WINDOW (8 pages) of speculative readpages on a
    /// sequential-access miss.
    fn readahead(&self, _start: u64, _nr_pages: u32) {}

    /// Truncate-down hook. Called when `i_size` shrinks so the cache
    /// can drop pages past the new EOF before the FS frees the
    /// underlying blocks. Default: no-op (the cache walks itself).
    fn truncate_below(&self, _new_size: u64) {}
}
```

#### `FileObject` — the new `VmObject`

```rust
pub struct FileObject {
    /// The page cache to consult on faults. Arc so a `MAP_PRIVATE`
    /// CoW that mutates a page does so against a fresh copy without
    /// racing the cache.
    cache: Arc<PageCache>,

    /// Region [object_offset .. object_offset + len_pages*4096) of
    /// the file this VMA covers.
    file_offset_pages: u64,

    /// Size cap for SIGBUS-on-OOR (mirrors AnonObject::len_pages).
    len_pages: usize,

    /// MAP_SHARED vs MAP_PRIVATE. Determines whether write faults
    /// dirty the cache page (Shared) or trigger CoW into a fresh
    /// AnonObject-backed page (Private).
    share: Share,
}

impl VmObject for FileObject {
    fn fault(&self, offset: usize, access: Access) -> Result<u64, VmFault> {
        // 1. Bounds-check against len_pages.
        // 2. pgoff = file_offset_pages + (offset / 4096).
        // 3. Consult the page cache — on miss, call readpage().
        // 4. For Shared + Write: bump PG_DIRTY, enlist in cache.dirty.
        // 5. For Private + Write: do NOT touch the cache page. Return
        //    a VmFault::CoWNeeded sentinel; the resolver upgrades the
        //    PTE through cow_copy_and_remap exactly the way a fork-
        //    induced CoW does today.
        // (Pseudocode; full algorithm in §Algorithms.)
    }

    fn frame_at(&self, offset: usize) -> Option<u64> { /* page-cache lookup */ }
    fn clone_private(&self) -> Arc<dyn VmObject> { /* same cache, share = Private */ }
    fn truncate_from_page(&self, from: usize) { /* delegate to cache */ }
    fn evict_range(&self, first: usize, last: usize) { /* delegate */ }
    fn len_pages(&self) -> Option<usize> { Some(self.len_pages) }
}
```

#### `FileOps::mmap`

The new VFS hook:

```rust
pub trait FileOps: Send + Sync {
    /// ...existing methods...

    /// Produce a backing `VmObject` for the requested range. The
    /// returned object is plugged into the VMA tree by `sys_mmap`.
    /// Default returns `ENODEV` so non-mmappable FS types (devfs
    /// control nodes, sockets) keep today's behaviour.
    fn mmap(
        &self,
        _f: &OpenFile,
        _file_offset: u64,
        _len_pages: usize,
        _share: Share,
        _prot: ProtUser,
    ) -> Result<Arc<dyn VmObject>, i64> {
        Err(ENODEV)
    }
}
```

ext2's impl returns `Arc::new(FileObject { cache: inode.mapping.clone(), ... })`.
ramfs and tarfs override the default with a thin `AnonObject`-style
wrapper (their data is already in memory; no `AddressSpaceOps` needed).

### Algorithms and protocols

#### Page-fault path

```
fault(va, access):
    [pure-logic gates: SMAP, RSVD, canonical, prot_user] ── unchanged
    vma = vmatree.lookup(va)
    obj = vma.object  // either AnonObject or FileObject

    res = obj.fault(va - vma.start + vma.object_offset, access)
    match res:
      Ok(phys)               -> install PTE, flush TLB
      Err(VmFault::CoWNeeded) -> cow_copy_and_remap(va, vma, ...)
      Err(VmFault::ParkAndRetry) -> park on the page wait-queue, retry
      Err(other)             -> SIGSEGV / SIGBUS per the existing table
```

#### `FileObject::fault` happy path

```
fault(off, access):
    pgoff = self.file_offset_pages + off/4096
    if pgoff >= cache.i_size_pages():           return Err(OutOfRange)  // SIGBUS

    // Fast path: cache hit on UPTODATE page.
    {
        guard = cache.inner.lock()
        if let Some(page) = guard.pages.get(&pgoff):
            if page.state & PG_UPTODATE != 0 && page.state & PG_LOCKED == 0:
                if access == Write && self.share == Private:
                    drop(guard); return Err(VmFault::CoWNeeded)
                if access == Write && self.share == Shared:
                    set PG_DIRTY; guard.dirty.insert(pgoff)
                inc_refcount(page.phys)         // PTE reference
                return Ok(page.phys)
    }

    // Slow path: miss or stale. Drop the cache mutex; serialize via
    // PG_LOCKED on the page we install.
    let stub = Arc::new(CachePage::new_locked(alloc_zeroed_page()?))
    let installed = {
        let mut guard = cache.inner.lock()
        match guard.pages.get(&pgoff):
            Some(other) -> { drop_stub_frame(stub); other.clone() }
            None        -> { guard.pages.insert(pgoff, stub.clone()); stub }
    }

    if installed is the stub:
        // We own the fill. Drop nothing, but we MUST NOT hold cache.inner.
        debug_assert!(!holding_cache_inner_lock());
        ops.readpage(pgoff, hhdm_window(installed.phys))   // blocks
        installed.state.fetch_or(PG_UPTODATE, Release)
        installed.state.fetch_and(!PG_LOCKED, Release)
        installed.wait.wake_all()
    else:
        // Someone else owns the fill. Park if still locked.
        while installed.state & PG_LOCKED != 0:
            installed.wait.park_until(|| installed.state & PG_LOCKED == 0)

    // Re-enter fast path (recursion bounded by 1 — page is now
    // UPTODATE and we hold a strong Arc, so a second eviction is
    // impossible until we drop the local Arc).
    same_post_lookup_logic_as_above
```

Three rules embedded above are normative:

> **N1 — No long-running work under `cache.inner`.** `readpage` and
> `writepage` always run with the per-cache mutex *released*.
> Serialization across concurrent fillers is via `PG_LOCKED` on the
> individual page, not via the cache mutex.
>
> **N2 — Single-cache-entry under SMP-or-fault-reentrancy.** The
> install step re-checks the index under the mutex and drops the
> losing stub. Mirrors RFC 0004 buffer-cache invariant 4.
>
> **N3 — Lock-order is always `vma_tree → cache.inner → page wait-queue
> → buffer_cache.inner`**. Acquiring in any other order is a bug. The
> page-fault handler must not hold the VMA-tree spin while it calls
> `obj.fault`; today's handler already drops it before the dispatch
> per RFC 0001 — this RFC reaffirms the order.

#### `MAP_PRIVATE` on a write fault

The page cache holds the master copy. A `Private` write fault:

1. Reads the cache page (potentially populating it via `readpage`).
2. Maps it into the faulting AS read-only (PTE lacks W). The cache's
   refcount on the frame is unchanged.
3. On the *write* fault, dispatch surfaces `VmFault::CoWNeeded`. The
   CoW resolver `cow_copy_and_remap` allocates a fresh private frame,
   memcpys from the cache page through the HHDM, installs the new
   frame W=1, and `frame::put`s the old PTE reference. The cache
   page is unaffected.

This means `Private` faults reuse the **same** CoW machinery used for
fork (`cow_copy_and_remap`). The `share` field on the VMA already
distinguishes the two paths. There is no new "Private file fault"
resolver — the existing one is the right shape.

`clone_private()` on a `FileObject` returns a *new* `FileObject` with
`share = Private` and the **same** `Arc<PageCache>`. Post-fork demand
faults in either parent or child re-enter the cache and CoW out
independently. This is the literal ext2-as-shared-read-only pattern
SerenityOS uses; it falls out of the existing `Share` semantics
unchanged.

#### `MAP_SHARED` writeback

`MAP_SHARED + PROT_WRITE`: the W bit is installed, the page is marked
`PG_DIRTY`, and `pgoff` is added to `cache.dirty`. The per-mount
writeback daemon (RFC 0004 Workstream C — *unchanged here*) gets a
new responsibility: in addition to walking the buffer cache, it walks
**every superblock-mounted PageCache** and calls `writepage` on each
dirty `pgoff`.

The daemon's existing structure already does the right thing. Concrete
extension:

```rust
fn writeback_one_inode(inode: &Arc<Inode>) {
    let pages: Vec<(u64, Arc<CachePage>)> = {
        let mut guard = inode.mapping.inner.lock();
        let dirty_pgoffs: Vec<u64> = guard.dirty.iter().copied().collect();
        dirty_pgoffs.into_iter()
            .filter_map(|p| guard.pages.get(&p).map(|c| (p, c.clone())))
            .collect()
        // Note: no I/O under the lock. We only collect strong refs.
    };
    for (pgoff, page) in pages {
        // PG_WRITEBACK transition is racey with concurrent writes —
        // the writer must observe PG_WRITEBACK and NOT clear PG_DIRTY
        // (the page may dirty again between snapshot and writepage).
        page.state.fetch_or(PG_WRITEBACK, Acquire);
        let copy = read_phys_page(page.phys);  // cheap memcpy via HHDM
        match inode.mapping.ops.writepage(pgoff, &copy) {
            Ok(_) => {
                page.state.fetch_and(!PG_DIRTY, Release);
                inode.mapping.inner.lock().dirty.remove(&pgoff);
            }
            Err(_) => kwarn!("writepage(ino={ino}, pgoff={pgoff}) failed; will retry"),
        }
        page.state.fetch_and(!PG_WRITEBACK, Release);
    }
}
```

The snapshot-then-writepage discipline (memcpy out under no lock, then
write the snapshot) means a concurrent `MAP_SHARED` mutator who dirties
the page **between** the snapshot and the `writepage` keeps the page
on `dirty`. This is the same "fold the next dirty into the next
sweep" property Linux's `clear_page_dirty_for_io` provides; we get it
naturally because the writer's `set_dirty` runs under
`cache.inner.lock()`, observes `PG_WRITEBACK`, and re-enlists the
page in `dirty` even if `writepage` is concurrently in flight.

**Ordering vs `fsync(2)`.** `FileOps::fsync(data_only=false)`
synchronously walks `cache.dirty`, flushes everything, then fences on
`BlockCache::sync_fs(sb_dev)`. Two-stage flush so a crash after
`fsync` returns has both the page-cache contents and the inode
metadata committed.

**`msync(2)`.** Out of scope as a syscall in this RFC (no userspace
caller yet); the underlying writeback path described above is the
substrate `msync` will eventually call. Open Question: ship a
`msync(MS_ASYNC | MS_SYNC)` syscall in the same epic, or defer to a
follow-up. Default plan: defer; the writeback daemon plus `fsync`
provide the same durability guarantees for the static-binary
userspace this enables.

#### Demand-paged execve

Today `mem::elf::load_user_elf` walks every `PT_LOAD`, allocates and
copies frames eagerly. With `FileObject` available, the loader changes
to:

1. Open the executable as an `OpenFile`.
2. For each `PT_LOAD`, build a `FileObject` covering the segment's
   `[p_offset, p_offset + p_filesz)` rounded to pages.
3. Insert a VMA at `[p_vaddr_page_aligned, p_vaddr_page_aligned +
   p_memsz_rounded)` with `share = Private` and the prot_user from
   `p_flags`. Pages outside `[p_offset, p_offset + p_filesz)` are
   handled by zero-filling — the segment's `.bss` tail rounds up to a
   page that is *partially* file-backed and *partially* zero. We
   handle this by splitting the segment into two VMAs: the
   page-aligned file-backed prefix uses `FileObject`, and the zero
   tail (if `p_memsz > p_filesz`) uses `AnonObject` exactly as today's
   stack/heap does.
4. Defer all reads to demand-fault.

`PT_INTERP` falls out: the dynamic loader is just another ELF that
gets the same treatment. The `ENOEXEC` gate from RFC 0004 Workstream
F is removed in the same PR that flips on file-backed mmap.

The split-segment trick avoids the historic Linux/SerenityOS bug where
`.bss` overlap with `.data` on the same page leaks file data into
`.bss` — we explicitly zero the page tail in the file-backed VMA's
`readpage` (see §"Tail-page zeroing" below).

##### Tail-page zeroing

`AddressSpaceOps::readpage` is responsible for zeroing the tail of the
last page when `pgoff * 4096 + 4096 > i_size`. The caller of
`readpage` does **not** zero — only the FS knows the file's exact
length, and zeroing twice would mask a driver bug. ext2's impl looks
like:

```rust
fn readpage(&self, pgoff: u64, buf: &mut [u8; 4096]) -> Result<usize, i64> {
    let i_size = self.inode.meta.read().size;
    let start = pgoff * 4096;
    if start >= i_size { buf.fill(0); return Ok(0); }
    let end = core::cmp::min(start + 4096, i_size);
    let n = (end - start) as usize;
    self.read_through_buffer_cache(start, &mut buf[..n])?;
    if n < 4096 { buf[n..].fill(0); }
    Ok(n)
}
```

#### Eviction (page cache)

The cache uses **CLOCK-Pro** with the same parameter shape as the
buffer cache. We do **not** unify the clock hand — the cache has its
own — but we keep the algorithm identical so the same lessons (never
evict pinned, never evict `DIRTY|WRITEBACK`) carry. The eviction
sweep:

- Skips any `Arc::strong_count > 1` page (held by a VMA's PTE lookup,
  by a fault in flight, or by writeback).
- Skips `PG_DIRTY | PG_WRITEBACK | PG_LOCKED | PG_IN_FLIGHT`.
- Skips any page whose `phys` refcount > 1 (the cache's own reference
  + at least one PTE — the cache's reference is the only one we can
  drop unilaterally).
- On no-victim, returns `ENOMEM` to the caller (the new fault path).
  The fault returns `VmFault::OutOfMemory`, which the resolver maps
  to SIGBUS per the existing table — same as a failed `AnonObject`
  fault today.

This is **strict invariant parity** with RFC 0004 Workstream C.

#### Truncate, unmap, and `MADV_DONTNEED`

- **`ftruncate(fd, new_size)` shrink.** ext2's `setattr` calls
  `inode.mapping.truncate_below(new_size)`, which evicts every cached
  page with `pgoff * 4096 >= new_size_page_aligned_up`. PTEs in
  outstanding mappings into the truncated range are *not* invalidated
  by this RFC; per POSIX, accessing past EOF after a `ftruncate` is a
  SIGBUS, and the existing PTE-residency check at fault time
  (i.e. the fault retried after a TLB shootdown) takes care of it.
  See Open Question on TLB shootdown for the deferred SMP story.
- **`munmap`.** Unchanged. `VmaTree::unmap_range` already drops the
  `Arc<dyn VmObject>` reference per VMA; for a `FileObject` the cache
  itself is held via `Arc<PageCache>` and lives until the inode dies.
- **`MADV_DONTNEED`.** Already wired through `VmObject::evict_range`
  — `FileObject` delegates to `PageCache::evict_range` which drops
  cache references on the affected pgoffs. Pages still resident in
  some PTE remain alive via the page-refcount; the next fault repopulates
  the cache from disk if the page has dropped out. This matches the
  Linux semantics and the existing anon-mmap behaviour.

### Kernel–Userspace Interface

| Syscall | Change |
|---|---|
| `mmap(addr, len, prot, flags, fd, off)` | When `fd != -1`, look up the `OpenFile`, validate `prot` ⊆ open flags (write to `O_RDONLY` → `EACCES`), call `OpenFile::file_ops.mmap(...)`, plug the returned `VmObject` into the VMA tree. `MAP_SHARED + PROT_WRITE` requires `O_RDWR` or `O_WRONLY`. |
| `munmap(addr, len)` | Unchanged. |
| `mprotect(addr, len, prot)` | Unchanged structurally; new errno: `EACCES` when `prot ⊆ open_flags` is violated for a `FileObject`-backed VMA. |
| `madvise(addr, len, advice)` | Unchanged. `MADV_WILLNEED` becomes a hint to `AddressSpaceOps::readahead`. |
| `fsync(fd, data_only)` | Now also flushes `inode.mapping.dirty` before falling through to `BlockCache::sync_fs`. |
| `ftruncate(fd, len)` | Calls `mapping.truncate_below(len)` after the FS shrinks the on-disk image. |
| `execve` | The static-only gate from RFC 0004 Workstream F is removed in the same PR that lands the demand-paged loader. `PT_INTERP` is honoured per `mem::loader::INTERP_LOAD_BASE`. |

No new syscall numbers. `msync(2)` is deliberately deferred (Open
Question).

**Errno table for `mmap` of a regular file:**

| Condition | Errno |
|---|---|
| `fd` not open | `EBADF` |
| File type not mmappable (socket, FIFO) | `ENODEV` |
| `MAP_SHARED + PROT_WRITE` on `O_RDONLY` open | `EACCES` |
| `off` not page-aligned | `EINVAL` |
| `len == 0` | `EINVAL` |
| `off + len` overflow or past `i_size` | `EINVAL` (Linux uses `ENXIO` on `i_size` overflow at fault time, not at mmap; this RFC matches Linux — `mmap` past EOF *succeeds*, the SIGBUS surfaces at fault) |
| Out of memory installing VMA | `ENOMEM` |
| Cache-fill OOM at fault time | SIGBUS (signal, not errno) |

## Security Considerations

- **Write-protection on `MAP_SHARED + O_RDONLY`.** Validated at
  `mmap` entry. `mprotect` later cannot upgrade to `PROT_WRITE` on a
  Shared-O_RDONLY VMA — checked against the cached `OpenFile`-derived
  `f_mode` snapshot stored on the VMA at insert time. Without this,
  a `mprotect(PROT_WRITE)` would silently turn an `O_RDONLY` mapping
  into a writable one and let userspace clobber the page-cache copy
  of a file it lacks write permission on.
- **Permission-on-mmap recheck.** Permissions are checked once at
  `open(2)` and again at `mmap(2)` against the same `OpenFile`. We
  do *not* re-check on every fault; that would let a file's mode
  change racing with a faulting mapping cause spurious SIGSEGVs and
  is not what POSIX prescribes. This matches Linux.
- **`PG_DIRTY` propagation across forks.** A `MAP_PRIVATE` write
  fault never marks the cache page dirty (CoW path). A `MAP_SHARED`
  write fault marks it dirty regardless of which fork-child issued
  the write — the cache is shared across the fork. This is the
  intended POSIX behaviour but worth stating: writes through
  `MAP_SHARED` after `fork(2)` are visible to other peers and to
  `read(2)` callers immediately, modulo PTE TLB lag.
- **Truncate / mmap race.** `ftruncate` evicts cache pages past
  `new_size` but does not invalidate live PTEs in this RFC (uniproc
  scope). On uniproc, the PTE walker is the only thread touching
  paging structures; the next fault past EOF correctly returns
  SIGBUS. SMP shootdown story is deferred to the SMP RFC — explicit
  Open Question below.
- **Information disclosure via tail-page padding.** Critical:
  `readpage` zeroes `[i_size .. page_end)` so a `MAP_SHARED` reader
  past EOF cannot see stale frame contents. The buffer cache's slab
  may have any prior content — we never expose those bytes to
  userspace. Tested by `tail_page_is_zero_past_eof` in the host
  tests.
- **Reserved-bit / exec-fault gates.** Unchanged — `mem::pf` still
  panics on RSVD, and the existing `prot_user_allows` gate runs
  before the dispatch into `VmObject::fault`.
- **No PTE leak through error logs.** `FileObject::fault` errors
  carry `(va, pgoff, errno)` — never the physical frame address or
  the cache pointer. RFC 0001 advisory A2.
- **Capability composition.** The existing DAC machinery
  (RFC 0004 Workstream B) gates the `open(2)` that produces the
  `OpenFile` passed to `mmap`. No new privilege check is introduced;
  the design *requires* that `OpenFile` correctly track the
  `Credential` snapshot at `open` time, which Workstream B already
  provides.

## Performance Considerations

- **Hot path: cache hit on UPTODATE page.** One `BlockingMutex`
  acquire-and-release on `cache.inner`, one `BTreeMap::get`, one
  atomic load on `state`, one refcount increment. Zero block I/O.
  Comparable to today's `AnonObject::fault` cache-hit path.
- **Mutex granularity.** The per-inode mutex serialises faults
  against the same inode. For uniproc this is irrelevant. Under SMP
  it becomes the bottleneck for hot files (`/lib/libc.so`); the SMP
  follow-up RFC will shard or replace with an XArray-style
  fine-grained lock. Out of scope here, but the data structure
  choice (BTreeMap-on-mutex) deliberately matches `AnonObject` so
  the same shard fix applies uniformly.
- **Readahead window.** Default 8 pages on sequential miss
  (`AddressSpaceOps::readahead`). Bounded by RFC 0004 buffer cache
  invariants — we never trigger sync flushes from readahead.
- **Memory overhead per cached page.** `CachePage` is 24 bytes of
  metadata (`phys: u64`, `pgoff: u64`, `state: AtomicU8`,
  `wait: WaitQueue<small_repr>`) + the 4 KiB data frame +
  `BTreeMap` node overhead (~48 bytes) ≈ 4168 bytes per page.
  About 2 % overhead; on par with Linux's `struct folio + struct
  page`.
- **Writeback contention.** The daemon iterates inodes and
  snapshot-collects dirty pgoffs under `cache.inner` (cheap), then
  performs `writepage` outside the lock. A pathological workload
  that dirties pages faster than writeback can flush builds
  unbounded `cache.dirty` — same as Linux. Bound is `i_size /
  4096 * mounts`, which the existing OOM path absorbs as a hard
  ceiling.
- **TLB shootdown.** Out of scope (uniproc). Truncate-below evicts
  cache entries but does not invalidate PTEs; the next fault re-runs
  the bounds check. SMP RFC owns shootdown.
- **Buffer-cache thrash.** Every page-cache miss issues 1 (4 KiB
  block size) or 4 (1 KiB block size) `bread` calls. The block buffer
  cache must therefore be sized large enough to hold the working set's
  worth of in-flight reads. Default sizing (RFC 0004) is unchanged;
  if the bring-up image keeps `block_size = 1 KiB`, expect 4× the
  buffer-cache pressure relative to a 4 KiB image. We recommend
  flipping rootfs to 4 KiB blocks in the same epic that lands the
  page cache (Open Question).

## Alternatives Considered

### Cache layering trade-off

Three options were on the table.

**A. Unified page-and-buffer cache** (FreeBSD, Linux post-2.4).
Block reads are served by the page cache via `buffer_head`s that map
fragments of a page onto disk blocks. Pro: zero double-buffering for
the common 4 KiB-block ext2 case; one cache to size and tune. Con:
the existing buffer cache is the foundation for ext2's metadata I/O
(superblock, BGDT, inode table, bitmaps, indirect blocks) — none of
which are page-aligned. Folding metadata reads into a page-grain
cache requires rewriting RFC 0004 Workstream C. The four normative
invariants (no spin across I/O, skip pinned + DIRTY|LOCKED_IO, no
sync flush from `bread`, single-cache-entry) stop being properties
of the cache as a whole and become properties of two distinct
sub-paths (file data vs metadata) inside it. **Rejected** — too much
churn for marginal gain on a uniproc kernel where the buffer cache
just merged.

**B. Buffer cache as backing store, page cache as window** (the
"slim" model). The page cache holds no frames of its own; every
`get_page` call reads through to the buffer cache, which holds the
real data. Pro: trivially correct because there is one source of
truth. Con: a 4 KiB page reaches into 1–4 buffer-cache entries and
must compose them under a fault-time lock; eviction policy is owned
entirely by the buffer cache, so the page cache loses any ability to
prefer the working set of mmapped files. Worse, the buffer cache's
unit of consistency is a *block* — `MAP_SHARED + write` on a 4 KiB
page must mark 4 buffers dirty in lock-step or risk a torn write
visible to a sibling `read(2)`. **Rejected** — the lock-step
constraint pulls work into the buffer cache that doesn't belong
there.

**C. Separate page cache, buffer cache as backing store on miss
only** ← **chosen**. The page cache owns its own frames; on miss it
issues `readpage`, which the FS implements by `bread`-ing one or
more blocks and `memcpy`-ing into the cache page (or, on 4 KiB
blocks with proper alignment, by donating the buffer's slab — see
the "in-place buffer hand-off" Open Question). After the page is
populated, the page cache is fully self-sufficient until eviction or
writeback. The buffer cache stays the canonical place for metadata
I/O; its four invariants are unmodified. The page cache and buffer
cache are **independent caches with explicit handoff**, not nested.

This is essentially the SerenityOS/Mach split: a memory object
(`InodeVMObject` / `vm_object_t`) per inode, layered above a block
substrate. It's also the model Linux *was* before the unification
era — and Linux's unification depended on `buffer_head` engineering
that vibix has not paid for and does not need at uniproc scale.

### `VmObject` redesign vs `FileObject` slot-in

The `VmObject` trait already has every method we need. We considered
adding a parallel `FileVmObject` trait with a richer interface
(`begin_io`, `end_io`, etc.), then realised every method shape we
wanted slots cleanly behind `fault` + `frame_at` + `evict_range` +
`truncate_from_page`. Keeping one trait avoids a second dispatch
table in the fault hot path.

### CoW resolver redesign

A `MAP_PRIVATE + write` fault could allocate a new `AnonObject` per
VMA and copy on demand directly from `FileObject::fault`, bypassing
the existing `cow_copy_and_remap`. We rejected this because:

- The existing CoW path is well-tested and correctness-critical
  (RFC 0001 Workstream).
- A second copy path means two places to fix when SMP shootdown lands.
- The PTE-layer CoW already handles the refcount accounting; the
  `FileObject` merely surfaces `VmFault::CoWNeeded` and lets the
  resolver do its job.

### Per-VMA private copy as `AnonObject`

After a `MAP_PRIVATE + write` fault, the new private frame could be
inserted into a per-VMA `AnonObject` so re-faults on the same private
page hit a cache. We do this implicitly via the PTE — the PTE caches
`(pgoff → private_phys)` directly. We considered also inserting the
private frame into a fresh `AnonObject` per VMA so madvise(DONTNEED)
on the private region works. Implementing this requires either:
(a) a `CompositeObject` that delegates to `FileObject` for unfaulted
pages and `AnonObject` for written pages, or (b) extending
`FileObject` with its own private-frame map.

Option (b) is simpler and fits the existing trait surface — adopt it
in the implementation issues. Mentioned here for design-record
clarity; no normative change to the design.

## Open Questions

- [ ] **rootfs block size.** RFC 0004 left this open
  ("`-b 4096` matches host defaults; `1 KiB` makes indirect-block
  math smaller"). Page cache shifts the calculus toward 4 KiB:
  a 4 KiB block size means one `bread` per `readpage`, vs four for
  1 KiB. Recommend flipping to 4 KiB in the same epic that lands the
  page cache. Decided: 4 KiB.
- [ ] **In-place buffer hand-off vs always-memcpy.** When `block_size
  == 4096` and the buffer is page-aligned, `readpage` could reuse the
  `BufferHead.data` slab as the cache page directly (zero-copy).
  This requires teaching the buffer cache to release frame ownership
  on demand and the page cache to accept ownership; coupling that
  the explicit-handoff layering was specifically chosen to avoid.
  **Defer** to a follow-up perf RFC; first ship the always-memcpy
  path. Memcpy of one 4 KiB page is ~1 µs.
- [ ] **`msync(2)` syscall.** Out of this epic; deferred. The
  writeback daemon + `fsync` is sufficient for the static + dynamic
  binary userspace this RFC enables. Track as a follow-up issue.
- [ ] **TLB shootdown on truncate / page eviction.** Out of scope
  (uniproc). Resolved by SMP RFC.
- [ ] **`MAP_HUGETLB`, `MAP_LOCKED`, `MAP_NORESERVE`.** All rejected
  with `EINVAL` for the initial implementation. Track as follow-ups.
- [ ] **Mincore, posix_fadvise.** Out of scope. The cache structure
  trivially supports both; ship in the same epic if a userspace
  caller materialises before merge.
- [ ] **`MAP_SHARED` over `tmpfs` / `tarfs`.** ramfs/tarfs override
  `FileOps::mmap` to return an `AnonObject`-style backing — no page
  cache, no writeback. Document this in the FS impls; `MAP_SHARED`
  on a tarfs file is read-only by mount semantics anyway, so no
  writeback is sensible.

### Resolved during peer review

*(populated during defense cycles)*

### Deferred to follow-up RFCs

- `msync(2)` syscall and the precise `MS_ASYNC`/`MS_SYNC`/
  `MS_INVALIDATE` semantics.
- SMP page-cache sharding and TLB shootdown discipline.
- Per-CPU magazine layer over the page cache (Bonwick & Adams 2001).
- Huge pages (`MAP_HUGETLB`, transparent hugepages).
- Page migration / NUMA balancing.
- Direct I/O bypass (`O_DIRECT`).
- `splice(2)` / `sendfile(2)` zero-copy.

## Implementation Roadmap

Five workstreams, three waves. Wave 1 is parallelisable; wave 2 blocks
on wave 1; wave 3 blocks on wave 2.

### Workstream A — Page cache core (wave 1)

- [ ] mem: introduce `PageCache`, `CachePage`, `PG_*` state bits, per-cache `BlockingMutex<PageCacheInner>` (BTreeMap + dirty BTreeSet)
- [ ] mem: `AddressSpaceOps` trait (`readpage`/`writepage`/`readahead`/`truncate_below`) with default no-op `readahead`/`truncate_below`
- [ ] mem: `FileObject : VmObject` with `share`-aware `fault` (Shared write → mark dirty; Private write → `VmFault::CoWNeeded`); `frame_at`/`clone_private`/`truncate_from_page`/`evict_range`
- [ ] mem: page-fault path threads `VmFault::CoWNeeded` and `VmFault::ParkAndRetry` into the existing resolver — re-uses `cow_copy_and_remap` unchanged
- [ ] mem: page-cache CLOCK-Pro eviction matching the four buffer-cache invariants; `ENOMEM` rather than sync flush; host unit tests for skip-pinned, skip-DIRTY, no-victim
- [ ] mem: **invariant assertion** — `debug_lockdep::assert_no_spinlocks_held()` at the top of `AddressSpaceOps::{readpage, writepage}`; assert `cache.inner` is not held when crossing the FS hook

### Workstream B — VFS plumbing (wave 1)

- [ ] vfs: add `FileOps::mmap(f, file_offset, len_pages, share, prot) -> Result<Arc<dyn VmObject>, i64>` defaulting to `ENODEV`
- [ ] vfs: extend `Inode` with `mapping: Option<Arc<PageCache>>` (gated by `#[cfg(feature = "page_cache")]` initially); construct lazily on first mmap or first read
- [ ] sys: rewire `sys_mmap` for `fd != -1` — look up `OpenFile`, validate `prot ⊆ f_mode` (write-to-RO ⇒ `EACCES`), call `FileOps::mmap`, plug into VMA tree; preserve `MAP_FIXED`/`MAP_FIXED_NOREPLACE` semantics
- [ ] sys: extend `mprotect` to reject `PROT_WRITE` upgrades on Shared-O_RDONLY `FileObject`-backed VMAs (`EACCES`)
- [ ] sys: extend `fsync` to flush `inode.mapping.dirty` before `BlockCache::sync_fs`; both error paths surface `EIO`

### Workstream C — ext2 AddressSpaceOps (wave 2, blocks on A + B + RFC 0004 #537 — already merged)

- [ ] fs/ext2: implement `AddressSpaceOps` for `Ext2Inode` — `readpage` walks indirect blocks, `bread`s through the buffer cache, memcpys 4 KiB into the page, zero-fills the `[i_size .. page_end)` tail
- [ ] fs/ext2: implement `writepage` — splits the page back into block-sized fragments, `mark_dirty` + `sync_dirty_buffer` per fragment; rollback on per-block failure (best-effort: the next sweep retries)
- [ ] fs/ext2: implement 8-page sequential-readahead in `readahead` — never holds the cache mutex; bounded by buffer-cache invariants
- [ ] fs/ext2: hook `truncate_below` into `setattr(size)` — evict pages past `new_size_page_aligned_up` *before* freeing on-disk blocks
- [ ] fs/ext2: implement `FileOps::mmap` returning `Arc<FileObject>` with the inode's lazily-constructed `mapping`
- [ ] fs/ext2: route `FileOps::read` through the page cache when present (so a `read` after `mmap` and a `read` without share the same backing copy); fall back to direct `bread` if `mapping` is `None`

### Workstream D — Writeback daemon extension (wave 2)

- [ ] block: extend the per-mount writeback daemon to walk every superblock-mounted inode's `mapping` and call `writepage` on every dirty pgoff (snapshot-collect under cache mutex, write outside)
- [ ] block: writeback ordering — page-cache pages flushed first, then `BlockCache::sync_fs`; documents the soft-update style ordering already used by ext2 for create/unlink
- [ ] block: `sync(2)` / `sync_fs(sb)` triggers an immediate page-cache + buffer-cache flush (no waiting for the next interval)
- [ ] block: writeback-daemon unit + integration tests (kernel test marker) — one MAP_SHARED writer, kill -9 mid-flight, verify the next mount sees a consistent prefix

### Workstream E — Demand-paged loader + execve (wave 3, blocks on A + C)

- [ ] mem/loader: rewrite `load_user_elf` to install file-backed VMAs over `PT_LOAD` segments instead of eager copies; split file-backed prefix vs zero-tail per the RFC; ensures `.bss` cannot leak file data
- [ ] mem/elf: PT_INTERP support — open the named interpreter, recurse `load_user_elf` at `INTERP_LOAD_BASE`, transfer initial PC to interpreter
- [ ] sys: remove the `PT_INTERP → ENOEXEC` gate from RFC 0004 Workstream F in the same PR that flips on file-backed mmap
- [ ] sys: `execve` test fixture — a small dynamic-linker stub ELF whose `PT_INTERP` resolves to a no-op interpreter that just `exit(0)`s; integration test boots it under QEMU and emits a `TEST_PASS` marker

### Label assignments (per `docs/agent-playbooks/prioritization.md`)

- A → `priority:P2`, `area:mem`, `track:filesystem`. Foundation; not on the PID 1 critical path.
- B → `priority:P2`, `area:fs`, `area:mem`, `track:filesystem`.
- C → `priority:P2`, `area:fs`, `area:mem`, `track:filesystem`.
- D → `priority:P2`, `area:fs`, `area:driver`, `track:filesystem`.
- E → `priority:P2`, `area:mem`, `area:userspace`, `track:filesystem`, `track:userspace` — gates dynamic linking.

## What this unlocks (downstream milestones — not designed here)

- **PT_INTERP / dynamic linker.** Workstream E lights the kernel side
  up; the userspace dynamic loader is a separate execution-only epic
  (well-precedented by every UNIX dynamic linker since SunOS 4).
- **Distro-boot demo.** Static-busybox today; with this RFC plus the
  dynamic-linker epic, alpine-musl userspace becomes runnable. Tracked
  separately as an integration-only epic.
- **Anonymous-mmap improvements.** `madvise(MADV_FREE)`, `MAP_LOCKED`,
  `MAP_HUGETLB`. Each is a small follow-up against the
  `VmObject`/`FileObject` substrate.
