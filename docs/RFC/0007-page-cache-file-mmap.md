---
rfc: 0007
title: Demand-Paged File mmap and Page Cache for ext2
status: Accepted
created: 2026-04-28
---

# RFC 0007: Demand-Paged File mmap and Page Cache for ext2

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
identically across mmap, read, and execve. RFC 0007 fixes the
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
    /// reference; every PTE mapping it holds one more. **`Arc::strong_count`
    /// of `CachePage` and `mem::refcount` of `phys` are independent
    /// counters with non-overlapping responsibilities** (see §Refcount
    /// discipline below). Padded to 64 bytes to avoid false-sharing on
    /// `state` between adjacent cache entries on SMP (uniproc today).
    pub phys: u64,

    /// Page index = file_offset / 4096.
    pub pgoff: u64,

    /// State bits — see `PG_*` below. `AtomicU8` so reads in the fault
    /// hot path don't take any lock. **All transitions documented in
    /// §State-bit ordering** — `PG_UPTODATE` and `PG_LOCKED` are released
    /// with `Release`; observers must use `Acquire` for the inverse load.
    pub state: AtomicU8,

    /// Wait-queue for the LOCKED-fill and WRITEBACK handshakes. A second
    /// fault on the same page parks here until the original reader
    /// publishes UPTODATE; `truncate_below` parks here on `PG_WRITEBACK`
    /// to wait out an in-flight `writepage` before the FS is allowed to
    /// free the underlying blocks.
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
    /// racing the cache. **Bound to the inode at construction and
    /// never rebound** — see §Security inode-binding rule. A second
    /// `execve` of the same path that resolves to a different inode
    /// constructs a *new* `FileObject` against that inode's distinct
    /// `Arc<PageCache>`; the old one continues serving the old mapping.
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

    /// Snapshot of the `OpenFile.f_mode` (`O_RDONLY`/`O_WRONLY`/`O_RDWR`)
    /// at `mmap` time. Consulted by `mprotect` so `PROT_WRITE` cannot
    /// be added to a Shared mapping that was opened read-only — closes
    /// the TOCTOU surface raised by Security B1. Snapshot, not a live
    /// reference: `OpenFile` may close before `munmap`; the VMA owns the
    /// access decision.
    open_mode: u32,

    /// Per-VMA private-frame cache for `MAP_PRIVATE` write faults.
    /// Empty for Shared mappings. After a CoW write fault, the new
    /// private frame is recorded here so re-faults (e.g. after
    /// `madvise(MADV_DONTNEED)` or a TLB shootdown) hit the same
    /// physical frame instead of allocating a fresh one. Mirrors the
    /// `clone_private` / `evict_range` plumbing of `AnonObject`.
    private_frames: BlockingMutex<BTreeMap<u64, u64>>, // pgoff → phys
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

### Refcount discipline

Two independent counters track different things and are **never
intermixed** by the implementation:

1. **`mem::refcount::get(phys)`** — counts the number of installed PTEs
   plus the cache's own ownership. Bumped by the fault path when a
   PTE is installed; decremented in `AddressSpace::drop` /
   `cow_copy_and_remap` when a PTE is removed; the cache itself holds
   exactly one reference to each `phys` it caches. This is the
   counter the existing CoW resolver uses; nothing changes here.
2. **`Arc::strong_count(&CachePage)`** — counts the cache index entry
   (1) plus any in-flight fault that has cloned the `Arc` *before*
   installing its PTE plus the writeback daemon's snapshot. **Eviction
   blocks on `Arc::strong_count > 1`** because a clone in flight
   indicates a fault has not yet decided whether to install a PTE
   (and possibly bump `mem::refcount`).

Concretely, the fault hot path:

```
let page = cache.inner.lock().pages.get(&pgoff).cloned();  // strong+1
drop(lock);
mem::refcount::try_inc_refcount(page.phys)?;               // PTE refcount+1
install_pte(page.phys);
// `page` Arc drops at scope end                           // strong-1
```

The strong count is back to 1 (the cache's own) once the fault
returns. The `mem::refcount` is `1 + (PTEs installed)`. Eviction sees
`strong_count == 1`, which means no fault is currently mid-resolution;
it then checks `mem::refcount::get(phys) <= 1` (only the cache holds
it) and frees the frame. If any PTE is still installed, the eviction
path skips the page even though `strong_count == 1` — the frame
refcount is the gating signal there. Both checks are needed; neither
subsumes the other.

This is the same separation Linux maintains via `page->_refcount`
(physical) vs `folio->_mapcount` (PTE) vs caller-held references; the
naming differs but the discipline is identical.

### State-bit ordering

`PG_LOCKED` and `PG_UPTODATE` are the two bits with cross-thread
correctness obligations. Their transitions are governed by:

- **Filler side** (the task that won the install race):
  `state.fetch_or(PG_LOCKED, Acquire)` is implicit in the install
  step (the page is constructed locked). After `readpage` returns,
  the filler issues `state.fetch_or(PG_UPTODATE, Release)` *before*
  `state.fetch_and(!PG_LOCKED, Release)`. The Release on the
  `PG_LOCKED` clear synchronises-with the Acquire load below; together
  they ensure the page contents (the writes performed *during*
  `readpage`) are visible to any observer that sees `PG_LOCKED` clear.
- **Observer side**: every reader does
  `state.load(Acquire)` and treats `PG_LOCKED` clear as the signal that
  the data is committed. `PG_UPTODATE` and the page bytes are guaranteed
  visible after the `Acquire`.
- **Writer side** (Shared write fault):
  `state.fetch_or(PG_DIRTY, AcqRel)`. The `dirty` index update happens
  *under* `cache.inner.lock()` — see §Algorithms — so the daemon's
  snapshot never sees an inconsistent (`PG_DIRTY` set, index
  unenrolled) state.
- **Writeback side**: `state.fetch_or(PG_WRITEBACK, AcqRel)` before
  the snapshot memcpy; `state.fetch_and(!PG_WRITEBACK, Release)` +
  `wait.wake_all()` after the writepage returns. `truncate_below`
  parks on `wait` while `PG_WRITEBACK` is set.
- **Filler error handling**: if `readpage` returns `Err`, the filler
  must:
  1. acquire `cache.inner.lock()`,
  2. remove the page from `pages` (the cache index),
  3. drop the cache's strong ref,
  4. `state.fetch_and(!PG_LOCKED, Release)` and `wait.wake_all()` so
     parked waiters retry the slow path against a fresh stub,
  5. `frame::put` the stub's physical frame.
  The page is *never* left in the cache with `PG_LOCKED` clear and
  `PG_UPTODATE` clear — that combination is reserved for the (yet
  unobservable) just-allocated state.

### Lock-order (normative)

The full lock order, top to bottom (acquire higher first; release
lower first):

```
1. Task::credentials  (BlockingRwLock<Arc<Credential>>)
2. Inode::meta        (RwLock — the per-inode metadata)
3. AddressSpace::vmas (BlockingRwLock — the VMA tree)
4. PageCache::inner   (BlockingMutex — per-inode cache index)
5. CachePage::wait    (WaitQueue — per-page parking)
6. BlockCache::inner  (BlockingMutex — RFC 0004 buffer cache)
7. mem::refcount      (lock-free atomics)
8. mem::frame         (BlockingMutex — global frame allocator)
```

The page-fault handler enters at level 3 (resolving the VMA), drops
to level 4 (cache lookup), drops to level 5 (parking on a slow path),
and lets `AddressSpaceOps::readpage` (run with no level-3-or-4 lock
held) take level 6 internally. **`assert_no_spinlocks_held()` is
asserted at the entry of every `AddressSpaceOps` method** — this is
a hard runtime assertion (not debug-only) for the same reason RFC 0004
makes it hard for the buffer cache: regression here is an immediate
deadlock on first contention.

Two refinements (added in defense cycle 2):

- **Level 4 is per-inode and does not nest.** Each `PageCache` is a
  *separate* level-4 lock instance. The discipline forbids holding
  *two* `PageCache::inner` locks simultaneously — a future helper
  that walks all inodes (e.g. for `sync(2)`) must release one
  `cache.inner` before acquiring another's. The writeback daemon
  already follows this naturally because it iterates inodes in
  outer-loop order and snapshot-collects from each before moving on.
  Stated normatively here so an `assert_no_other_pagecache_locked()`
  debug helper has a fixed contract to enforce.
- **`writeback_complete_wq` lives at level 6.5** — between the buffer
  cache (level 6) and the refcount/frame layer (levels 7–8). Its
  internal mutex is taken only to wake parked reclaimers, never with
  level-7 or level-8 locks held by the waker. The reclaimer parks
  with no lock held above level 4, by construction (it's already at
  the slow-path entry point). The waker (writeback daemon's loop and
  `CachePage::Drop`) takes the wq mutex with no other lock held.
  Worker A's IDT/STI rework lands the wq fan-out alongside the
  page-fault path so this ordering is enforced from day one.

Observers of `PG_DIRTY` (the writeback daemon's snapshot) use
`state.load(Acquire)`; the AcqRel fetch_or on the writer side is the
release pair. Stated explicitly so the AcqRel/Acquire pairing is
symmetric in §State-bit ordering.

### Page-fault IRQ discipline

The current `arch::x86_64::idt::page_fault` handler runs with IRQs
disabled (interrupt gate). The slow path of a `FileObject` fault
must:

1. Sample CR2 and the error code into local variables on the kernel
   stack (mandatory — re-enabling IRQs may cause a nested fault that
   clobbers CR2 before we read it).
2. Re-enable interrupts (`sti`) **before** the first `BlockingMutex::lock`
   call. The pure-logic gates in `mem::pf` (SMAP, RSVD, canonical, prot)
   already complete with IRQs disabled and produce a verdict before
   `sti`; the verdict-then-sti split is the safe place to reopen
   interrupts.
3. Drive the slow path with IRQs enabled — the task is now preemptible
   and may park.
4. On return from `obj.fault`, disable interrupts again before the
   final PTE install + TLB flush, then return through the IRET frame
   normally.

This requires the page-fault gate to remain an *interrupt* gate (not
a trap gate) so we control the precise STI placement. The change
lands as part of Workstream A and is the first sequenced step of the
fault rewrite — without it the slow path deadlocks the first time it
is hit.

### Eviction liveness

The cache's eviction policy returns `ENOMEM` only after a documented
**direct-reclaim** wait:

1. CLOCK-Pro sweep finds zero victims (every page is pinned, dirty, or
   locked).
2. The faulter parks on `BlockCache::writeback_complete_wq` — a
   per-cache waitqueue kicked by the writeback daemon every time it
   completes a `writepage`.
3. The faulter wakes on either: (a) a writepage completion
   (`PG_DIRTY`-pinned page may now be evictable), (b) a `CachePage`
   `Arc::strong_count` reaching 1 in its `Drop` (an `Arc::clone`-pinned
   page may now be evictable), or (c) a soft timeout of **2 seconds**
   (configurable via the same `writeback_secs=<N>` cmdline knob, with
   a separate `direct_reclaim_timeout_ms=<N>` override).
4. On every wake **before the soft cap**, the sweep retries. A wake
   may produce a victim or not; non-success keeps the faulter parked
   for the remainder of the 2 s window. Only after the soft cap
   expires with no victim found does the cache surface `ENOMEM`,
   which the resolver maps to SIGBUS.

This is a per-event retry — a writeback daemon issuing N writepages
in a row gives the parked faulter N retry opportunities, bounded only
by the soft cap. Closes the OS-engineer cycle-2 advisory clarification.

The 2-second cap exists so a pathological workload cannot park a
faulting thread for the full 30 s writeback interval. With the cap,
liveness reduces to "if a writepage ever completes within 2 s of the
fault, the fault will retry"; under sustained pressure the SIGBUS
surface is reachable, but it is reachable only when the system is
genuinely OOM by the standard the writeback daemon's cadence
defines. This is the bounded-direct-reclaim option (a) from the
academic blocking finding.

### Inode-binding rule

`FileObject.cache: Arc<PageCache>` is set at construction and is
**never** mutated for the lifetime of the `FileObject`. `PageCache`
holds an `inode_id: InodeId` and a per-inode `Arc<dyn AddressSpaceOps>`
captured from the `Arc<Inode>` at cache-construction time; the cache's
identity is the inode's identity. A second `execve` of the same path
that resolves to a different inode (the rename/unlink-then-replace
attack) constructs a *separate* `FileObject` against the new inode's
*separate* `Arc<PageCache>`. The first execve's mapping continues
serving the original inode's cache until the original mapping is
torn down.

This closes the TOCTOU surface raised in Security B3 by making
"refresh the FileObject's backing on inode replacement" a non-existent
operation — there is no API to do it, and any future API would have
to thread through the entire `VmObject` trait.

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
                    // Linearization: enrol in dirty index *first*,
                    // then atomic state OR. Daemon's snapshot reads
                    // index-then-state and treats either signal as
                    // "still dirty" for the next sweep.
                    guard.dirty.insert(pgoff)
                    page.state.fetch_or(PG_DIRTY, AcqRel)
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
        assert_no_spinlocks_held()
        match ops.readpage(pgoff, hhdm_window(installed.phys)):
          Ok(_) ->
            installed.state.fetch_or(PG_UPTODATE, Release)
            installed.state.fetch_and(!PG_LOCKED, Release)
            installed.wait.wake_all()
          Err(e) ->
            // Filler error contract — keep the cache index clean.
            let mut guard = cache.inner.lock()
            guard.pages.remove(&pgoff)        // drops the cache's strong ref
            drop(guard)
            installed.state.fetch_and(!PG_LOCKED, Release)
            installed.wait.wake_all()         // parked waiters retry slow path
            mem::frame::put(installed.phys)   // release stub frame
            return Err(VmFault::ReadFailed(e))

        // Truncate-vs-fill race recheck under cache.inner: i_size may
        // have shrunk while readpage was in flight. If so, evict the
        // page we just installed and surface OutOfRange.
        if pgoff >= cache.i_size_pages_locked():
            let mut guard = cache.inner.lock()
            guard.pages.remove(&pgoff)
            return Err(VmFault::OutOfRange)
    else:
        // Someone else owns the fill. Park if still locked.
        while installed.state.load(Acquire) & PG_LOCKED != 0:
            installed.wait.park_until(|| installed.state.load(Acquire) & PG_LOCKED == 0)
        // Wake-on-error: page may have been evicted from the index.
        // Retry the entire slow path; the recursion is bounded by the
        // monotonic FS-side outcome.
        if installed.state.load(Acquire) & PG_UPTODATE == 0:
            return retry_slow_path()

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
> per RFC 0001 — this RFC reaffirms the order. Full-stack order in
> §Lock-order (normative) above.
>
> **N4 — Read-after-writeback consistency** (Mach memory-object
> contract). A `read(2)` that observes a page returned from
> `cache.pages.get(&pgoff)` after a `writepage(pgoff, _)` has
> committed observes the post-writepage contents. Trivially holds
> today because both `read(2)` and `writepage` go through the same
> `Arc<CachePage>`; the rule is normative for future direct-IO
> bypass and for the SMP write-then-read-on-different-CPU case.
> Stated as an explicit invariant per Rashid et al. 1988
> ("Machine-Independent Virtual Memory Management for Paged
> Uniprocessor and Multiprocessor Architectures").

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

**Ordering vs `fsync(2)` and `fdatasync(2)`.**

`FileOps::fsync(data_only=false)` synchronously walks `cache.dirty`,
calls `writepage` on every dirty page, then fences on
`BlockCache::sync_fs(sb_dev)`. The per-page `writepage` performs its
own internal ordering: each data block is `sync_dirty_buffer`'d
*before* its parent indirect-block buffer is, matching RFC 0004
§create normative create-ordering (bitmap → inode → dirent, each
synchronous). The two-stage flush guarantees both page-cache contents
and inode-table metadata are on stable storage when `fsync` returns.

`FileOps::fsync(data_only=true)` (i.e. `fdatasync`) walks `cache.dirty`
and calls `writepage` exactly as the full path does, but **skips the
inode-table flush** if the dirty pages do not extend the file. Linux's
rule: `fdatasync` must flush whatever metadata is required for a
subsequent `read(2)` to see the post-fsync data — that is, indirect
blocks and the bitmap (if newly-allocated), but *not* `i_mtime` /
`i_atime` updates. Concretely:

- If `writepage` did not allocate any new blocks, only `s_state` and
  `i_mtime` would be dirty in the buffer cache, both of which are
  metadata-only and skipped.
- If `writepage` did allocate new blocks (the §writepage block
  allocation path below), the bitmap and indirect-block buffers are
  flushed via `sync_dirty_buffer` as part of `writepage` itself —
  before the data block — so `fdatasync` already has what it needs.

Database workloads (sqlite, postgres, leveldb) that issue
`fdatasync` after every transaction therefore avoid the
inode-table-block sync cost, which is the entire point of the API
distinction.

**Per-page write-error reporting.** A `writepage` failure marks the
inode's `mapping` with `wb_err: AtomicU32` (a monotonic counter that
increments on every distinct write failure). `fsync` returns `EIO`
if `wb_err` advanced since the last `fsync` on this `OpenFile`;
`OpenFile` snapshots `wb_err` at `open` and re-reads it on `fsync`.
This is the `errseq_t` pattern from Linux ≥ 4.13; vibix's
implementation is a flat counter rather than the multi-fd-snapshot
structure, accepting that two `fsync` callers may both observe the
same `EIO` once. Fully addresses the durability surface raised by
the filesystem reviewer (advisory A1).

**`msync(2)`.** Out of scope as a syscall in this RFC (no userspace
caller yet); the underlying writeback path described above is the
substrate `msync` will eventually call. Open Question: ship a
`msync(MS_ASYNC | MS_SYNC)` syscall in the same epic, or defer to a
follow-up. Default plan: defer; the writeback daemon plus `fsync`
provide the same durability guarantees for the static-binary
userspace this enables.

#### `writepage` block allocation (MAP_SHARED extend / sparse fill-in)

A `writepage` for a `(pgoff, buf)` whose underlying ext2 blocks are
unallocated (the file was extended via `ftruncate(fd, NEW_SIZE)` with
`NEW_SIZE > old_i_size`, or a sparse hole was written through
`MAP_SHARED`) **must** allocate the blocks before issuing the data
write. The allocation is performed by `Ext2Inode::writepage` — not
by the page cache — and follows RFC 0004 §create normative ordering:

1. Allocate the data block(s) via the block bitmap allocator
   (RFC 0004 Workstream E machinery). On 4 KiB blocks: one block per
   page; on 1 KiB blocks: up to four blocks per page; allocator runs
   in the parent inode's block group with linear spill.
2. If a new indirect-block pointer slot is needed (single/double/
   triple indirect), allocate that block too.
3. `sync_dirty_buffer` the bitmap (block bitmap reflects allocation).
4. `sync_dirty_buffer` the new indirect block (its forward pointer
   to the data block is set, but the data block contents are still
   undefined).
5. Write the data block via `mark_dirty + sync_dirty_buffer`.
6. Update `i_blocks` on the inode by `block_size / 512` per allocated
   block (data + every indirect), update `i_size` if the page extends
   the file, and `mark_dirty` the inode-table buffer.

The order is "allocate, advertise the pointer, commit the data" —
matches RFC 0004's "bitmap → inode → dirent" discipline and means a
crash between any pair of steps leaves the FS in one of these
recoverable states:

- Crash after step 3, before 4: bitmap shows the block as allocated
  but the indirect block doesn't reference it (orphan block — fsck
  reclaims).
- Crash after step 4, before 5: indirect block references a data
  block whose contents are whatever the freshly-allocated block
  contained on disk (zeros from `mkfs`, or stale from a prior file).
  This is the same "uninitialised data exposure" hole RFC 0004
  documents for the eager `FileOps::write` path; mitigation is the
  same: ext2 has no journal, so the application-visible state after
  crash recovery may include stale block contents. **An `O_TRUNC`
  + sparse-extend pattern over `MAP_SHARED` therefore inherits the
  same disclosure-via-crash surface that `write(2)` already has on
  ext2.** Documented; not a regression.

Rollback on per-step failure: every allocator returns the block to
the bitmap if a downstream step fails; the inode's in-memory
`i_blocks` / `i_size` are updated only after step 6. This matches
RFC 0004 Workstream E's rollback discipline.

`writepage`'s error path propagates to the writeback daemon's
`wb_err` increment (above) so a sticky `EIO` surfaces on the next
`fsync`.

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
  `inode.mapping.truncate_below(new_size)`, which:
  1. acquires `cache.inner`,
  2. updates `i_size: AtomicU64` to the new value,
  3. for every page in `[new_size_page_aligned_up..)`: if the page has
     `PG_WRITEBACK` set, **drop `cache.inner` and park on
     `page.wait` until `PG_WRITEBACK` clears**, then re-acquire and
     retry the sweep. This wait is mandatory — without it an in-flight
     `writepage` can commit stale data into blocks that the FS is
     concurrently freeing (the on-disk UAF surface raised by the
     filesystem reviewer's blocking finding).
  4. evicts the page (drops the cache strong ref + `frame::put`).
  5. returns to the FS, which then frees the on-disk blocks.

  PTEs in outstanding mappings into the truncated range are *not*
  invalidated by this RFC; per POSIX, accessing past EOF after a
  `ftruncate` is a SIGBUS, and the slow-path bounds recheck described
  in `FileObject::fault` (re-reads `i_size` after acquiring
  `cache.inner`) makes this correct on uniproc. See Open Question on
  TLB shootdown for the deferred SMP story.

- **`ftruncate(fd, new_size)` grow.** Lands as a metadata-only update
  on the inode (`i_size := new_size`, no block allocation). The cache
  takes the new `i_size` via `truncate_grow_to(new_size)`; subsequent
  faults into the extended range fault via the `readpage` slow path,
  which sees an unallocated indirect-block pointer and zero-fills the
  cache page (sparse hole). The first `MAP_SHARED + write` to such a
  page transitions through `writepage`, which **must allocate**: see
  §"writepage block allocation" below.
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
| `mmap(addr, len, prot, flags, fd, off)` | When `fd != -1` and `MAP_ANONYMOUS` is **not** set, look up the `OpenFile`, validate `prot` against open flags (see errno table below), call `OpenFile::file_ops.mmap(...)`, plug the returned `VmObject` into the VMA tree. **`MAP_SHARED + PROT_WRITE` requires `O_RDWR`** (not `O_WRONLY` — the write-fault path must read the page on miss before mutating it; an `O_WRONLY`-opened file cannot service that read). `MAP_ANONYMOUS` ignores `fd` per Linux semantics. |
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
| File type not mmappable (socket, FIFO, directory) | `ENODEV` |
| `MAP_SHARED + PROT_WRITE` and `OpenFile.f_mode` is not `O_RDWR` (i.e. `O_RDONLY` *or* `O_WRONLY`) | `EACCES` |
| `MAP_PRIVATE + PROT_WRITE` on `O_WRONLY` open (cannot read on miss) | `EACCES` |
| `off` not page-aligned | `EINVAL` |
| `len == 0` | `EINVAL` |
| `off + len` overflows `off_t` | `EOVERFLOW` |
| `off + len` past `i_size` | **succeeds** — Linux/POSIX `mmap` is allowed past EOF; SIGBUS surfaces at fault time when the page is touched (matches Linux `mmap(2) NOTES`) |
| Out of memory installing VMA | `ENOMEM` |
| Cache-fill OOM at fault time | SIGBUS (signal, not errno) |
| Sparse hole at `pgoff` (no allocated block) | **succeeds** — `readpage` zero-fills the page; first `MAP_SHARED + write` fault dirties it, `writepage` allocates blocks per §writepage block allocation |

`mprotect` upgrade rules apply the same `f_mode` snapshot stored on
the VMA: `PROT_WRITE` cannot be added to a Shared mapping whose
`open_mode` was not `O_RDWR`; `PROT_EXEC` cannot be added to a
mapping whose backing file was not opened with execute permission
(no separate `O_EXEC` flag exists, so this check uses the
`Inode.permission(EXECUTE)` result snapshotted at `mmap` time).

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
- **Mutex granularity (split-lock from day 1).** The per-inode mutex
  is **split** between the cache *index* and per-page *state*:
  - `PageCacheInner.pages` (`BTreeMap`) and `PageCacheInner.dirty`
    (`BTreeSet`) sit under one `BlockingMutex` — held only for the
    O(log n) lookup/insert/remove and dropped immediately.
  - `CachePage.state` is `AtomicU8` and `CachePage.wait` is its own
    `WaitQueue` — neither requires the index mutex to access. The
    fast path holds the index mutex for the lookup, drops it,
    releases the page atomic operations independently.

  This split is identical in shape to Linux's `i_pages` (XArray, lock
  per leaf) + per-folio `flags`/`waitqueue`. On uniproc the
  index mutex is uncontended; on SMP, the per-page state path lets
  faults against the same inode but different pages proceed in
  parallel, with only the index lookup serialised. This is the
  performance-engineer's "option (b)" — split-lock from day one —
  picked over a future BTreeMap → concurrent_btree swap because
  the migration path of swapping the index data structure is
  drop-in (it's already behind one mutex), whereas re-architecting
  the page state to a per-page lock *post hoc* is invasive.
  Cost: ~16 bytes per `CachePage` for the wait-queue (already in
  the structure). No additional RAM for the split.

- **Cache-line-friendly `CachePage`.** Padded to 64 bytes via
  `#[repr(align(64))]` so `state` does not false-share with the next
  `CachePage`'s metadata on SMP. Uniproc cost: zero. Acknowledges
  the perf-reviewer advisory A2.
- **Readahead policy (heuristic, not blanket).** The default
  read-ahead window is **0 pages** for a "cold" inode (no prior
  faults observed). The cache tracks a tiny per-inode read-ahead
  state (`ra_state: { last_pgoff, hit_streak }`); on each miss:
  - if `pgoff == ra_state.last_pgoff + 1`, increment `hit_streak`;
  - if `hit_streak >= 2`, set the next miss's read-ahead window to
    `min(2^hit_streak, RA_MAX_PAGES)` (cap `RA_MAX_PAGES = 8`);
  - on any non-sequential miss, reset to 0.

  This is the same exponential-ramp Linux's `file_ra_state` uses,
  miniaturised. `posix_fadvise(POSIX_FADV_SEQUENTIAL)` and
  `madvise(MADV_SEQUENTIAL)` (when implemented) jump straight to the
  cap; `POSIX_FADV_RANDOM` / `MADV_RANDOM` permanently disable
  read-ahead for the inode. The execve fault stream — typically not
  sequential past the first few pages — observes 0 read-ahead until
  `_start` -> `.text` produces a streak. This addresses the
  performance-engineer blocking finding that an unconditional
  8-page read-ahead would *increase* cold-execve latency.
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

All open questions are **deferred to implementation** — none block
the design as accepted.

- [ ] **rootfs block size.** Recommend flipping to 4 KiB in the same
  epic that lands the page cache (decided: 4 KiB; track as a small
  bring-up issue alongside Workstream C).
- [ ] **In-place buffer hand-off vs always-memcpy.** Ship the
  always-memcpy path first; revisit zero-copy as a follow-up perf
  RFC if the ~1 µs/page memcpy shows up in profiles.
- [ ] **`msync(2)` syscall.** Deferred to a follow-up. Writeback
  daemon + `fsync` covers durability; no current userspace caller.
- [ ] **TLB shootdown on truncate / page eviction.** Out of scope
  (uniproc). Resolved by SMP RFC.
- [ ] **`MAP_HUGETLB`, `MAP_LOCKED`, `MAP_NORESERVE`.** Rejected
  with `EINVAL` for the initial implementation. Each lands as a
  small follow-up RFC if a userspace caller appears.
- [ ] **`mincore`, `posix_fadvise`.** Cache trivially supports both;
  ship if a userspace caller materialises during the implementation
  epic.
- [ ] **`MAP_SHARED` over `tarfs`/`ramfs`.** Override `FileOps::mmap`
  to return `AnonObject`-style backing; document in the FS impls.
  No writeback; tarfs is read-only by mount semantics.
- [ ] **`ra_state` placement (per-inode vs per-OpenFile).** Pick
  per-`PageCache` for MVP; revisit when concurrent-readers-of-same-
  file becomes a measured workload (Performance cycle-2 A1).
- [ ] **`dirty_ratio` writer-throttling.** Linux-style throttle
  knob to bound `cache.dirty` growth under sustained pressure.
  Defer to a follow-up perf RFC (Performance cycle-1 A3).

### Resolved during peer review

**Defense cycle 1** (six archetype reviewers, all `CHANGES REQUESTED`):

- *Security B1* — `f_mode` snapshot now lives explicitly on
  `FileObject.open_mode`; `mprotect` consults it. (§Key data
  structures, §Errno table.)
- *Security B2* — `readpage` filler-error contract spelt out:
  remove from index, drop strong ref, clear `PG_LOCKED`, wake
  waiters, free stub frame, surface `VmFault::ReadFailed`. No
  uninitialised tail bytes leak via SIGBUS-restart cycles.
  (§Algorithms, fault slow path.)
- *Security B3* — `FileObject` is bound to its `Arc<PageCache>`
  for life and never rebound; second execve of the same path
  resolving to a different inode constructs a fresh object.
  (§Inode-binding rule.)
- *OS B1* — IRQ discipline made explicit: the page-fault handler
  STIs after the pure-logic verdict, drives the slow path with
  IRQs enabled, then CLI before the PTE install. (§Page-fault IRQ
  discipline.)
- *OS B2* — `PG_LOCKED`/`PG_UPTODATE` ordering specified Acquire/
  Release; full state transition table in §State-bit ordering.
- *OS B3* — `Arc::strong_count` and `mem::refcount` now have
  explicit, non-overlapping responsibilities. (§Refcount discipline.)
- *OS B4* — Truncate-vs-fill race fixed: `truncate_below` updates
  `i_size` under `cache.inner` before evicting; the fault slow
  path re-checks `pgoff < i_size_pages_locked()` after install.
- *Userspace B1* — Errno table corrected: `mmap` past `i_size`
  succeeds; SIGBUS surfaces at fault. `EOVERFLOW` on `off + len`
  overflowing `off_t`.
- *Userspace B2* — `MAP_SHARED + PROT_WRITE` requires `O_RDWR`,
  not `O_RDWR or O_WRONLY`. Errno table updated.
- *Userspace B3* — `fdatasync` semantics specified to skip
  inode-table flush when no blocks were allocated; matches Linux
  per-API distinction.
- *Academic B1* — Eviction liveness: bounded direct-reclaim wait
  on the writeback-completion waitqueue, with a 2 s soft cap
  before surfacing SIGBUS. Faults under contention no longer
  silently spuriously fail. (§Eviction liveness.)
- *Filesystem B1* — `MAP_SHARED + ftruncate-up + write` path
  fully specified: `writepage` allocates blocks via the ext2
  bitmap allocator with RFC 0004 §create normative ordering.
  (§writepage block allocation.)
- *Filesystem B2* — `truncate_below` parks on `PG_WRITEBACK`
  before evicting and freeing on-disk blocks, closing the
  on-disk-UAF surface. (§Truncate, unmap, MADV_DONTNEED.)
- *Filesystem B3* — Per-block ordering inside `writepage`
  (data-block synced before parent indirect-block) made
  normative. (§Ordering vs fsync.)
- *Performance B1* — Split lock from day one: index mutex is
  separate from per-page state atomics + per-page wait-queue,
  matching Linux's i_pages-XArray + per-folio locking shape.
- *Performance B2* — Read-ahead policy is now an exponential
  ramp gated on observed sequential access; cold-execve sees 0
  read-ahead until a streak develops.

Also folded in: read-after-writeback invariant (Academic A1),
sparse-hole zero-fill (Userspace A5), wb_err errseq counter
(Filesystem A1), full lock-order ladder (OS A4), inode-meta lock
position (OS A4), `mprotect` PROT_EXEC rule (Userspace A3),
`MAP_ANONYMOUS + fd != -1` Linux compatibility (Userspace A1),
`mmap` of directory errno (Userspace A2).

**Defense cycle 2** (one residual blocker, five LGTM):

- *OS B1 (lock-order per-inode parallelism)* — §Lock-order section
  now states normatively that level 4 is per-inode and does not
  nest; helpers iterating across inodes must release one
  `cache.inner` before acquiring another's. `writeback_complete_wq`
  pinned at level 6.5; observers of `PG_DIRTY` use Acquire-load
  symmetric to the AcqRel writer (OS A2). Direct-reclaim retry
  semantics clarified: per-event retry on every wake until the 2 s
  soft cap (OS A1). `Arc::strong_count`-Drop wakes added to the
  `writeback_complete_wq` kicker set (Performance A2). Empty
  `mmap` and tail-of-extended-page test cases added to the test
  plans (Userspace A1, A2). Crash-test inverse (kill mid-truncate
  → fsck no-orphan-blocks) added (Filesystem A1). Direct-reclaim
  framed as an availability trade-off in §Eviction liveness
  (Academic A1).

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

- [ ] arch/x86_64/idt: rework page-fault gate to STI after the pure-logic verdict and CLI before PTE install + IRET; mandatory before any blocking-mutex slow path can be exercised (§Page-fault IRQ discipline)
- [ ] mem: introduce `PageCache`, `CachePage`, `PG_*` state bits with documented Acquire/Release transitions; per-cache `BlockingMutex<PageCacheInner>` (BTreeMap pages + BTreeSet dirty); `CachePage` is `#[repr(align(64))]`
- [ ] mem: `AddressSpaceOps` trait (`readpage`/`writepage`/`readahead`/`truncate_below`) with default no-op `readahead`/`truncate_below`
- [ ] mem: `FileObject : VmObject` with `share`-aware `fault`, `open_mode` snapshot, per-VMA `private_frames` map; `frame_at`/`clone_private`/`truncate_from_page`/`evict_range`
- [ ] mem: page-fault path threads `VmFault::CoWNeeded`, `VmFault::ParkAndRetry`, `VmFault::ReadFailed(errno)` into the existing resolver — re-uses `cow_copy_and_remap` unchanged for CoW
- [ ] mem: page-cache CLOCK-Pro eviction with the four buffer-cache invariants + the bounded direct-reclaim wait (2 s cap, configurable; parks on writeback-completion waitqueue) before surfacing `ENOMEM`/SIGBUS; host unit tests for skip-pinned, skip-DIRTY, no-victim, direct-reclaim-progress
- [ ] mem: per-inode read-ahead heuristic (`ra_state: { last_pgoff, hit_streak }`) — exponential ramp on sequential, hard reset on non-sequential; cap `RA_MAX_PAGES = 8`
- [ ] mem: **invariant assertions (runtime, not debug-only)** — `assert_no_spinlocks_held()` at the top of every `AddressSpaceOps` method; `cache.inner` not held across `readpage`/`writepage`
- [ ] mem: refcount-discipline tests — `Arc::strong_count(CachePage)` vs `mem::refcount::get(phys)` gating eviction independently; verify a cache page held only by an installed PTE is *not* evicted
- [ ] mem: host-side cold-mmap fault-latency benchmark (microseconds per page) reported by `cargo xtask bench page-cache`; first run establishes a baseline for CI regression detection

### Workstream B — VFS plumbing (wave 1)

- [ ] vfs: add `FileOps::mmap(f, file_offset, len_pages, share, prot) -> Result<Arc<dyn VmObject>, i64>` defaulting to `ENODEV`
- [ ] vfs: extend `Inode` with `mapping: Option<Arc<PageCache>>` (gated by `#[cfg(feature = "page_cache")]` initially); construct lazily on first mmap or first read; the cache holds a `Arc<dyn AddressSpaceOps>` captured from the inode at construction (inode-binding rule)
- [ ] sys: rewire `sys_mmap` for `fd != -1` — look up `OpenFile`, validate per the new errno table (`EACCES` for `MAP_SHARED + PROT_WRITE` without `O_RDWR`; `EOVERFLOW` on `off + len`; **succeed** past `i_size`; `MAP_ANONYMOUS` ignores `fd`), call `FileOps::mmap`, snapshot `open_mode` onto the returned `FileObject`, plug into VMA tree; preserve `MAP_FIXED`/`MAP_FIXED_NOREPLACE` semantics
- [ ] sys: extend `mprotect` — consult `FileObject.open_mode` snapshot; reject `PROT_WRITE` upgrades on `MAP_SHARED` mappings whose `open_mode` is not `O_RDWR` (`EACCES`); reject `PROT_EXEC` upgrades on mappings backed by a non-executable inode at `mmap` time (`EACCES`)
- [ ] sys: extend `fsync(fd, data_only=false)` to flush `inode.mapping.dirty` (calls `writepage` on each), then `BlockCache::sync_fs(sb_dev)`; surface `EIO` if `mapping.wb_err` advanced since the `OpenFile`'s last fsync snapshot (errseq pattern)
- [ ] sys: implement `fdatasync` (the `data_only=true` path) — same data flush, **skip** inode-table-buffer sync when no allocation occurred; allocation flushes are issued inside `writepage` so they're already on stable storage

### Workstream C — ext2 AddressSpaceOps (wave 2, blocks on A + B + RFC 0004 #537 — already merged)

- [ ] fs/ext2: implement `AddressSpaceOps::readpage` for `Ext2Inode` — walks indirect blocks, `bread`s through the buffer cache, memcpys 4 KiB into the page, zero-fills the `[i_size .. page_end)` tail; sparse holes (indirect-block pointer == 0) zero-fill the whole page; on `Err`, returns a faithful errno that the page-cache filler propagates
- [ ] fs/ext2: implement `AddressSpaceOps::writepage` — split into block-sized fragments; **for unallocated underlying blocks**, call into the bitmap allocator (RFC 0004 Workstream E machinery) and follow the normative ordering: bitmap → indirect-block → data block, each via `sync_dirty_buffer`; rollback on per-block failure; updates `i_blocks` and `i_size` only after the data write succeeds
- [ ] fs/ext2: hook `truncate_below` into `setattr(size)` — wait on every `PG_WRITEBACK` page in the truncated range to drain *before* the FS frees the on-disk blocks (closes the on-disk UAF surface); evict, then return to the FS for block free
- [ ] fs/ext2: cache-readahead implementation — heuristic-driven (per Workstream A's `ra_state`); never holds the cache mutex; bounded by buffer-cache invariants
- [ ] fs/ext2: implement `FileOps::mmap` returning `Arc<FileObject>` with the inode's lazily-constructed `mapping` and the `OpenFile.f_mode` snapshot
- [ ] fs/ext2: route `FileOps::read` through the page cache when present (so a `read` after `mmap` and a `read` without share the same backing copy); fall back to direct `bread` if `mapping` is `None`

### Workstream D — Writeback daemon extension (wave 2)

- [ ] block: extend the per-mount writeback daemon to walk every superblock-mounted inode's `mapping` and call `writepage` on every dirty pgoff (snapshot-collect under cache mutex, write outside; the snapshot-then-writepage discipline keeps a concurrent writer's re-dirty observable for the next sweep)
- [ ] block: writeback ordering — page-cache pages flushed first (`writepage` does its own bitmap → indirect → data ordering internally), then `BlockCache::sync_fs`; matches RFC 0004 §create normative ordering
- [ ] block: `sync(2)` / `sync_fs(sb)` triggers an immediate page-cache + buffer-cache flush (no waiting for the next interval)
- [ ] block: writeback-completion waitqueue (`writeback_complete_wq` per cache, kicked after every `writepage` returns and from `CachePage::Drop` when strong-count reaches 1); the eviction direct-reclaim path parks on this with the configurable 2 s soft cap; per-event retry on each wake until the cap expires
- [ ] block: per-cache `wb_err: AtomicU32` errseq counter; advanced on every `writepage` failure; `OpenFile` snapshots at `open` and re-reads at `fsync` to surface a sticky `EIO`
- [ ] block: writeback-daemon unit + integration tests (kernel test marker) — one MAP_SHARED writer, kill -9 mid-flight, verify the next mount sees a consistent prefix; truncate-vs-writeback race test verifies no on-disk UAF; **inverse**: kill mid-truncate (between `truncate_below` evict and FS block-free), verify next-mount fsck reports zero orphan blocks; sparse-then-extend test (mmap-extended file, write *some* pages via MAP_SHARED, verify reads see zeros for unwritten holes); empty-file mmap test (zero-length file + len > 0, expect SIGBUS at fault); tail-page zero test (mmap last partial page of a freshly-extended file, read tail beyond i_size, expect zeros)

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
