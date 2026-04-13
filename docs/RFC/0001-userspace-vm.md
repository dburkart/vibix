---
rfc: 0001
title: Userspace Virtual Memory Subsystem
status: In Review
created: 2026-04-13
---

# RFC 0001: Userspace Virtual Memory Subsystem

## Abstract

This RFC proposes a per-process userspace virtual memory subsystem for vibix.
It introduces a three-layer model — `AddressSpace` (per-process, owns one
PML4), `Vma` (a per-process region descriptor in a sorted interval map), and
`VmObject` (a refcounted backing object: anonymous, copy-on-write, or
file-backed in the future) — together with a redesigned `#PF` resolver, a
small POSIX-shaped syscall surface (`mmap`, `munmap`, `mprotect`, `brk`), and
a TLB-flush abstraction that is a no-op on the current single-CPU kernel but
preserves the API shape needed for SMP shootdown. The design replaces today's
flat `VmaList` with structures that can split, merge, and clone for `fork()`,
unblocking issues #123 (process model), #132 (task exit / reclaim), and #133
(CoW + remove) on the P0 critical path to PID 1.

## Motivation

Vibix today has a working physical frame allocator, kernel paging, a kernel
heap, and a minimal per-task `VmaList` with two backing kinds (`AnonZero`,
`Cow`). The list is flat, supports neither partial unmap nor merge, panics on
overlap rather than rejecting, and exposes no syscall surface. The page-fault
handler in `kernel/src/arch/x86_64/idt.rs` dispatches directly on the current
task's `VmaList` and has no concept of an address space distinct from a task.

To launch PID 1 (issue #121) and run real userspace, four things must land:

1. **Per-process address-space objects** with their own PML4 (today's
   `new_task_pml4` exists but no struct owns it; #132 cannot reclaim it).
2. **A VMA representation that supports split/merge** so `mmap`/`munmap`/
   `mprotect` over partial ranges work — the bare minimum a libc allocator
   (musl/glibc-style) demands.
3. **CoW that survives `fork()`** with correct refcount semantics — #133
   landed `VmaKind::Cow` over a single source frame, but a real fork must
   share *every* page in the parent address space, not one.
4. **Userspace-facing syscalls** for `mmap`/`munmap`/`mprotect`/`brk` so
   userspace can grow its heap and stack and arrange its loader segments.

This RFC defines the data structures, fault-handling protocol, syscall
semantics, and lifecycle (build, clone-for-fork, teardown) that make those
four work together. It deliberately does **not** yet add file-backed mappings,
swap, NUMA, or huge pages — but it leaves the type lattice room for them.

## Background

### What vibix has today

- `kernel/src/mem/frame.rs` — `BitmapFrameAllocator` over up to 4 GiB of RAM,
  ~O(1) alloc/free.
- `kernel/src/mem/paging.rs` — `OffsetPageTable` over the active PML4,
  `map_range`, `unmap_page`, kernel-PML4 build-and-switch.
- `kernel/src/mem/heap.rs` — 16 MiB grow-on-demand kernel heap.
- `kernel/src/mem/vma.rs` — `Vma { start, end, kind, flags }`, `VmaList`
  (flat `Vec`, no merge/split), `VmaKind::{AnonZero, Cow{frame}}`.
- `kernel/src/arch/x86_64/idt.rs:page_fault` — fault handler that walks the
  current task's `VmaList`, allocates a frame for `AnonZero`, copies for `Cow`.
- `kernel/src/task/task.rs` — `NEXT_STACK_VA` bump allocator, no exit path.

### What other kernels do

**Linux** (per `Documentation/mm/process_addrs.html`,
`mm/{memory,mmap,mprotect,rmap,mmu_gather}.c`): `mm_struct` owns a maple tree
of `vm_area_struct`. Faults arrive at `do_user_addr_fault` →
`handle_mm_fault` → `handle_pte_fault`, which dispatches to
`do_anonymous_page`, `do_swap_page`, `do_wp_page` (CoW), or `do_fault`
(file-backed). Locking is hierarchical: `mmap_lock` (rwsem) protects the
maple tree; per-VMA `vm_lock_seq` (since 6.4) lets faults proceed without
contending for it; `pte_offset_map_lock` provides per-PTE locks.
`copy_page_range` in `kernel/fork.c:dup_mmap` strips R/W on every PTE in both
parent and child, leaving them pointing at the same frames, and `do_wp_page`
unshares on first write.

**SerenityOS** (`Kernel/Memory/`): three layers — `AddressSpace` owns a
`PageDirectory` and an intrusive RB-tree `RegionTree`; each `Region` is a
slice into a refcounted `VMObject` (`AnonymousVMObject` /
`InodeVMObject`); CoW state lives in the VMObject as a `Bitmap m_cow_map`.
`Region::handle_fault` dispatches on access type and PTE state to typed
sub-handlers.

**Redox** (`src/context/memory.rs`): one-layer `Grant` (VMA + backing kind
in one enum) inside an `AddrSpace { table, grants: BTreeMap<Page, GrantInfo>,
used_by: CpuSet }`. CoW is tracked per *physical frame* via a global
`PageInfo` array (`AtomicUsize` refcount per 4 KiB frame), distinguishing
`RefCount::{One, Cow(n), Shared(n)}`. A `Flusher` carries a CPU set and a
`tlb_ack` counter through every mapper call, abstracting single-CPU and
SMP shootdown behind one interface.

### x86-64 hardware contract

From the Intel SDM Vol. 3A:

- 4-level paging walks PML4 → PDPT → PD → PT, ANDing R/W and U/S and ORing
  XD across the four entries (§4.6). A user-RW-NX leaf is useless if any
  upper entry lacks U/S=1.
- `#PF` (vector 14) pushes an error code with bits P, W/R, U/S, RSVD, I/D,
  PK, SS (§4.7); CR2 holds the faulting linear address. The bit-tuple is
  enough to classify demand-page-on-write ({P=0, W/R=1, U/S=1}), CoW write
  fault ({P=1, W/R=1, U/S=1}), kernel bug (RSVD=1), and SMAP violation
  (kernel-mode CPL with U/S=1 and AC=0).
- TLB caches *any* walk whose entries had P=1 (§4.10). Software must
  `INVLPG` / `MOV CR3` after narrowing permissions, clearing P, or
  remapping a frame; widening permissions is safe to skip but most kernels
  flush anyway for determinism. Global pages (G + CR4.PGE) survive CR3
  reloads — reserve for the kernel half. PCIDs (CR4.PCIDE) tag TLB entries
  by 12-bit ID and are the standard fast-context-switch path.
- SMEP/SMAP/UMIP (CR4 bits 20/21/11) harden the kernel/user boundary;
  copy-from/to-user must bracket with STAC/CLAC.

### POSIX surface

POSIX.1-2017 mandates `mmap`/`munmap`/`mprotect`/`posix_madvise`. The
core required behaviour: `len==0 → EINVAL`, page-aligned addresses,
PROT_NONE/READ/WRITE/EXEC bits, MAP_PRIVATE xor MAP_SHARED, and partial
sub-range support for `munmap`/`mprotect` (so VMAs must split). MAP_FIXED
silently evicts overlapping mappings; MAP_FIXED_NOREPLACE (Linux 4.17) is
strictly safer. `brk`/`sbrk` is LEGACY but ubiquitous — glibc/musl `malloc`
uses it for small allocations and `mmap` for large ones, so a stub `brk`
plus working `mmap` is sufficient to run a real allocator.

## Design

### Overview

```
Process (per-task)
  └── Arc<AddressSpace>
        ├── VmaTree                    (BTreeMap<usize, Vma>, keyed by start)
        │     └── Vma { start, end, prot, share, Arc<dyn VmObject> }
        ├── PageTable (PML4 frame + offset mapper)
        └── statistics (rss, vm_size, mappings)

VmObject (trait, refcounted via Arc)
  ├── AnonObject       — zero-fill on first touch, frames owned by object
  ├── CowChildObject   — view of another AnonObject with private overrides
  └── (future) FileObject, PhysObject

global  PageRefcount[]  — one AtomicU16 per 4 KiB physical frame (CoW refcounts)
```

A **task** holds an `Arc<AddressSpaceLock>` (an `RwLock<AddressSpace>`).
Multiple tasks (threads of the same process, eventually) share one
`AddressSpace`. `fork()` produces a new `AddressSpace` whose VMAs reference
the same `VmObject`s but whose page tables have all writable user PTEs
demoted to read-only and whose corresponding frames have refcount bumped.

### Key Data Structures

**`AddressSpace`** (`kernel/src/mem/addrspace.rs`, new):

```rust
pub struct AddressSpace {
    /// Per-process PML4; the lower half (entries 0..256) is user-owned,
    /// the upper half (entries 256..512) is shared with the kernel and
    /// installed at construction by copying the canonical kernel PML4.
    page_table: PageTable,
    /// Sorted interval map of user VMAs. Half-open [start, end).
    vmas: VmaTree,
    /// First valid user VA (initial mmap hint floor).
    mmap_base: VirtAddr,
    /// brk window: [brk_start, brk_cur), grown by `sys_brk`.
    brk_start: VirtAddr,
    brk_cur: VirtAddr,
    brk_max: VirtAddr, // hard cap (e.g., mmap_base - guard)
    /// Counters for diagnostics and rlimits.
    rss_pages: usize,
    vm_pages: usize,
}
```

`AddressSpace` is wrapped in `RwLock<AddressSpace>` (vibix's existing
sync primitive). The lock is a single rwsem-equivalent — read for fault
resolution, write for `mmap`/`munmap`/`mprotect`/`fork`. SMP per-VMA
sequence locks (Linux ≥ 6.4) are explicitly out of scope; the API leaves
room (see `Vma::lock_seq` placeholder below).

**`Vma`** (replaces today's `kernel/src/mem/vma.rs`):

```rust
pub struct Vma {
    pub start: VirtAddr,         // page-aligned
    pub end:   VirtAddr,         // page-aligned, exclusive
    pub prot:  Prot,             // R/W/X bitset
    pub share: ShareMode,        // Private | Shared
    pub object: Arc<dyn VmObject>,
    pub object_offset: usize,    // bytes into the VmObject this VMA starts at
    pub flags:  VmFlags,         // GROWSDOWN, LOCKED, STACK, …
    /// Reserved for future per-VMA SMP sequence lock; unused on UP.
    _lock_seq: u32,
}
```

**`VmaTree`**: a `BTreeMap<usize, Vma>` keyed by `start` for O(log n)
lookup, split, and merge. `find(addr)` does `range(..=addr).next_back()` and
checks `addr < vma.end`. We pick BTreeMap over a maple-tree-like custom
structure because the standard library's BTreeMap is already in use, and
typical address spaces have ≤ ~100 VMAs. Iterators are exposed as the
public API (no `vm_next` pointers) so a maple-tree-equivalent can replace
the implementation later without breaking callers.

**`VmObject`** (trait):

```rust
pub trait VmObject: Send + Sync {
    /// Resolve the frame backing `offset` (page-aligned), allocating if
    /// needed. The returned frame must be installed into the caller's PT.
    fn fault(&self, offset: usize, access: Access) -> Result<PhysFrame, VmFault>;
    /// Number of pages this object covers; None for unbounded (e.g., heap).
    fn len_pages(&self) -> Option<usize>;
    /// Hint: clone for fork. Default implementation returns Arc::clone(self);
    /// AnonObject implementations override to split CoW state if needed.
    fn clone_for_fork(self: Arc<Self>) -> Arc<dyn VmObject> { self.clone() }
}
```

Concrete implementations:

- `AnonObject`: zero-fill on `fault`. Frame is allocated, zeroed via HHDM,
  cached in an internal sparse table (`BTreeMap<usize, PhysFrame>`), and
  returned. Drop frees all backing frames whose refcount falls to zero.
- `CowChildObject { parent: Arc<AnonObject>, overrides: BTreeMap<usize, PhysFrame> }`:
  read faults return `parent.fault()`; write faults trigger PTE-level CoW
  resolution in the page-fault path (see Algorithms below) — the `VmObject`
  itself does not allocate.

**Global `PageRefcount`** (`kernel/src/mem/refcount.rs`, new): a static
array of `AtomicU16`, one entry per usable 4 KiB physical frame
(MAX_PHYS_BYTES / 4096 = 1,048,576 entries × 2 bytes = 2 MiB at 4 GiB). The
allocator initialises a frame's refcount to 1 on `alloc`, increments on
share, decrements on unmap, and frees the frame when it drops to 0. This
mirrors Redox's `PageInfo`. Refcount widening from 16-bit can happen later;
16 bits cover up to 65,535 sharers, ample for fork chains.

### Algorithms and Protocols

**Page-fault dispatch**, replacing `idt.rs:page_fault` (signature unchanged):

```
on #PF (cr2, error_code, in_kernel_mode):
  if in_kernel_mode and error_code.user_bit() == 0:
    // existing kernel-fault path (panic / IST handling) unchanged
    return existing_kernel_fault(...)

  let aspace = current_task.address_space.read();
  let vma = match aspace.find(cr2) {
    Some(v) => v,
    None    => return deliver_sigsegv(SI_MAPERR),
  }

  let access = Access::from_error_code(error_code);

  // Permission check first — protection violation never falls through to
  // the resolver.
  if !vma.prot.allows(access):
    return deliver_sigsegv(SI_ACCERR)

  // Reserved-bit fault is always a kernel bug.
  if error_code.rsvd() { panic("PTE reserved-bit corruption at {cr2}") }

  match (error_code.present(), access.is_write()) {
    (false, _)    => resolve_demand_page(&aspace, vma, cr2, access),
    (true, true)  => resolve_cow(&aspace, vma, cr2),
    (true, false) => spurious_fault_retry(),  // widening race; just return
  }
```

`resolve_demand_page` calls `vma.object.fault(offset, access)`, then maps
the returned frame at `cr2 & !0xFFF` with `vma.prot`'s flags, bumping the
frame's refcount.

`resolve_cow` is the write-on-CoW path:

```
let pte = aspace.page_table.lookup_mut(cr2);
let old_frame = pte.frame();
let rc = page_refcount(old_frame).fetch_sub(1, Acquire);
if rc == 1:
  // we were the last sharer — just upgrade to writable in-place.
  pte.set_writable(true);
  invlpg(cr2);
else:
  // need a private copy.
  let new_frame = frame_alloc()?;
  copy_4k_via_hhdm(old_frame, new_frame);
  pte.set_frame(new_frame); pte.set_writable(true);
  invlpg(cr2);
  // old_frame's refcount already decremented above.
```

The single-sharer fast path matches Linux's `wp_page_reuse` and Serenity's
`if (page_slot->ref_count() == 1)` optimisation.

**`fork()` page-table copy** (called from process duplication):

```
fn fork_address_space(parent: &AddressSpace) -> Result<AddressSpace, Errno> {
  let mut child = AddressSpace::new_empty()?;   // fresh PML4, kernel half copied
  for vma in parent.vmas.iter():
    let child_vma = vma.clone_metadata(); // same object, same offset, same prot
    if vma.share == ShareMode::Private:
      // CoW both sides: walk PTEs in [vma.start, vma.end), strip W in
      // parent, install identical PTE (also W-stripped) in child, and
      // bump page_refcount[frame].
      for (va, pte) in parent.page_table.range_mut(vma.start, vma.end):
        if pte.is_present():
          pte.set_writable(false);
          page_refcount(pte.frame()).fetch_add(1, Release);
          child.page_table.install(va, pte.value());
      // queue local INVLPGs (or full TLB flush; see Performance below)
    else:
      // Shared: PTEs simply duplicated, no W-strip. Refcount still bumps.
      for (va, pte) in parent.page_table.range(vma.start, vma.end):
        if pte.is_present():
          page_refcount(pte.frame()).fetch_add(1, Release);
          child.page_table.install(va, pte.value());
    child.vmas.insert(child_vma);
  Ok(child)
}
```

The W-strip happens in the *parent* as well as the child. Both sides take
a write fault on first store and CoW-resolve independently.

**`mmap` / `munmap` / `mprotect`** all flow through three primitives on
`VmaTree`: `insert(vma)` (with merge), `unmap_range(start, end)` (with
split at boundaries), `change_protection(start, end, new_prot)` (with
split + merge). Splits clone the `Arc<dyn VmObject>`; merges require the
adjacent VMAs to have matching prot/share/object/object_offset and be
contiguous.

**TLB invalidation** is funnelled through a `Flusher` (`kernel/src/mem/tlb.rs`):

```rust
pub struct Flusher<'a> {
    aspace: &'a AddressSpace,
    actions: TlbActions,    // bitset: NewMapping, RevokeWrite, FreeFrame, Move
    pages: SmallVec<[VirtAddr; 16]>,
}
impl<'a> Flusher<'a> {
    pub fn invalidate(&mut self, va: VirtAddr) { self.pages.push(va); }
    pub fn finish(self) {
        // UP today: just INVLPG locally on every queued page (or MOV CR3
        // if more than 32 entries — heuristic threshold).
        for va in self.pages { unsafe { x86::tlb::flush(va) } }
        // SMP later: send TLB-shootdown IPIs to aspace.used_by, spin on ack.
    }
}
```

Every mapper mutation (`mmap`, `munmap`, `mprotect`, `fork_address_space`)
takes `&mut Flusher`. Today's UP implementation is trivial; the abstraction
lets SMP shootdown drop in without touching every call site.

### Kernel–Userspace Interface

Syscall numbers are assigned in the same series as #125 (mmap was already
slated). The minimal POSIX-shaped surface:

| nr  | name        | signature                                                | min impl                       |
|-----|-------------|----------------------------------------------------------|--------------------------------|
| TBD | `mmap`      | `(addr, len, prot, flags, fd, off) → addr`               | anon-private only; `fd=-1`     |
| TBD | `munmap`    | `(addr, len) → 0`                                        | partial sub-range, splits VMAs |
| TBD | `mprotect`  | `(addr, len, prot) → 0`                                  | partial sub-range, splits VMAs |
| TBD | `brk`       | `(addr) → new_break`                                     | grow/shrink anon region        |
| TBD | `madvise`   | `(addr, len, advice) → 0`                                | accept all, no-op              |

Errnos follow POSIX strictly:

- `mmap`: `EINVAL` (`len == 0`, unaligned addr under MAP_FIXED, both/neither
  of MAP_PRIVATE/MAP_SHARED, unknown bits in flags), `ENOMEM` (no room or
  RLIMIT_AS), `EBADF`/`EACCES` (deferred — file-backed not yet supported,
  return `ENOTSUP` for `fd != -1`), `EEXIST` for MAP_FIXED_NOREPLACE.
- `munmap`/`mprotect`: `EINVAL` (`len == 0`, unaligned addr), `ENOMEM`
  (range covers unmapped pages — POSIX-conformant strictness).
- `brk`: returns the *current* break; never sets errno.

Supported flags (vibix-init):

```
MAP_PRIVATE         0x02
MAP_SHARED          0x01     // returns ENOTSUP without a backing object
MAP_FIXED           0x10
MAP_FIXED_NOREPLACE 0x100000
MAP_ANONYMOUS       0x20
MAP_GROWSDOWN       0x100    // marks VMA; growth happens in fault handler
MAP_STACK           0x20000  // no-op marker
```

PROT bits: `PROT_NONE=0`, `PROT_READ=1`, `PROT_WRITE=2`, `PROT_EXEC=4`.
`PROT_WRITE` without `PROT_READ` is silently upgraded to RW (matches x86
hardware, where R is not separable).

`/proc` and `/sys` layouts: N/A — neither subsystem exists yet.

### Stack growth

A user stack is created as a `MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN`
VMA. On a `#PF` whose `cr2` is below `vma.start` but within
`stack_guard_gap` (256 pages, matching Linux), the resolver extends `vma.start`
downward by one page and installs the page. A guard VMA below the stack
(PROT_NONE, marked `STACK_GUARD`) catches over-runs and converts them to
SIGSEGV.

### Address-space teardown

`AddressSpace::drop` walks every VMA, calls `unmap_range` (which decrements
`page_refcount` on every present frame and frees those that hit 0), then
walks the lower half of the PML4 freeing every intermediate page-table
frame. The PML4 frame itself is freed last. This addresses #132's leak.

## Security Considerations

- **CR4 bits**: kernel enables SMEP, SMAP, UMIP (and NXE in EFER) early in
  `arch::init`; copy-to/from-user wraps with STAC/CLAC. The fault handler
  must reject any `#PF` whose CPL=0, U/S=1, AC=0 as an SMAP violation
  before consulting VMAs (otherwise a user-controlled address could probe
  kernel logic via fault-side-channels).
- **Kernel-half protection**: every per-process PML4 copies the canonical
  kernel PML4's upper-half entries (256–511) at construction. User code
  cannot modify these — its VMAs are clamped to `0..0x0000_8000_0000_0000`
  (canonical lower half).
- **Reserved-bit faults panic**: a `#PF` with RSVD=1 indicates the kernel
  itself wrote a malformed PTE. Continuing risks corrupting another address
  space; we panic with the faulting VA, frame, and PTE word.
- **Refcount overflow**: 16-bit per-frame refcount caps at 65,535 sharers.
  The fork path `checked_add(1)` and on overflow falls back to copying the
  frame eagerly (degenerate but safe). A future widen to `AtomicU32` is
  trivial; we accept the surface for now.
- **CoW race**: two CPUs may write-fault the same shared frame
  simultaneously. Resolution holds `aspace.write()`, which serialises
  resolution within an address space; cross-address-space CoW state is
  protected by the per-frame refcount's atomic decrement.
- **Information disclosure via fresh frames**: `AnonObject::fault` zeroes
  the frame *before* installing the PTE. This is a hard invariant — any
  code path that returns a frame to user space without zeroing first is a
  CVE.
- **MAP_FIXED hijacking**: classic MAP_FIXED can silently evict an
  existing mapping. We default to MAP_FIXED_NOREPLACE in the loader and
  document MAP_FIXED as last-resort — it is allowed but logs at info-level
  when it actually overwrites.
- **Stack/heap collision**: `brk_max` is enforced strictly; the stack
  VMA's growth is bounded to never collide with the highest mmap or with
  `brk_max`. A growth attempt that would collide returns SIGSEGV rather
  than overlapping a user mapping.
- **Speculative-execution side channels**: out of scope. KPTI / Meltdown
  mitigation is filed separately if/when it becomes relevant; vibix is
  bare-metal hobby and the threat model excludes hostile multi-tenant
  workloads.

## Performance Considerations

- **Hot path** is the page-fault resolver. Per fault: one `BTreeMap::range`
  lookup (O(log n) on ≤ ~100 VMAs), one `Arc::clone` of the VmObject, one
  page-table walk, one frame allocation in the demand-zero case, one
  `INVLPG`. No global locks except `aspace.write()`.
- **Address-space lock**: a single `RwLock` per `AddressSpace`. Read for
  fault, write for mmap-family. On UP with cooperative + preemptive
  multitasking, contention is between concurrent threads of the same
  process; today vibix has no threads, so contention is structurally zero.
  We accept the simple single-lock model and revisit if/when threads land.
- **TLB flush batching**: `Flusher` buffers up to 32 invalidations. Above
  that threshold it falls back to a full `MOV CR3, CR3` (cheaper than 32+
  `INVLPG`s on Intel uarch per SDM §4.10.4 commentary). PCID is not used
  in v1; switching `Cr3` flushes the entire TLB on context switch — a
  known cost we accept until PCID lands (separate RFC).
- **CoW refcount memory cost**: 2 MiB at 4 GiB physical RAM (one
  `AtomicU16` per 4 KiB frame). Acceptable; equivalent to one bitmap word
  per 32 frames, similar order to today's `BitmapFrameAllocator`.
- **VMA merging amortises allocator pressure**: a libc `malloc` that
  calls `mmap` repeatedly to grow its arena will be merged into a single
  VMA, keeping the BTreeMap small.
- **Fork cost**: O(P) where P is the number of present user pages — every
  PTE in the parent must be visited to strip W. This matches Linux. With
  `vfork`/`exec` userspace pattern (which we will support post-RFC) the
  parent's PTEs are never written between fork and exec, so the W-strip
  is rarely paid in practice.

## Alternatives Considered

1. **Keep the flat `VmaList` and add `mprotect`/`munmap` as range loops.**
   Rejected: any partial-range mutation requires splitting a VMA, which
   forces a sorted indexed structure regardless. Building it on a `Vec`
   with linear scans defeats the design before it lands.

2. **Adopt Redox's flat `Grant` enum (provider variant per backing).**
   Rejected: every new backing kind grows an enum that touches every
   match site (`PhysBorrowed`, `External`, `FmapBorrowed`, …). The trait-
   object `VmObject` keeps each backing's state encapsulated and is more
   idiomatic Rust.

3. **Adopt SerenityOS's per-VMObject `Bitmap m_cow_map` for CoW state.**
   Rejected: CoW state is fundamentally per-physical-frame (a frame might
   be shared between sibling forks via different VMObjects). A global
   per-frame refcount is the natural representation; SerenityOS's bitmap
   is a workaround for C++'s lack of cheap `Arc`.

4. **Defer per-process PML4 to a single global table with VMAs as views.**
   Rejected: prevents true address-space isolation. SMEP/SMAP only
   protect the boundary; isolation between user processes requires
   distinct PML4s.

5. **Implement maple tree directly.** Rejected as premature. BTreeMap is
   already in `alloc`, has the right asymptotic behaviour, and address
   spaces are small. The iterator-only public API leaves room to swap.

6. **Use Linux's `mmap_lock` rwsem + per-VMA seqlock from day one.**
   Rejected as over-engineering for a UP kernel. `Vma` reserves
   `_lock_seq: u32` to make the upgrade additive.

7. **Skip MAP_FIXED entirely.** Rejected: ELF loaders need it for
   PT_LOAD segments at fixed VAs. We do default new code to
   MAP_FIXED_NOREPLACE.

## Open Questions

- **PCID adoption**: when does the cost of full-TLB-flush on context
  switch start to bite? Likely after we have ≥ 4 long-running user
  processes. Track as follow-up RFC.
- **File-backed mappings**: design depends on the VFS layer (no RFC yet).
  This RFC keeps the `VmObject` trait shape that `FileObject` will fit;
  no on-disk semantics committed.
- **Threads / shared address spaces**: the `Arc<AddressSpaceLock>` model
  supports threads natively, but the syscall API for `clone(CLONE_VM)`
  is out of scope. Deferred.
- **Zero-page optimisation**: should `AnonObject::fault` return a single
  shared zero-frame for read-only faults and only allocate on write?
  Linux does. Deferred — not a correctness issue, only an RSS/perf one.
- **Stack guard gap default**: 256 pages is Linux's. Open whether 64
  pages is sufficient for vibix until we have data on real userspace
  stack-probe distances.
- **mlock / mlockall**: deferred. Returning `0` as a no-op is POSIX-
  conformant for unprivileged callers and we have no swap to defeat.

## Implementation Roadmap

Ordered dependency-first. Each item is independently landable behind the
existing `VmaList` (kept in tree until item 4 lands), so no big-bang.

- [ ] mem: introduce `PageRefcount` global array and integrate with the frame allocator
- [ ] mem: add `AddressSpace` struct (PML4 + VmaTree + brk window) with kernel-half copy
- [ ] mem: add `VmObject` trait and `AnonObject` implementation (zero-fill demand paging)
- [ ] mem: introduce `VmaTree` (BTreeMap-backed) with `insert/unmap_range/change_protection` (split + merge)
- [ ] mem: add `Flusher` TLB-invalidation abstraction, thread through mapper APIs
- [ ] mem: rewrite `#PF` resolver to dispatch on `AddressSpace`/`Vma`/`VmObject` with CoW fast-path
- [ ] task: replace per-task `VmaList` with `Arc<RwLock<AddressSpace>>`; migrate existing AnonZero/Cow paths
- [ ] mem: implement `fork_address_space` (PTE W-strip + refcount bump for both halves)
- [ ] task: implement `AddressSpace::drop` reclaim (frees all VMAs, page-table frames, PML4)
- [ ] syscall: wire `mmap` / `munmap` / `mprotect` / `madvise` (anon-private only)
- [ ] syscall: wire `brk` over a pre-reserved heap region in `AddressSpace`
- [ ] mem: stack `MAP_GROWSDOWN` resolver path with guard-page VMA
- [ ] tests: integration tests for split/merge, COW divergence under fork, partial unmap, mprotect downgrade-and-flush, brk grow/shrink, MAP_FIXED_NOREPLACE EEXIST, stack growth into guard
