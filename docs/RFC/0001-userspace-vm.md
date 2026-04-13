---
rfc: 0001
title: Userspace Virtual Memory Subsystem
status: Accepted
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

### Foundational prior art

This RFC is a faithful re-implementation of the **Mach VM model** as
laid out in Rashid et al., *"Machine-Independent Virtual Memory
Management for Paged Uniprocessor and Multiprocessor Architectures"*
(ASPLOS-II, 1987), which introduced the `vm_object` / `vm_map_entry`
split that maps directly onto our `VmObject` / `Vma`. The per-frame
refcount discipline follows Bonwick's slab/vmem treatment
(*"The Slab Allocator"*, USENIX 1994; *"Magazines and Vmem"*,
USENIX 2001). The `MAP_FIXED_NOREPLACE` rationale follows Linux commit
`a4ff8e8620d3` (Michal Hocko, 2018). Nothing in this RFC claims novelty
beyond combining these well-studied pieces in idiomatic Rust; the
Academic reviewer's framing as "duplicate, not novel" is correct and
deliberate (Academic advisory A5, A6).

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
sync primitive). Because every published syscall and every fault that
resolves into the address space *mutates* PTEs (CoW) or VMA structure
(mmap/munmap/mprotect/fork), the page-fault path takes the **write** lock
unconditionally — the read lock exists only for future read-only
introspection (`/proc/self/maps`-equivalents). This is simpler and
closes the OS-Engineer/Security finding that the original pseudocode took
`read()` and then mutated. SMP per-VMA sequence locks (Linux ≥ 6.4) are
explicitly out of scope; the API leaves room (see `Vma::_lock_seq` below).

**IRQ-safety contract.** The `AddressSpace` lock is **never** taken from
interrupt context. Every call site (page-fault handler, syscall entry,
fork/exec/exit) runs with interrupts enabled in a task context. We
enforce this with a debug assertion (`debug_assert!(!in_irq())`) inside
the lock's read/write entry points. Async-completion and timer paths that
need to touch user memory must defer to a task-context worker; this
matches vibix's existing interrupt-safety contract documented in
`docs/interrupts.md`. This invariant is what lets the lock remain a
plain `RwLock` rather than a spin-lock-with-IRQ-disable.

**`Vma`** (replaces today's `kernel/src/mem/vma.rs`):

```rust
#[repr(C)]
pub struct Vma {
    pub start: VirtAddr,         // page-aligned (4 KiB)
    pub end:   VirtAddr,         // page-aligned (4 KiB), exclusive
    pub prot_user: Prot,         // PROT_* as the user requested (W/O preserved)
    pub prot_pte:  Prot,         // effective bits installed in PTEs (W/O => RW)
    pub share: ShareMode,        // Private | Shared
    pub object: Arc<dyn VmObject>,
    pub object_offset: usize,    // bytes into the VmObject this VMA starts at
    pub flags:  VmFlags,         // GROWSDOWN, LOCKED, STACK, …
    /// Reserved for future per-VMA SMP sequence lock; unused on UP.
    _lock_seq: u32,
}
```

`prot_user` records exactly what userspace asked for; `prot_pte` is the
hardware-installable subset (where `PROT_WRITE` without `PROT_READ` is
mapped to `R|W` because x86 cannot separate them — see User-Space
finding B2). `mincore` / `/proc/self/maps`-equivalents report
`prot_user`, so the round-trip is preserved.

**Alignment rule (single, repo-wide).** Every byte address that crosses
the syscall boundary is rounded as follows, applied uniformly to `mmap`,
`munmap`, `mprotect`, `madvise`:

- `addr` must be page-aligned exactly (no rounding). A non-aligned `addr`
  on `mmap` without `MAP_FIXED` is rounded **down** to a page; with
  `MAP_FIXED` it returns `EINVAL`.
- `len` is rounded **up** to a whole page (`(len + 4095) & !4095`),
  matching POSIX "entire pages containing any part of the range." `len`
  is rejected with `EINVAL` only when `len == 0` or when the rounded
  result overflows.

This single rule keeps `VmaTree` intervals and PTE presence in lockstep
across all four syscalls (Security finding B3).

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
on #PF (cr2, error_code, cpl):
  // 1. SMAP first, unconditionally — kernel mode touching a user page
  //    with AC=0 is a violation no matter what the VmaTree says.
  if cpl == 0 and error_code.user_bit() == 1 and !rflags_ac():
    panic_smap_violation(cr2)              // never returns

  // 2. Pure kernel fault (CPL=0, supervisor page) → existing handler.
  if cpl == 0 and error_code.user_bit() == 0:
    return existing_kernel_fault(...)

  // 3. Reserved-bit fault is always a kernel bug. Scrub PTE physaddr
  //    from any user-reachable channel; log the VA only.
  if error_code.rsvd():
    panic_rsvd_corruption(cr2)             // PTE word logged to klog only

  // 4. cr2 must be canonical and below USER_VA_END before we touch any
  //    user-controlled state.
  if !cr2.is_canonical() or cr2 >= USER_VA_END:
    return deliver_sigsegv(SI_MAPERR)

  // 5. Take the WRITE lock — every fault that survives may mutate PTEs.
  //    See "AddressSpace lock semantics" above.
  let mut aspace = current_task.address_space.write();
  let vma = match aspace.find(cr2) {
    Some(v) => v,
    None    => return resolve_growsdown_or_segv(&mut aspace, cr2),
  }

  let access = Access::from_error_code(error_code);

  // 6. Permission check uses prot_user, not prot_pte.
  if !vma.prot_user.allows(access):
    return deliver_sigsegv(SI_ACCERR)

  match (error_code.present(), access.is_write()) {
    (false, _)    => resolve_demand_page(&mut aspace, vma, cr2, access),
    (true, true)  => resolve_cow(&mut aspace, vma, cr2),
    (true, false) => return,  // widening race; IRET re-walks TLB. Safe
                              // because x86 auto-reloads on PTE present-
                              // bit set; we did the user mutation under
                              // the write lock and INVLPG'd already.
  }
```

`resolve_demand_page` calls `vma.object.fault(offset, access)`, then maps
the returned frame at `cr2 & !0xFFF` with `vma.prot`'s flags, bumping the
frame's refcount.

`resolve_cow` is the write-on-CoW path. Two invariants drive its shape:

- **Refcount sentinel.** The frame allocator treats refcount 0 as
  "free." We must never write 0 into a refcount slot whose frame is
  still installed in a PTE (OS-Engineer finding B1). The fast path
  therefore *peeks* at the refcount instead of decrementing — only the
  copy path decrements (because only the copy path drops our reference
  to the old frame).
- **PTE U/S=1.** Before mutating any PTE in CoW, verify that its U/S
  bit is set. A write fault routed here against a kernel-installed PTE
  (a kernel bug elsewhere) must panic, not silently turn a kernel page
  user-writable (Security finding B5).

```
// Held: aspace.write() — exclusive over this address space.
let pte = aspace.page_table.lookup_mut(cr2);
assert!(pte.user(), "CoW resolver entered with U/S=0 PTE; kernel bug");
let old_frame = pte.frame();

// Acquire-load the refcount to synchronize with any concurrent decrement
// elsewhere; we do NOT modify it on the fast path.
let rc = page_refcount(old_frame).load(Acquire);
if rc == 1:
  // We are the last sharer (refcount 1 — only this PTE references the
  // frame). Promote in place. No decrement: refcount stays 1, matching
  // the new sole-owner state. The Acquire load synchronizes-with all
  // prior writes from any previous owner.
  pte.set_writable(true);
  flusher.invalidate(cr2);
else:
  // Need a private copy.
  let new_frame = frame_alloc()?;       // refcount[new_frame] = 1 by alloc
  copy_4k_via_hhdm(old_frame, new_frame);
  pte.set_frame(new_frame);
  pte.set_writable(true);
  flusher.invalidate(cr2);
  // Now drop our reference to old_frame. Release on the dec orders the
  // PTE update before any observer that subsequently sees rc==1 and
  // tries to write the old frame. If this dec brings it to 0, the
  // allocator reclaims; an Acquire fence happens inside frame_free
  // before the frame is handed out again.
  let prev = page_refcount(old_frame).fetch_sub(1, Release);
  if prev == 1:
    atomic::fence(Acquire);
    frame_free(old_frame);
```

This matches Linux's `wp_page_reuse` (fast path) and `wp_page_copy` (slow
path) shape and adopts the canonical Arc-style memory ordering called
out by the OS-Engineer reviewer (B4) and the Academic reviewer (A1, A3).
The "ownership invariant" the Academic reviewer asks be made explicit:
*VMAs hold strong references to their `VmObject`s via `Arc`; the
per-frame `page_refcount` tracks how many PTEs across all address spaces
reference each frame and is independent of the `Arc` graph. Refcount is
either exact or over-approximated; it is never under-approximated.* The
fork path's `Release`-ordered increment and the CoW path's
`Release`-ordered decrement form a release-acquire chain via the atomic
fence above.

**`fork()` page-table copy** (called from process duplication). Takes a
`Flusher` so the parent's W-strip is shootdown-correct on every CPU in
`parent.used_by` (OS-Engineer finding B5):

```
fn fork_address_space(
    parent: &mut AddressSpace,    // write lock held
    flusher: &mut Flusher,        // covers parent.used_by
) -> Result<AddressSpace, Errno> {
  let mut child = AddressSpace::new_empty()?;   // fresh PML4, kernel half copied
  for vma in parent.vmas.iter():
    let child_vma = vma.clone_metadata();
    if vma.share == ShareMode::Private:
      for (va, pte) in parent.page_table.range_mut(vma.start, vma.end):
        if pte.is_present():
          // Bump refcount BEFORE stripping W in the parent. Order: a
          // future CoW resolver in the parent (which loads refcount with
          // Acquire) must observe rc>=2 once it sees the W-stripped PTE.
          // Relaxed is sufficient on the inc; the Release on subsequent
          // CoW dec is what publishes frame contents.
          if page_refcount(pte.frame()).fetch_add(1, Relaxed) == u16::MAX:
            // Saturation: roll back this VMA's increments and copy the
            // frame eagerly. If allocation fails, roll back the entire
            // fork. (See "Refcount saturation" in Security below.)
            return Err(rollback_fork(parent, child, vma, va))
          pte.set_writable(false);
          child.page_table.install(va, pte.with_writable(false));
          flusher.invalidate(va);   // parent CPUs lose stale W TLB entry
    else: // ShareMode::Shared
      for (va, pte) in parent.page_table.range(vma.start, vma.end):
        if pte.is_present():
          if page_refcount(pte.frame()).fetch_add(1, Relaxed) == u16::MAX:
            return Err(rollback_fork(parent, child, vma, va))
          child.page_table.install(va, pte.value());
    child.vmas.insert(child_vma);
  // CRITICAL: flusher.finish() runs before fork() returns to userspace.
  // Otherwise the parent could observe stale W=1 TLB entries and bypass
  // CoW, silently corrupting the child's view (Security advisory A7).
  flusher.finish();
  Ok(child)
}
```

The W-strip happens in the *parent* as well as the child. Both sides
take a write fault on first store and CoW-resolve independently. The
`flusher.finish()` call is mandatory before return — `fork_address_space`
asserts on drop that `flusher` was finished.

**`mmap` / `munmap` / `mprotect`** all flow through three primitives on
`VmaTree`: `insert(vma)` (with merge), `unmap_range(start, end)` (with
split at boundaries), `change_protection(start, end, new_prot)` (with
split + merge). Splits clone the `Arc<dyn VmObject>`; merges require the
adjacent VMAs to have matching prot/share/object/object_offset and be
contiguous.

**Lock ordering invariant for the future.** When threads land and a
single process can hold two `AddressSpace`s open simultaneously
(`fork()` is the canonical case), the parent's lock is acquired before
the child's. We adopt the Linux convention: when two `AddressSpace`s
must be locked together, lock by ascending pointer-address of the
`AddressSpace` heap allocation (Academic advisory A2). This is free
today (only one is locked at a time outside of fork, and fork constructs
the child *after* taking the parent lock) and prevents the deadlock
class once a future RFC adds `clone(CLONE_VM)`-style sharing.

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

**Address validation (every mmap-family syscall, before any state
mutation).** Required to close Security finding B2:

1. `len == 0` → `EINVAL`.
2. `len` rounded up to a page; if rounding overflows `usize`, `EINVAL`.
3. `addr` must be canonical (bits 48..63 all equal bit 47); else `EINVAL`.
4. `addr.checked_add(len_rounded)` must succeed; else `EINVAL`.
5. `addr + len_rounded <= USER_VA_END` (= `0x0000_8000_0000_0000` minus
   the per-aspace guard region); else `EINVAL`. This forbids any user-
   controlled range from touching the kernel half.
6. `addr` page-alignment: required for `MAP_FIXED`, `munmap`, `mprotect`,
   `madvise` (else `EINVAL`); for non-FIXED `mmap` `addr` is treated as
   a hint and rounded down.

Errnos (POSIX-conformant unless explicitly noted as a documented
deviation):

- `mmap`:
  - `EINVAL` — failed validation 1–6, both/neither of MAP_PRIVATE/
    MAP_SHARED, unknown bits in `flags`.
  - `ENOMEM` — no room for non-FIXED, or `RLIMIT_AS` exceeded, or
    `VmaTree::insert` returns `AllocError` from the kernel heap.
  - `EEXIST` — `MAP_FIXED_NOREPLACE` would overlap an existing VMA.
  - `ENODEV` — `fd != -1` (file-backed not yet supported). This matches
    Linux's "file type not supported by mmap" semantics and is the
    POSIX-listed errno (User-Space finding B3); we do not invent
    `ENOTSUP` here.
  - `EACCES` — reserved for the future file-backed path.

- `munmap`:
  - `EINVAL` — failed validation 1–6.
  - **No `ENOMEM` on holes.** `munmap` over a range that is partly or
    wholly unmapped returns `0` (POSIX requirement; User-Space finding
    B1). `glibc`/`musl` `free()` paths depend on this.

- `mprotect`:
  - `EINVAL` — failed validation 1–6, unknown PROT bits.
  - `ENOMEM` — only when the request specifies an `addr`+`len` that is
    not entirely contained in mapped VMAs of *this address space at the
    page granularity Linux uses* — i.e., a sub-page within the requested
    range has no VMA. Holes spanning whole VMAs return `ENOMEM`; partial
    coverage of a single VMA does not. This matches Linux's
    `mprotect_fixup` failure mode and is the standard POSIX
    interpretation.

- `brk`:
  - On failure (request past `brk_max` or allocation failure), returns
    the **current** (unchanged) break. `glibc`/`musl` `sbrk` detect
    failure by comparing return value against the prior break (User-
    Space advisory A3). No errno set.

- `madvise`:
  - Always returns `0` for valid advice values; `EINVAL` for unknown.
    `MADV_DONTNEED` on `MAP_PRIVATE | MAP_ANONYMOUS` zeros pages by
    dropping PTEs and decrementing refcounts (Security advisory A5,
    User-Space advisory A4) — required because jemalloc/mimalloc rely on
    it. Other advice is no-op.

**Syscall ABI return convention.** All syscalls return `i64` in `rax`.
Success is `>= 0` (for `mmap` the new VA, for `brk` the new break, for
others 0). Failure is `-errno` in the range `-1..=-4095` (Linux
convention; User-Space advisory A5).

**Syscall numbers** are pinned in this RFC (User-Space advisory A1):
`mmap=9`, `munmap=11`, `mprotect=10`, `brk=12`, `madvise=28` — chosen to
match Linux x86-64 numbering so a future `vibix-sys` crate can share
constants. Implementation issue (#125 successor) freezes the table
before PID 1 lands.

Supported flags (vibix-init):

```
MAP_PRIVATE         0x02
MAP_SHARED          0x01     // anonymous MAP_SHARED is fully supported
                             // (shared-memory between fork children).
                             // file-backed MAP_SHARED returns ENODEV until
                             // the file-backed VmObject lands.
MAP_FIXED           0x10
MAP_FIXED_NOREPLACE 0x100000
MAP_ANONYMOUS       0x20
MAP_GROWSDOWN       0x100    // marks VMA; growth happens in fault handler
MAP_STACK           0x20000  // no-op marker
```

PROT bits: `PROT_NONE=0`, `PROT_READ=1`, `PROT_WRITE=2`, `PROT_EXEC=4`.
`PROT_WRITE` without `PROT_READ` is **accepted as the user's request**
(stored in `vma.prot_user`) but the PTE is installed with `R|W` because
x86 cannot separate them. Userspace observability paths (future
`/proc/self/maps`, `mincore`) report `prot_user`; `mprotect` round-trip
preserves the original bits. This closes User-Space finding B2: we no
longer silently mutate the user's request.

`PROT_EXEC` clears the XD bit in the leaf PTE; clearing `PROT_EXEC` sets
XD. W^X is **not** enforced at the kernel boundary — userspace JITs
need `RWX` mappings transiently. We will revisit if a hardening RFC
later adds an opt-in W^X enforcement (User-Space advisory A7).

**MAP_FIXED loader invariant (kernel-initiated mappings).** Any caller
*inside the kernel* that maps an untrusted byte stream's segment to a
fixed VA (today: the ring-0 ELF loader, #148) MUST:

1. Use `MAP_FIXED_NOREPLACE`, never bare `MAP_FIXED`.
2. Reject any segment whose `[p_vaddr, p_vaddr + p_memsz)` is non-
   canonical, exceeds `USER_VA_END`, overflows, or overlaps the stack-
   guard region.

This addresses Security finding B4 — the loader cannot be tricked into
clobbering kernel-half PML4 entries or stack guards via crafted ELFs.
The check lives in the loader itself; the VM subsystem rejects out-of-
range addresses unconditionally regardless.

`/proc` and `/sys` layouts: N/A — neither subsystem exists yet.

### Stack growth

A user stack is created as a `MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN`
VMA. On a `#PF` whose `cr2` is below `vma.start` but within
`stack_guard_gap` (256 pages, matching Linux), the resolver extends
`vma.start` downward by **exactly one page** and installs the page. A
single fault never extends by more than one page (Security advisory A6) —
this defeats attacker-controlled multi-page jumps over the guard. After
each extension we also enforce `RLIMIT_STACK` (today: a fixed 8 MiB
default; future per-task limit). A guard VMA below the stack (PROT_NONE,
marked `STACK_GUARD`) catches over-runs and converts them to SIGSEGV.

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
- **Refcount saturation rollback (Security A4, OS A2).** The fork path
  uses `fetch_add(1, Relaxed)` and observes the previous value. If the
  previous value was already `u16::MAX`, we cannot safely share the
  frame again. The protocol is:
  1. Walk back the *current VMA's* increments, decrementing every frame
     we already added a ref to within this VMA.
  2. If the rollback succeeds, fall back to **eager copy** of the
     remaining VMA (allocate fresh frames, memcpy via HHDM, install in
     child without touching parent's refcount). The child's new frames
     start at refcount 1; the parent's refcounts are unchanged for that
     VMA's surviving entries.
  3. If allocation for the eager copy fails, walk back **all** VMAs
     already processed in this fork (decrementing refcounts and freeing
     child PML4 entries), then return `ENOMEM`. Fork is all-or-nothing;
     partial address spaces are never observable.

  Eager copy does *not* require a reverse map: we are inside fork, the
  child's address space is private and not yet visible to anyone, and
  we hold the parent's write lock. The "16-bit refcount + saturation
  fallback" formal invariant is *over-approximation only — refcount is
  exact or higher, never lower.* A future widen to `AtomicU32` is
  trivial.

- **CoW race**: two threads of the same process may write-fault the same
  shared frame simultaneously. Resolution holds `aspace.write()`,
  which serialises *PTE mutation and refcount inspection within this
  address space.* Cross-address-space CoW state is protected by the per-
  frame refcount's atomic increment/decrement plus the
  release-acquire fence pair documented in `resolve_cow`. The CoW
  resolver's PTE U/S=1 assertion catches any kernel-mapping leakage
  before it becomes user-writable (Security finding B5).
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
  than overlapping a user mapping. The `brk_max` guard is **non-zero**
  (default 1 MiB between top of brk and `mmap_base`) so a saturated
  brk does not strand subsequent mmap allocations (Security advisory A8).

- **`page_refcount` static sizing (Security A3, OS A1).** The array is
  sized from the same `MAX_PHYS_BYTES` constant the frame allocator
  uses (`kernel/src/mem/frame.rs`), not from "usable" RAM. MMIO and
  reserved regions never enter the refcount path: the allocator marks
  those frames as permanently used in its bitmap and never returns them
  via `frame_alloc`, so no PTE installed by the VM subsystem can point
  at one. We assert in `frame_free(f)` that `page_refcount[f]` was
  exactly 0 before reclaim, catching any underflow at the source.

- **Reserved-bit panic console hygiene (Security A2).** `panic_rsvd_
  corruption(cr2)` logs only the faulting VA. The PTE word and the
  physical address it embedded are written to `klog` (kernel-only ring
  buffer) and never to the boot serial console, which a future userspace
  may reach.
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

All blocking review findings were resolved in defense cycle 1
(commit `7e550ec`). The following items are intentionally **deferred to
implementation** — they do not block acceptance and will be revisited as
the roadmap progresses:

- **PCID adoption** — deferred to implementation. Track as follow-up RFC
  once context-switch profiling shows full-TLB-flush dominating.
- **File-backed mappings** — deferred to implementation. The `VmObject`
  trait shape is committed; the `FileObject` impl awaits the VFS RFC.
- **Threads / shared address spaces** — deferred. The
  `Arc<AddressSpaceLock>` model and the lock-by-ascending-pointer
  invariant are committed; the `clone(CLONE_VM)` syscall awaits the
  threading RFC.
- **Zero-page optimisation** — deferred to implementation. Not a
  correctness issue; an RSS/perf optimisation that can land anytime.
- **Stack guard gap default** — deferred. Starts at Linux's 256 pages;
  can be tuned as we collect data.
- **mlock / mlockall** — deferred. Returning `0` as a no-op is POSIX-
  conformant and we have no swap to defeat.
- **PageRefcount false-sharing under SMP** (OS advisory A7) — deferred.
  Becomes relevant only with SMP fork storms; address when the SMP RFC
  lands.
- **Reverse-map (rmap) for refcount-saturation rollback at scale** —
  deferred. The current eager-copy fallback is correct but O(VMA) on
  saturation; an rmap would let us walk just the affected frame's PTEs.
  Not on the P0 path.

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
