# Memory Subsystem

**Sources:** `kernel/src/mem/`
- `mod.rs` — module root, `mem::init()`, shared types
- `frame.rs` — bitmap physical frame allocator
- `heap.rs` — growing kernel heap (`#[global_allocator]`)
- `paging.rs` — kernel page-table mapper, PML4 builder, CR3 switch
- `pat.rs` — Page Attribute Table (Write-Combining slot)

## Overview

The memory subsystem manages all physical and virtual memory used by the kernel.
It has three layers that build on each other:

```
Physical frames  ←  BitmapFrameAllocator   (frame.rs)
Virtual mappings ←  OffsetPageTable / PML4  (paging.rs)
Heap allocations ←  GrowingHeap            (heap.rs)
```

`mem::init()` calls all three in order:

```rust
pub fn init() {
    frame::init();   // scan Limine memmap, build bitmap
    paging::init();  // wrap Limine's PML4, build kernel-owned PML4, switch CR3
    heap::init();    // map initial 1 MiB slab, register #[global_allocator]
}
```

## Frame Allocator (`frame.rs`)

### Design

`BitmapFrameAllocator` tracks 4 KiB physical frames with one bit per frame.

- **Set bit** = frame used/reserved.
- **Clear bit** = frame available.

The bitmap lives in `.bss` as a static array (`BITMAP_WORDS = 16384 u64` words
= 128 KiB), covering up to 4 GiB of physical RAM. At init, all bits are set to
`1` (used), then every USABLE region from the Limine memory map is released
(bits cleared). Frames outside any USABLE region are permanently marked used and
never handed out.

Allocation scans forward from `next_hint`, finding the first word with a clear
bit. `next_hint` advances on each allocation and wraps only when no free frame
is found ahead, making allocation effectively O(1) on the common path.

Deallocation is O(1): compute the bit index from the physical address, clear it,
and update `next_hint` if the freed frame is before the current hint.

### Constants

| Constant | Value | Meaning |
|---|---|---|
| `FRAME_SIZE` | 4096 | Bytes per frame |
| `MAX_PHYS_BYTES` | 4 GiB | Highest tracked physical address |
| `BITMAP_WORDS` | 16384 | `u64` words in the bitmap (= MAX_PHYS_BYTES / 4096 / 64) |
| `MAX_REGIONS` | 64 | Max USABLE regions snapshotted from Limine |

### Host Testability

`BitmapFrameAllocator` depends only on `Region` and `FRAME_SIZE`, both free of
Limine or x86_64 types. It compiles against host `std` under `cargo test --lib`
and has a comprehensive unit-test suite in `frame.rs`.

## Heap Allocator (`heap.rs`)

### Design

`GrowingHeap` is a `GlobalAlloc` wrapper around `linked_list_allocator::LockedHeap`.
It reserves a 16 MiB virtual window starting at `HEAP_BASE = 0xFFFF_C000_0000_0000`
and backs it on demand:

- **Init:** `heap::init()` maps the first 1 MiB (`INITIAL_HEAP_SIZE`) with
  `paging::map_range` and hands it to the inner `LockedHeap`. The smoke marker
  `"heap: 1024 KiB"` confirms this.
- **Grow:** When `alloc()` sees a null result it takes `grow_lock`, re-checks
  (another concurrent path may have grown already), and if still OOM calls
  `grow_locked()`. This maps the next `GROW_CHUNK_BYTES` (64 KiB) chunk and
  calls `Heap::extend`. Growth is monotonic — the heap never shrinks.
- **Cap:** Once `mapped` reaches `HEAP_MAX_SIZE` (16 MiB) `grow_locked` returns
  false and `alloc` returns null. A null from the global allocator causes Rust's
  allocator-error handler to panic.

### Constants

| Constant | Value | Meaning |
|---|---|---|
| `HEAP_BASE` | `0xFFFF_C000_0000_0000` | Virtual base of the heap window |
| `INITIAL_HEAP_SIZE` | 1 MiB | Backed at init |
| `HEAP_MAX_SIZE` | 16 MiB | Hard cap |
| `GROW_CHUNK_FRAMES` | 16 | Frames mapped per grow step (= 64 KiB) |

## Paging (`paging.rs`)

### Design

The paging subsystem goes through two phases:

**Phase 1 — wrap Limine's tree:** `paging::init(hhdm_offset)` reads `CR3`,
wraps the active Limine PML4 in an `OffsetPageTable`, and stores it in
`MAPPER`. Early subsystems (heap init, IST guard page) call `map_range` /
`unmap_page` through this mapper.

**Phase 2 — build and switch the kernel PML4:** After the heap is live,
`build_and_switch_kernel_pml4()` (called from `mem::init`) constructs a fresh
PML4 that maps exactly:
- The kernel text, rodata, and data/bss sections with tight flags (RX, RO, RW
  respectively) derived from the ELF section headers in the embedded kernel file.
- HHDM as 2 MiB pages (`Size2MiB`) for efficiency.
- The heap window.
- The IST stack (without the guard page that sits below it).
- The framebuffer with Write-Combining PAT bits.

CR3 is then atomically switched to the new PML4 via `Cr3::write`. After the
switch, Limine's original page table is no longer reachable; reclaiming its
frames is tracked in issue #46.

### Key Functions

| Function | Description |
|---|---|
| `paging::init(hhdm)` | Wraps Limine's PML4 in `MAPPER` |
| `map_range(start, frames, flags)` | Maps `frames` pages at `start` VA, allocating PTs from the frame pool |
| `unmap_page(page)` | Unmaps a single page and returns its frame to the pool |
| `map_phys_into_hhdm(phys, size, flags)` | Maps a physical range into the HHDM window (used by ACPI + APIC) |
| `build_and_switch_kernel_pml4()` | Constructs the final kernel PML4 and switches CR3 |
| `with_mapper(f)` | Runs a closure with exclusive access to the active mapper |

### `KernelFrameAllocator`

A zero-sized adapter that implements `x86_64`'s `FrameAllocator<Size4KiB>` by
delegating to `frame::global()`. Constructed inline wherever the mapper APIs
need a frame allocator.

## Page Attribute Table (`pat.rs`)

The PAT subsystem reprograms MSR `0x277` to assign Write-Combining (`WC`) to
PAT entry 7 (PAT4 in the Intel naming). The framebuffer pages are then mapped
with `PAT | PWT` bits in their PTEs, hitting the WC entry. WC coalesces
write-combined stores before flushing to MMIO, reducing the number of bus
cycles for pixel blitting.

`pat::init()` is called inside `build_and_switch_kernel_pml4` before the
framebuffer mappings are installed.
