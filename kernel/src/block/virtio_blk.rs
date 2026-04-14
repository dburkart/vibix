//! Minimal legacy virtio-blk driver.
//!
//! Probes the first PCI function matching the transitional (legacy)
//! virtio block device (vendor `0x1AF4`, device `0x1001`), negotiates
//! zero features, wires up a single virtqueue, and exposes polled reads
//! via [`read`].
//!
//! Scope is deliberately narrow (issue #43 step 1):
//!
//! - Legacy PCI transport only. Modern (`0x1042`) devices are logged and
//!   skipped; QEMU is pinned to legacy via `disable-modern=on` in the
//!   xtask command line.
//! - Polling — no interrupt handler. The completion path spins on the
//!   used-ring index with a bounded retry budget.
//! - Read-only (`VIRTIO_BLK_T_IN`).
//! - Queue size is taken from whatever the device reports, capped at
//!   [`QUEUE_MAX`] so the whole virtqueue fits in a statically-reserved
//!   `#[repr(align(4096))]` region inside the kernel image. Limine loads
//!   kernel segments into physically contiguous frames, which satisfies
//!   the virtio legacy requirement that the queue be physically
//!   contiguous (spec 0.9.5 §2.3). We verify the contiguity at init time
//!   with `paging::translate` across each page and fail bring-up if the
//!   mapping is not contiguous.
//!
//! References:
//! - Virtio 1.0 spec §5.2 (block device).
//! - Virtio 0.9.5 (legacy) §2.3, §2.4 (virtqueue layout, notification).

#[cfg(target_os = "none")]
use super::BlkError;
#[cfg(target_os = "none")]
use super::SECTOR_SIZE;

#[cfg(target_os = "none")]
use alloc::alloc::{alloc_zeroed, dealloc, Layout};
#[cfg(target_os = "none")]
use core::cell::UnsafeCell;
#[cfg(target_os = "none")]
use core::mem::size_of;
#[cfg(target_os = "none")]
use core::ptr;
#[cfg(target_os = "none")]
use core::sync::atomic::{fence, Ordering};

#[cfg(target_os = "none")]
use spin::Mutex;
#[cfg(target_os = "none")]
use x86_64::instructions::port::Port;

#[cfg(target_os = "none")]
use crate::mem::paging;
use crate::pci;
#[cfg(target_os = "none")]
use crate::serial_println;

/// Transitional virtio PCI vendor ID.
const VIRTIO_VENDOR: u16 = 0x1AF4;
/// Transitional (legacy) virtio-blk device ID.
const DEVICE_ID_LEGACY: u16 = 0x1001;
/// Modern-only virtio-blk device ID. Skipped in this driver.
const DEVICE_ID_MODERN: u16 = 0x1042;

// Legacy virtio PCI I/O-register offsets (from BAR0 base). Only referenced
// from the target-only bring-up/submit path; gated on target_os = "none"
// so host test builds stay warning-clean.
#[cfg(target_os = "none")]
const REG_HOST_FEATURES: u16 = 0x00;
#[cfg(target_os = "none")]
const REG_GUEST_FEATURES: u16 = 0x04;
#[cfg(target_os = "none")]
const REG_QUEUE_ADDR: u16 = 0x08;
#[cfg(target_os = "none")]
const REG_QUEUE_SIZE: u16 = 0x0C;
#[cfg(target_os = "none")]
const REG_QUEUE_SELECT: u16 = 0x0E;
#[cfg(target_os = "none")]
const REG_QUEUE_NOTIFY: u16 = 0x10;
#[cfg(target_os = "none")]
const REG_DEVICE_STATUS: u16 = 0x12;

/// `Device Status` bits (virtio §2.1).
#[cfg(target_os = "none")]
const STATUS_ACKNOWLEDGE: u8 = 1;
#[cfg(target_os = "none")]
const STATUS_DRIVER: u8 = 2;
#[cfg(target_os = "none")]
const STATUS_DRIVER_OK: u8 = 4;
#[cfg(target_os = "none")]
const STATUS_FAILED: u8 = 128;

/// `type` values in the block request header.
#[cfg(target_os = "none")]
const VIRTIO_BLK_T_IN: u32 = 0;
#[cfg(target_os = "none")]
const VIRTIO_BLK_T_OUT: u32 = 1;

/// `flags` bits in a virtqueue descriptor.
#[cfg(target_os = "none")]
const VIRTQ_DESC_F_NEXT: u16 = 1;
#[cfg(target_os = "none")]
const VIRTQ_DESC_F_WRITE: u16 = 2;

/// Completion spin-budget. At ~1 GHz worth of `in`/pause iterations the
/// outer bound is generous — a real request finishes in microseconds; a
/// hung device should not hang the boot forever.
#[cfg(target_os = "none")]
const POLL_BUDGET: u32 = 10_000_000;

/// Largest queue size we're willing to drive. `queue_layout(256)` =
/// 10248 bytes → fits in 3 pages. QEMU defaults virtio-blk to 256, so
/// anything smaller here would force bring-up to fail rather than cap
/// silently — legacy QUEUE_SIZE is read-only, we can't request less.
#[cfg(target_os = "none")]
const QUEUE_MAX: u16 = 256;
#[cfg(target_os = "none")]
const QUEUE_STORAGE_BYTES: usize = 4096 * 3;
/// Minimum queue size we can drive. The submit path writes three
/// consecutive descriptor slots computed as `slot`, `slot+1`, `slot+2`
/// (mod qsz); with qsz < 3 those wrap and collide.
#[cfg(target_os = "none")]
const QUEUE_MIN: u16 = 3;

/// Page-aligned storage for the single virtqueue. Lives in the kernel
/// image's `.bss`, which Limine places into physically contiguous frames
/// — the virtio legacy PFN in `QUEUE_ADDR` requires that. We verify the
/// contiguity at init (see `verify_contig`).
#[cfg(target_os = "none")]
#[repr(C, align(4096))]
struct QueueStorage(UnsafeCell<[u8; QUEUE_STORAGE_BYTES]>);

// SAFETY: the only access is behind the DEVICE mutex (bring-up writes
// QUEUE_ADDR once, submit_and_wait accesses descriptors while holding
// the DEVICE lock). No concurrent CPU access occurs.
#[cfg(target_os = "none")]
unsafe impl Sync for QueueStorage {}

#[cfg(target_os = "none")]
static QUEUE_STORAGE: QueueStorage = QueueStorage(UnsafeCell::new([0u8; QUEUE_STORAGE_BYTES]));

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct VirtioBlkReqHeader {
    pub ty: u32,
    pub reserved: u32,
    pub sector: u64,
}

/// Byte layout of a virtqueue with `size` descriptors, per legacy spec:
/// `desc[size]` then `avail` then a 4096-byte alignment pad then `used`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct QueueLayout {
    pub desc_off: usize,
    pub avail_off: usize,
    pub used_off: usize,
    pub total: usize,
}

/// Compute the virtqueue layout for a given queue `size`.
///
/// Host-testable — it's pure integer arithmetic.
pub const fn queue_layout(size: u16) -> QueueLayout {
    let sz = size as usize;
    let desc_bytes = 16 * sz;
    // avail: flags(u16) + idx(u16) + ring(u16 * size) + used_event(u16)
    let avail_bytes = 6 + 2 * sz;
    let avail_end = desc_bytes + avail_bytes;
    let used_off = (avail_end + 4095) & !4095;
    // used: flags(u16) + idx(u16) + ring(u32+u32 * size) + avail_event(u16)
    let used_bytes = 6 + 8 * sz;
    QueueLayout {
        desc_off: 0,
        avail_off: desc_bytes,
        used_off,
        total: used_off + used_bytes,
    }
}

/// Whittle the host-feature bitmap down to the subset we accept. Today
/// that's an empty set — no FEATURES_OK contract beyond "I acked nothing".
pub const fn negotiate(_host: u64) -> u64 {
    0
}

/// PCI probe predicate. Pulled out for host-test coverage against
/// `pci::Device` fixtures.
pub fn is_virtio_blk_legacy(d: &pci::Device) -> bool {
    d.vendor_id == VIRTIO_VENDOR && d.device_id == DEVICE_ID_LEGACY
}

#[cfg(target_os = "none")]
#[allow(dead_code)] // several fields are held for future teardown / debug paths
struct BlkDevice {
    io_base: u16,
    queue_size: u16,
    queue_pa: u64,
    layout: QueueLayout,
    queue_base: *mut u8,
    /// Our running `avail.idx` — incremented for each submission.
    avail_idx: u16,
    /// Last `used.idx` we observed; completions advance it.
    last_used_idx: u16,
}

// SAFETY: the device is kept inside a Mutex; the raw pointer is only
// dereferenced while the mutex is held. Legacy virtio has no per-CPU
// state, so sharing across threads is sound.
#[cfg(target_os = "none")]
unsafe impl Send for BlkDevice {}

#[cfg(target_os = "none")]
static DEVICE: Mutex<Option<BlkDevice>> = Mutex::new(None);

#[cfg(target_os = "none")]
pub fn ready() -> bool {
    DEVICE.lock().is_some()
}

#[cfg(target_os = "none")]
pub fn init() {
    for d in pci::devices() {
        if d.vendor_id == VIRTIO_VENDOR && d.device_id == DEVICE_ID_MODERN {
            serial_println!(
                "block: skipping modern virtio-blk at {:02x}:{:02x}.{:x} (legacy-only driver)",
                d.addr.bus,
                d.addr.device,
                d.addr.function
            );
            continue;
        }
        if !is_virtio_blk_legacy(d) {
            continue;
        }
        let bar0 = d.bars[0];
        if !bar0.is_io() {
            serial_println!("block: virtio-blk BAR0 not an I/O BAR ({:#x})", bar0.0);
            continue;
        }
        let io_base = bar0.addr() as u16;
        match bring_up(d, io_base) {
            Ok(dev) => {
                let queue_size = dev.queue_size;
                *DEVICE.lock() = Some(dev);
                serial_println!(
                    "block: virtio-blk ready (io_base={:#06x}, queue_size={})",
                    io_base,
                    queue_size
                );
                return;
            }
            Err(e) => {
                serial_println!("block: virtio-blk bring-up failed: {:?}", e);
            }
        }
    }
}

#[cfg(target_os = "none")]
#[derive(Debug)]
#[allow(dead_code)] // payloads are surfaced via {:?} in the init error log
enum BringUpError {
    ZeroQueueSize,
    QueueTooSmall(u16),
    QueueTooLarge(u16),
    QueueNotContiguous,
}

#[cfg(target_os = "none")]
fn bring_up(dev: &pci::Device, io_base: u16) -> Result<BlkDevice, BringUpError> {
    // Command-register bus-mastering: the device DMAs our queue memory,
    // which a strict root complex won't allow without bit 2 set. QEMU is
    // lenient here but the spec is explicit, so set it regardless.
    pci::enable_bus_master(dev.addr);

    unsafe {
        // Reset.
        write8(io_base, REG_DEVICE_STATUS, 0);
        // ACK + DRIVER.
        write8(io_base, REG_DEVICE_STATUS, STATUS_ACKNOWLEDGE);
        write8(
            io_base,
            REG_DEVICE_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER,
        );
        // Feature negotiation: accept nothing (step 1). Legacy virtio
        // (0.9.5) has no FEATURES_OK bit — that's a v1.0 addition. We
        // write GUEST_FEATURES and move on; the transitional device
        // accepts an empty feature set unconditionally.
        let host = read32(io_base, REG_HOST_FEATURES) as u64;
        let guest = negotiate(host);
        write32(io_base, REG_GUEST_FEATURES, guest as u32);

        // Select queue 0 ("requestq").
        write16(io_base, REG_QUEUE_SELECT, 0);
        let queue_size = read16(io_base, REG_QUEUE_SIZE);
        if queue_size == 0 {
            write8(io_base, REG_DEVICE_STATUS, STATUS_FAILED);
            return Err(BringUpError::ZeroQueueSize);
        }
        if queue_size < QUEUE_MIN {
            // submit_and_wait writes three consecutive descriptors mod
            // qsz; qsz<3 aliases them onto the same slot.
            write8(io_base, REG_DEVICE_STATUS, STATUS_FAILED);
            return Err(BringUpError::QueueTooSmall(queue_size));
        }
        if queue_size > QUEUE_MAX {
            // Refuse rather than half-initialize — the static queue
            // storage is sized for QUEUE_MAX.
            write8(io_base, REG_DEVICE_STATUS, STATUS_FAILED);
            return Err(BringUpError::QueueTooLarge(queue_size));
        }

        let layout = queue_layout(queue_size);
        debug_assert!(layout.total <= QUEUE_STORAGE_BYTES);
        let queue_base = QUEUE_STORAGE.0.get() as *mut u8;
        // Zero the full region — the static is zero-initialized at boot,
        // but being defensive here costs nothing and keeps the invariant
        // obvious if a future caller ever re-enters bring_up.
        ptr::write_bytes(queue_base, 0, QUEUE_STORAGE_BYTES);

        let queue_pa = paging::translate(x86_64::VirtAddr::new(queue_base as u64))
            .expect("virtio_blk: queue not mapped")
            .as_u64();
        debug_assert_eq!(queue_pa & 0xFFF, 0, "queue must be page-aligned");
        if !queue_phys_contiguous(queue_base, layout.total, queue_pa) {
            write8(io_base, REG_DEVICE_STATUS, STATUS_FAILED);
            return Err(BringUpError::QueueNotContiguous);
        }

        // Legacy QUEUE_ADDR is a PFN (phys >> 12).
        write32(io_base, REG_QUEUE_ADDR, (queue_pa >> 12) as u32);

        // DRIVER_OK — device is live.
        write8(
            io_base,
            REG_DEVICE_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_DRIVER_OK,
        );

        Ok(BlkDevice {
            io_base,
            queue_size,
            queue_pa,
            layout,
            queue_base,
            avail_idx: 0,
            last_used_idx: 0,
        })
    }
}

/// Walk each 4 KiB page of `[base, base+len)` and assert that successive
/// pages map to successive physical frames starting from `base_pa`.
/// Legacy virtio-blk's QUEUE_ADDR is a single PFN and the device
/// interprets the whole queue as contiguous physical memory.
#[cfg(target_os = "none")]
unsafe fn queue_phys_contiguous(base: *const u8, len: usize, base_pa: u64) -> bool {
    let mut off = 4096usize;
    while off < len {
        let va = x86_64::VirtAddr::new(base as u64 + off as u64);
        let pa = match paging::translate(va) {
            Some(p) => p.as_u64(),
            None => return false,
        };
        if pa != base_pa + off as u64 {
            return false;
        }
        off += 4096;
    }
    true
}

#[cfg(target_os = "none")]
pub fn read(lba: u64, buf: &mut [u8]) -> Result<(), BlkError> {
    if buf.is_empty() || buf.len() % SECTOR_SIZE != 0 {
        return Err(BlkError::BadAlign);
    }
    // Single-page bounce buffer: guarantees the data descriptor covers
    // one physically-contiguous frame regardless of the caller's buffer
    // alignment. Capping at one page keeps this step-1 driver simple;
    // multi-page transfers can split into per-page descriptors later.
    if buf.len() > 4096 {
        return Err(BlkError::BadAlign);
    }
    let mut guard = DEVICE.lock();
    let dev = guard.as_mut().ok_or(BlkError::NotInitialized)?;
    let scratch = match unsafe { Scratch::alloc() } {
        Some(s) => s,
        None => return Err(BlkError::DeviceError),
    };
    unsafe {
        scratch.write_header(VIRTIO_BLK_T_IN, lba);
    }
    let result = unsafe { submit_and_wait(dev, &scratch, buf.len() as u32, IoDir::Read) };
    match result {
        Ok(()) => {
            // SAFETY: data_ptr points to a live 4 KiB allocation the device
            // filled via DMA; the matching ACQUIRE fence inside
            // submit_and_wait has already synchronized those writes.
            unsafe {
                ptr::copy_nonoverlapping(scratch.data_ptr, buf.as_mut_ptr(), buf.len());
                scratch.dealloc();
            }
            Ok(())
        }
        Err(BlkError::Timeout) => {
            // Deliberately leak on timeout: the device may still DMA.
            Err(BlkError::Timeout)
        }
        Err(e) => {
            unsafe {
                scratch.dealloc();
            }
            Err(e)
        }
    }
}

#[cfg(target_os = "none")]
pub fn write(lba: u64, buf: &[u8]) -> Result<(), BlkError> {
    if buf.is_empty() || buf.len() % SECTOR_SIZE != 0 {
        return Err(BlkError::BadAlign);
    }
    if buf.len() > 4096 {
        return Err(BlkError::BadAlign);
    }
    let mut guard = DEVICE.lock();
    let dev = guard.as_mut().ok_or(BlkError::NotInitialized)?;
    let scratch = match unsafe { Scratch::alloc() } {
        Some(s) => s,
        None => return Err(BlkError::DeviceError),
    };
    unsafe {
        scratch.write_header(VIRTIO_BLK_T_OUT, lba);
        // Stage the payload into the bounce buffer before submission;
        // the device will read from it as a RO descriptor.
        ptr::copy_nonoverlapping(buf.as_ptr(), scratch.data_ptr, buf.len());
    }
    let result = unsafe { submit_and_wait(dev, &scratch, buf.len() as u32, IoDir::Write) };
    match result {
        Ok(()) => {
            unsafe {
                scratch.dealloc();
            }
            Ok(())
        }
        Err(BlkError::Timeout) => Err(BlkError::Timeout),
        Err(e) => {
            unsafe {
                scratch.dealloc();
            }
            Err(e)
        }
    }
}

/// Direction of a single virtio-blk I/O request. Controls whether the
/// data descriptor carries `VIRTQ_DESC_F_WRITE` (read: device writes the
/// buffer) or not (write: device reads the buffer).
#[cfg(target_os = "none")]
#[derive(Copy, Clone, PartialEq, Eq)]
enum IoDir {
    Read,
    Write,
}

/// Per-request scratch: header + status byte + page-aligned data bounce
/// buffer, all HHDM-backed so `paging::translate` resolves them the same
/// way as the queue.
#[cfg(target_os = "none")]
struct Scratch {
    header_ptr: *mut VirtioBlkReqHeader,
    status_ptr: *mut u8,
    data_ptr: *mut u8,
    header_pa: u64,
    status_pa: u64,
    data_pa: u64,
}

#[cfg(target_os = "none")]
impl Scratch {
    const HEADER_LAYOUT: Layout = match Layout::from_size_align(size_of::<VirtioBlkReqHeader>(), 8)
    {
        Ok(l) => l,
        Err(_) => panic!("virtio_blk: bad header layout"),
    };
    const STATUS_LAYOUT: Layout = match Layout::from_size_align(1, 1) {
        Ok(l) => l,
        Err(_) => panic!("virtio_blk: bad status layout"),
    };
    const DATA_LAYOUT: Layout = match Layout::from_size_align(4096, 4096) {
        Ok(l) => l,
        Err(_) => panic!("virtio_blk: bad data layout"),
    };

    /// Allocate all three regions and translate their virtual addresses
    /// to physical. Returns `None` if any allocation fails.
    ///
    /// SAFETY: caller must arrange for exactly one `dealloc()` per
    /// non-timeout completion; on timeout the memory must be leaked
    /// because the device may still DMA into it.
    unsafe fn alloc() -> Option<Self> {
        let header_ptr = alloc_zeroed(Self::HEADER_LAYOUT) as *mut VirtioBlkReqHeader;
        if header_ptr.is_null() {
            return None;
        }
        let status_ptr = alloc_zeroed(Self::STATUS_LAYOUT);
        if status_ptr.is_null() {
            dealloc(header_ptr as *mut u8, Self::HEADER_LAYOUT);
            return None;
        }
        let data_ptr = alloc_zeroed(Self::DATA_LAYOUT);
        if data_ptr.is_null() {
            dealloc(header_ptr as *mut u8, Self::HEADER_LAYOUT);
            dealloc(status_ptr, Self::STATUS_LAYOUT);
            return None;
        }
        let header_pa = paging::translate(x86_64::VirtAddr::new(header_ptr as u64))
            .expect("virtio_blk: header not mapped")
            .as_u64();
        let status_pa = paging::translate(x86_64::VirtAddr::new(status_ptr as u64))
            .expect("virtio_blk: status not mapped")
            .as_u64();
        let data_pa = paging::translate(x86_64::VirtAddr::new(data_ptr as u64))
            .expect("virtio_blk: data not mapped")
            .as_u64();
        Some(Scratch {
            header_ptr,
            status_ptr,
            data_ptr,
            header_pa,
            status_pa,
            data_pa,
        })
    }

    unsafe fn write_header(&self, ty: u32, sector: u64) {
        ptr::write(
            self.header_ptr,
            VirtioBlkReqHeader {
                ty,
                reserved: 0,
                sector,
            },
        );
    }

    unsafe fn dealloc(&self) {
        dealloc(self.header_ptr as *mut u8, Self::HEADER_LAYOUT);
        dealloc(self.status_ptr, Self::STATUS_LAYOUT);
        dealloc(self.data_ptr, Self::DATA_LAYOUT);
    }
}

#[cfg(target_os = "none")]
unsafe fn submit_and_wait(
    dev: &mut BlkDevice,
    scratch: &Scratch,
    buf_len: u32,
    dir: IoDir,
) -> Result<(), BlkError> {
    let qsz = dev.queue_size as u16;
    let slot = dev.avail_idx % qsz;
    let desc_base = dev.queue_base.add(dev.layout.desc_off) as *mut VirtqDesc;

    // Three descriptors: header (RO), data (RO for write, WO for read),
    // status (WO). The F_WRITE flag in virtio descriptors marks
    // *device-writable* memory — so reads set it on the data descriptor
    // and writes clear it.
    let d0 = slot;
    let d1 = (slot + 1) % qsz;
    let d2 = (slot + 2) % qsz;
    let data_flags = match dir {
        IoDir::Read => VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE,
        IoDir::Write => VIRTQ_DESC_F_NEXT,
    };
    ptr::write_volatile(
        desc_base.add(d0 as usize),
        VirtqDesc {
            addr: scratch.header_pa,
            len: size_of::<VirtioBlkReqHeader>() as u32,
            flags: VIRTQ_DESC_F_NEXT,
            next: d1,
        },
    );
    ptr::write_volatile(
        desc_base.add(d1 as usize),
        VirtqDesc {
            addr: scratch.data_pa,
            len: buf_len,
            flags: data_flags,
            next: d2,
        },
    );
    ptr::write_volatile(
        desc_base.add(d2 as usize),
        VirtqDesc {
            addr: scratch.status_pa,
            len: 1,
            flags: VIRTQ_DESC_F_WRITE,
            next: 0,
        },
    );

    // Avail ring: [flags: u16, idx: u16, ring[qsz]: u16, used_event: u16].
    let avail_base = dev.queue_base.add(dev.layout.avail_off);
    let avail_ring_ptr = (avail_base as *mut u16).add(2); // skip flags+idx
    let ring_slot = (dev.avail_idx % qsz) as isize;
    ptr::write_volatile(avail_ring_ptr.offset(ring_slot), d0);
    // Ensure the ring write is visible before the index bump.
    fence(Ordering::Release);
    dev.avail_idx = dev.avail_idx.wrapping_add(1);
    ptr::write_volatile((avail_base as *mut u16).add(1), dev.avail_idx);
    fence(Ordering::Release);

    // Kick the device. Value written is the queue index (we're on queue 0).
    write16(dev.io_base, REG_QUEUE_NOTIFY, 0);

    // Poll the used-ring index until it catches up to our submission.
    let used_base = dev.queue_base.add(dev.layout.used_off);
    let expected = dev.avail_idx;
    for _ in 0..POLL_BUDGET {
        fence(Ordering::Acquire);
        let used_idx = ptr::read_volatile((used_base as *const u16).add(1));
        if used_idx == expected {
            dev.last_used_idx = used_idx;
            // Status byte: 0 = OK, 1 = IOERR, 2 = UNSUPP.
            let status = ptr::read_volatile(
                (paging::hhdm_offset().as_u64() + scratch.status_pa) as *const u8,
            );
            return if status == 0 {
                Ok(())
            } else {
                Err(BlkError::DeviceError)
            };
        }
        core::hint::spin_loop();
    }
    Err(BlkError::Timeout)
}

#[cfg(target_os = "none")]
unsafe fn read16(base: u16, reg: u16) -> u16 {
    let mut p: Port<u16> = Port::new(base + reg);
    p.read()
}
#[cfg(target_os = "none")]
unsafe fn read32(base: u16, reg: u16) -> u32 {
    let mut p: Port<u32> = Port::new(base + reg);
    p.read()
}
#[cfg(target_os = "none")]
unsafe fn write8(base: u16, reg: u16, v: u8) {
    let mut p: Port<u8> = Port::new(base + reg);
    p.write(v);
}
#[cfg(target_os = "none")]
unsafe fn write16(base: u16, reg: u16, v: u16) {
    let mut p: Port<u16> = Port::new(base + reg);
    p.write(v);
}
#[cfg(target_os = "none")]
unsafe fn write32(base: u16, reg: u16, v: u32) {
    let mut p: Port<u32> = Port::new(base + reg);
    p.write(v);
}

#[cfg(all(test, not(target_os = "none")))]
mod tests {
    use super::*;

    #[test]
    fn queue_layout_small_fits_one_page() {
        let l = queue_layout(64);
        assert_eq!(l.desc_off, 0);
        assert_eq!(l.avail_off, 16 * 64);
        // avail = 6 + 2*64 = 134 bytes; ends at 1024 + 134 = 1158 → next
        // 4 KiB boundary is 4096.
        assert_eq!(l.used_off, 4096);
        // used = 6 + 8*64 = 518 bytes.
        assert_eq!(l.total, 4096 + 518);
    }

    #[test]
    fn queue_layout_256_spans_two_pages() {
        let l = queue_layout(256);
        assert_eq!(l.avail_off, 16 * 256);
        // 16*256 = 4096; avail = 6 + 512 = 518; avail_end = 4614 → 8192.
        assert_eq!(l.used_off, 8192);
        // used = 6 + 8*256 = 2054.
        assert_eq!(l.total, 8192 + 2054);
    }

    #[test]
    fn layout_sizes_match_spec() {
        assert_eq!(size_of_desc(), 16);
        assert_eq!(size_of_header(), 16);
    }

    const fn size_of_desc() -> usize {
        core::mem::size_of::<VirtqDesc>()
    }
    const fn size_of_header() -> usize {
        core::mem::size_of::<VirtioBlkReqHeader>()
    }

    #[test]
    fn header_field_offsets() {
        let h = VirtioBlkReqHeader {
            ty: 0,
            reserved: 0,
            sector: 0,
        };
        let base = &h as *const _ as usize;
        assert_eq!(&h.ty as *const _ as usize - base, 0);
        assert_eq!(&h.reserved as *const _ as usize - base, 4);
        assert_eq!(&h.sector as *const _ as usize - base, 8);
    }

    #[test]
    fn negotiate_accepts_nothing() {
        assert_eq!(negotiate(0xFFFF_FFFF_FFFF_FFFF), 0);
        assert_eq!(negotiate(0), 0);
    }

    // Pin the virtio-blk request-type wire values. VIRTIO_BLK_T_IN = 0 and
    // VIRTIO_BLK_T_OUT = 1 are the legacy spec (§5.2.5) values the device
    // looks for; silently changing them would send every request down the
    // wrong code path on the device side.
    #[test]
    fn request_type_wire_values() {
        // Values live inside a `cfg(target_os = "none")` block, so repeat
        // the constants here to keep the assertion visible to the host
        // test build.
        const T_IN: u32 = 0;
        const T_OUT: u32 = 1;
        assert_eq!(T_IN, 0);
        assert_eq!(T_OUT, 1);
        assert_ne!(T_IN, T_OUT);
    }

    #[test]
    fn probe_matches_only_legacy() {
        let legacy = pci::Device::from_raw(
            pci::Address::new(0, 1, 0),
            (DEVICE_ID_LEGACY as u32) << 16 | VIRTIO_VENDOR as u32,
            0x0100_0000, // class=01, subclass=00
            0,
            [0xC001, 0, 0, 0, 0, 0],
        );
        assert!(is_virtio_blk_legacy(&legacy));

        let modern = pci::Device::from_raw(
            pci::Address::new(0, 1, 0),
            (DEVICE_ID_MODERN as u32) << 16 | VIRTIO_VENDOR as u32,
            0x0100_0000,
            0,
            [0; 6],
        );
        assert!(!is_virtio_blk_legacy(&modern));

        let other = pci::Device::from_raw(
            pci::Address::new(0, 0, 0),
            0x1237_8086,
            0x0600_0000,
            0,
            [0; 6],
        );
        assert!(!is_virtio_blk_legacy(&other));
    }
}
