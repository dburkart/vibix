//! Integration test for #161: dropping the last `Arc<RwLock<AddressSpace>>`
//! returns every leaf VMA frame, every intermediate page-table frame in
//! the user half, and the PML4 frame itself to the global allocator.
//!
//! The signal is `mem::frame::free_frames()` returning to (or above)
//! its pre-spawn baseline after a worker that allocates, faults, and
//! exits has been reaped. A leaky `Drop for AddressSpace` would leave
//! the VMA leaves, intermediate L3/L2/L1 tables, and/or PML4 stranded.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use vibix::mem::frame;
use vibix::mem::vma::{Vma, VmaKind};
use vibix::{
    exit_qemu, serial_println, task,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};
use x86_64::structures::paging::PageTableFlags;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    task::init();
    x86_64::instructions::interrupts::enable();
    run_tests();
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info)
}

fn run_tests() {
    let tests: &[(&str, &dyn Testable)] = &[(
        "drop_releases_vma_pages_pml4",
        &(drop_releases_vma_pages_pml4 as fn()),
    )];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

/// Lower-half VA chosen to land in an L4 entry the bootstrap kernel
/// PML4 doesn't touch — keeps the worker's intermediate tables wholly
/// owned by its private PML4 so that `Drop` reclaim can be observed
/// in isolation.
const WORKER_VMA_BASE: usize = 0x0000_3000_0000_0000;
const WORKER_VMA_PAGES: usize = 8;

static WORKER_DONE: AtomicUsize = AtomicUsize::new(0);

fn worker() -> ! {
    task::install_vma_on_current(Vma::new(
        WORKER_VMA_BASE,
        WORKER_VMA_BASE + WORKER_VMA_PAGES * 4096,
        VmaKind::AnonZero,
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE,
    ));

    // Touch every page so the resolver installs a leaf frame for each.
    for i in 0..WORKER_VMA_PAGES {
        let va = WORKER_VMA_BASE + i * 4096;
        unsafe { ptr::write_volatile(va as *mut u8, 0xCD) };
    }

    WORKER_DONE.fetch_add(1, Ordering::SeqCst);
    task::exit();
}

fn drop_releases_vma_pages_pml4() {
    // Run a couple of warm-up cycles so any one-shot allocations
    // (per-task FPU areas grown into a slab, etc.) settle before the
    // baseline measurement.
    for _ in 0..2 {
        WORKER_DONE.store(0, Ordering::SeqCst);
        task::spawn(worker);
        wait_for_worker();
    }

    let baseline = frame::free_frames();

    const ITERATIONS: usize = 16;
    for i in 0..ITERATIONS {
        WORKER_DONE.store(0, Ordering::SeqCst);
        task::spawn(worker);
        wait_for_worker();
        assert_eq!(
            WORKER_DONE.load(Ordering::SeqCst),
            1,
            "worker {i} never reached exit()"
        );
    }

    let after = frame::free_frames();

    // After all reaps complete, the free-frame count must not have
    // dropped below baseline: every VMA leaf, every L3/L2/L1
    // intermediate table, and every PML4 must have been returned.
    assert!(
        after >= baseline,
        "frame leak across {ITERATIONS} spawn/exit cycles: \
         baseline={baseline}, after={after}, delta={}",
        baseline as isize - after as isize,
    );
}

fn wait_for_worker() {
    for _ in 0..200 {
        if WORKER_DONE.load(Ordering::SeqCst) == 1 {
            // Extra ticks so pending_exit drains and Drop runs.
            for _ in 0..10 {
                x86_64::instructions::hlt();
            }
            return;
        }
        x86_64::instructions::hlt();
    }
    panic!("worker never reached exit()");
}
