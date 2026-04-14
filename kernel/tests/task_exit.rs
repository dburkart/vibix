//! Integration test: `task::exit()` removes the running task from the
//! scheduler and its stack pages, VMA-backed frames, and PML4 frame
//! are returned to the global allocator. Validated by running many
//! spawn→exit cycles in a single boot without exhausting free frames.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use vibix::mem::frame;
use vibix::mem::vmatree::{Share, Vma};
use vibix::mem::vmobject::AnonObject;
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
    let tests: &[(&str, &dyn Testable)] = &[
        ("exit_removes_task", &(exit_removes_task as fn())),
        ("exit_loop_no_leak", &(exit_loop_no_leak as fn())),
        (
            "exit_loop_no_intermediate_leak",
            &(exit_loop_no_intermediate_leak as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

static EXIT_REACHED: AtomicUsize = AtomicUsize::new(0);

fn exit_worker() -> ! {
    EXIT_REACHED.fetch_add(1, Ordering::SeqCst);
    task::exit();
}

fn exit_removes_task() {
    // Baseline: only the bootstrap task is live.
    let mut baseline = 0usize;
    task::for_each_task(|_| baseline += 1);
    assert_eq!(baseline, 1, "unexpected tasks before spawn");

    EXIT_REACHED.store(0, Ordering::SeqCst);
    task::spawn(exit_worker);

    // Wait for the worker to run and then be reaped. One tick (10 ms)
    // is enough to reap; give it generous slack.
    for _ in 0..50 {
        if EXIT_REACHED.load(Ordering::SeqCst) == 1 {
            // Extra ticks so pending_exit drains through preempt_tick.
            for _ in 0..10 {
                x86_64::instructions::hlt();
            }
            break;
        }
        x86_64::instructions::hlt();
    }

    assert_eq!(
        EXIT_REACHED.load(Ordering::SeqCst),
        1,
        "worker never reached exit()"
    );

    let mut after = 0usize;
    task::for_each_task(|_| after += 1);
    assert_eq!(
        after, baseline,
        "task count didn't return to baseline after exit (leak in scheduler)"
    );
}

fn exit_loop_no_leak() {
    // Spawn-and-exit many times. If the PML4 / stack frames were not
    // being returned to the global allocator, `new_task_pml4` or the
    // stack-page map calls would eventually fail — the kernel has a
    // small pool of usable frames and 64 unreaped PML4s + stacks would
    // comfortably exhaust it.
    //
    // The strong signal here is "kernel still boots tests through this
    // loop without panicking in the allocator path." A leak panics;
    // a clean reap survives.
    const ITERATIONS: usize = 64;

    for i in 0..ITERATIONS {
        EXIT_REACHED.store(0, Ordering::SeqCst);
        task::spawn(exit_worker);
        for _ in 0..50 {
            if EXIT_REACHED.load(Ordering::SeqCst) == 1 {
                for _ in 0..4 {
                    x86_64::instructions::hlt();
                }
                break;
            }
            x86_64::instructions::hlt();
        }
        assert_eq!(
            EXIT_REACHED.load(Ordering::SeqCst),
            1,
            "worker {i} didn't reach exit()"
        );
    }

    let mut live = 0usize;
    task::for_each_task(|_| live += 1);
    assert_eq!(live, 1, "tasks leaking across exit loop");
}

// Lower-half VA in an L4 entry the bootstrap PML4 leaves untouched, so
// every L3/L2/L1 intermediate the worker faults in is wholly owned by
// its own PML4 and observable on reap.
const VMA_BASE: usize = 0x0000_3000_0000_0000;
const VMA_PAGES: usize = 8;

static FAULT_WORKER_DONE: AtomicUsize = AtomicUsize::new(0);

fn fault_worker() -> ! {
    let prot_pte =
        (PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE).bits();
    task::install_vma_on_current(Vma::new(
        VMA_BASE,
        VMA_BASE + VMA_PAGES * 4096,
        0x3, // PROT_READ | PROT_WRITE
        prot_pte,
        Share::Private,
        AnonObject::new(Some(VMA_PAGES)),
        0,
    ));

    for i in 0..VMA_PAGES {
        let va = VMA_BASE + i * 4096;
        unsafe { ptr::write_volatile(va as *mut u8, 0xCD) };
    }

    FAULT_WORKER_DONE.fetch_add(1, Ordering::SeqCst);
    task::exit();
}

fn wait_for_fault_worker() {
    for _ in 0..200 {
        if FAULT_WORKER_DONE.load(Ordering::SeqCst) == 1 {
            // Reap (and the Drop for AddressSpace that releases its
            // intermediate page-table frames) lands on the next
            // preempt_tick that drains pending_exit.
            for _ in 0..10 {
                x86_64::instructions::hlt();
            }
            return;
        }
        x86_64::instructions::hlt();
    }
    panic!("fault_worker never reached exit()");
}

// Regression for #146: every L3/L2/L1 intermediate page-table frame
// allocated by faulting an AnonZero VMA must be returned to the global
// allocator on `task::exit`. addrspace_drop.rs covers the same chain
// via the Arc<RwLock<AddressSpace>> drop, but the wiring through
// `task::exit` → `reap_pending` → drop is what userspace actually
// triggers, so it gets its own assertion alongside the scheduler-side
// leak check above.
fn exit_loop_no_intermediate_leak() {
    for _ in 0..2 {
        FAULT_WORKER_DONE.store(0, Ordering::SeqCst);
        task::spawn(fault_worker);
        wait_for_fault_worker();
    }

    let baseline = frame::free_frames();

    const ITERATIONS: usize = 32;
    for i in 0..ITERATIONS {
        FAULT_WORKER_DONE.store(0, Ordering::SeqCst);
        task::spawn(fault_worker);
        wait_for_fault_worker();
        assert_eq!(
            FAULT_WORKER_DONE.load(Ordering::SeqCst),
            1,
            "fault_worker {i} never reached exit()"
        );
    }

    let after = frame::free_frames();
    assert!(
        after >= baseline,
        "intermediate page-table leak across {ITERATIONS} task::exit cycles: \
         baseline={baseline}, after={after}, delta={}",
        baseline as isize - after as isize,
    );
}
