//! Integration test: each spawned task gets its own PML4 and
//! `context_switch` reloads CR3 on every rotation. Proves the
//! groundwork for per-task address spaces (#26) — different PML4s,
//! kernel upper half still reachable from each.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use vibix::{
    exit_qemu, serial_println, task,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};
use x86_64::registers::control::Cr3;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    task::init();
    // Preemption drives task rotation — without IF=1 the workers never
    // run and we deadlock on the atomics below.
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
        ("distinct_pml4_per_task", &(distinct_pml4_per_task as fn())),
        (
            "kernel_upper_half_shared",
            &(kernel_upper_half_shared as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

static A_CR3: AtomicU64 = AtomicU64::new(0);
static B_CR3: AtomicU64 = AtomicU64::new(0);
static DONE: AtomicUsize = AtomicUsize::new(0);

fn task_a() -> ! {
    A_CR3.store(Cr3::read().0.start_address().as_u64(), Ordering::SeqCst);
    DONE.fetch_add(1, Ordering::SeqCst);
    loop {
        x86_64::instructions::hlt();
    }
}

fn task_b() -> ! {
    B_CR3.store(Cr3::read().0.start_address().as_u64(), Ordering::SeqCst);
    DONE.fetch_add(1, Ordering::SeqCst);
    loop {
        x86_64::instructions::hlt();
    }
}

fn distinct_pml4_per_task() {
    let boot_cr3 = Cr3::read().0.start_address().as_u64();
    A_CR3.store(0, Ordering::SeqCst);
    B_CR3.store(0, Ordering::SeqCst);
    DONE.store(0, Ordering::SeqCst);

    task::spawn(task_a);
    task::spawn(task_b);

    // Bounded wait so a scheduling regression fails the test in ~1s
    // instead of hanging CI.
    for _ in 0..1_000 {
        if DONE.load(Ordering::SeqCst) >= 2 {
            break;
        }
        x86_64::instructions::hlt();
    }

    let a = A_CR3.load(Ordering::SeqCst);
    let b = B_CR3.load(Ordering::SeqCst);
    assert_ne!(a, 0, "task A never ran");
    assert_ne!(b, 0, "task B never ran");
    assert_ne!(
        a, boot_cr3,
        "task A shares bootstrap CR3 — new_task_pml4 regressed"
    );
    assert_ne!(
        b, boot_cr3,
        "task B shares bootstrap CR3 — new_task_pml4 regressed"
    );
    assert_ne!(a, b, "tasks A and B share CR3 — PML4 alloc regressed");
    serial_println!("  boot=0x{boot_cr3:x} a=0x{a:x} b=0x{b:x}");
}

fn kernel_upper_half_shared() {
    // If the kernel upper half weren't mirrored in task PML4s, task A
    // would have faulted the instant it touched A_CR3 (a .bss static
    // in the kernel image) — the fact that distinct_pml4_per_task
    // above reached DONE=2 already proves it. Re-assert explicitly so
    // a future test ordering change doesn't silently skip the check.
    use vibix::mem::paging;
    use x86_64::VirtAddr;
    let marker_va = VirtAddr::new(&raw const A_CR3 as u64);
    paging::translate(marker_va).expect("kernel .bss unreachable after task rotation");
    let fn_ptr: fn() = kernel_upper_half_shared;
    let fn_va = VirtAddr::new(fn_ptr as usize as u64);
    paging::translate(fn_va).expect("kernel .text unreachable after task rotation");
}
