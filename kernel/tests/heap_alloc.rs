//! Integration test: the kernel heap supports Box, Vec, and reclaims
//! space on drop.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::panic::PanicInfo;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    run_tests();
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info)
}

fn run_tests() {
    let tests: &[(&str, &dyn Testable)] = &[
        ("simple_box", &(simple_box as fn())),
        ("large_vec", &(large_vec as fn())),
        ("many_allocations_reclaim", &(many_allocations_reclaim as fn())),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

fn simple_box() {
    let a = Box::new(42u64);
    let b = Box::new(0xDEAD_BEEFu64);
    assert_eq!(*a, 42);
    assert_eq!(*b, 0xDEAD_BEEF);
}

fn large_vec() {
    const N: usize = 10_000;
    let mut v: Vec<usize> = Vec::with_capacity(N);
    for i in 0..N {
        v.push(i);
    }
    let sum: usize = v.iter().sum();
    assert_eq!(sum, (N - 1) * N / 2);
}

fn many_allocations_reclaim() {
    // If dealloc didn't work, we'd OOM well before 1000 iterations at
    // 1 MiB total heap with 10 KiB allocations per iteration.
    for _ in 0..1_000 {
        let v: Vec<u8> = Vec::with_capacity(10 * 1024);
        core::hint::black_box(v);
    }
}
