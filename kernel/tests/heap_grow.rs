//! Integration test: the heap grows past its initial 1 MiB slab on
//! demand.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::panic::PanicInfo;

use vibix::{
    exit_qemu,
    mem::heap::{self, INITIAL_HEAP_SIZE},
    serial_println,
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
        ("starts_at_initial_size", &(starts_at_initial_size as fn())),
        ("grows_past_initial", &(grows_past_initial as fn())),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

fn starts_at_initial_size() {
    assert_eq!(heap::mapped_size(), INITIAL_HEAP_SIZE);
}

fn grows_past_initial() {
    // 2 MiB overshoots the 1 MiB initial slab enough to require at
    // least one grow step. Touch both ends so a silent half-mapping
    // would page-fault the test.
    const N: usize = 2 * 1024 * 1024;
    let v: Vec<u8> = vec![0xAB; N];
    assert_eq!(v.len(), N);
    assert_eq!(v[0], 0xAB);
    assert_eq!(v[N - 1], 0xAB);
    let after = heap::mapped_size();
    assert!(
        after > INITIAL_HEAP_SIZE,
        "heap did not grow: mapped_size={after}, INITIAL={INITIAL_HEAP_SIZE}"
    );
}
