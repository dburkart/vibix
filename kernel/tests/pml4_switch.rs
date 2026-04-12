//! Integration test: after `vibix::init` builds a fresh kernel PML4 and
//! swaps CR3 to it, known-good virtual addresses still translate and
//! read/write as expected, and the allocator can still grow the heap
//! into the new tree.

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
use x86_64::VirtAddr;

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
        ("kernel_text_translates", &(kernel_text_translates as fn())),
        ("heap_ptr_translates", &(heap_ptr_translates as fn())),
        ("stack_local_translates", &(stack_local_translates as fn())),
        ("heap_grows_after_switch", &(heap_grows_after_switch as fn())),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

fn kernel_text_translates() {
    use vibix::mem::paging;
    let fn_ptr: fn() = kernel_text_translates;
    let va = VirtAddr::new(fn_ptr as usize as u64);
    let phys = paging::translate(va).expect("kernel .text address not mapped after CR3 switch");
    serial_println!("  fn @ {va:?} -> {phys:?}");
}

fn heap_ptr_translates() {
    use vibix::mem::paging;
    let boxed = Box::new(0xCAFE_F00Du64);
    let va = VirtAddr::new(&*boxed as *const u64 as u64);
    let phys = paging::translate(va).expect("heap address not mapped after CR3 switch");
    assert_eq!(*boxed, 0xCAFE_F00D);
    serial_println!("  heap @ {va:?} -> {phys:?}");
}

fn stack_local_translates() {
    use vibix::mem::paging;
    let local: u64 = 0xDEAD_BEEF_DEAD_BEEF;
    let va = VirtAddr::new(&local as *const u64 as u64);
    let phys = paging::translate(va).expect("stack local not mapped after CR3 switch");
    assert_eq!(local, 0xDEAD_BEEF_DEAD_BEEF);
    serial_println!("  stack @ {va:?} -> {phys:?}");
}

fn heap_grows_after_switch() {
    // Force the heap past the 1 MiB initial slab to exercise
    // `heap::grow_once` → `paging::map_range` against the new tree.
    let before = vibix::mem::heap::mapped_size();
    let mut v: Vec<u64> = Vec::new();
    for i in 0..(256 * 1024u64) {
        v.push(i);
    }
    let after = vibix::mem::heap::mapped_size();
    assert!(after > before, "heap did not grow after CR3 switch");
    assert_eq!(v[12345], 12345);
    serial_println!("  heap grew {before} -> {after} bytes");
}
