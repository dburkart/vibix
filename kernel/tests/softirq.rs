//! Integration test: soft-IRQ primitive (#404).
//!
//! Verifies the raise/drain flow end-to-end. We register a handler,
//! raise the bit from task context, and let the drain at the tail of
//! `preempt_tick` run it on the next timer IRQ. The latch case
//! re-raises inside the handler and asserts it fires again.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, Ordering};

use vibix::task::softirq::{drain, raise, register, reset_for_test, SoftIrq};
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
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
        (
            "drain_with_nothing_pending_is_noop",
            &(drain_with_nothing_pending_is_noop as fn()),
        ),
        (
            "unregistered_vector_is_silently_dropped",
            &(unregistered_vector_is_silently_dropped as fn()),
        ),
        (
            "multiple_raises_coalesce_to_one_run",
            &(multiple_raises_coalesce_to_one_run as fn()),
        ),
        ("two_vectors_both_fire", &(two_vectors_both_fire as fn())),
        (
            "raise_fires_handler_on_next_tick",
            &(raise_fires_handler_on_next_tick as fn()),
        ),
        (
            "re_raise_inside_handler_latches",
            &(re_raise_inside_handler_latches as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

static RAN: AtomicU32 = AtomicU32::new(0);
fn ran_handler() {
    RAN.fetch_add(1, Ordering::Relaxed);
}

static A_COUNT: AtomicU32 = AtomicU32::new(0);
fn handler_a() {
    A_COUNT.fetch_add(1, Ordering::Relaxed);
}

static B_COUNT: AtomicU32 = AtomicU32::new(0);
fn handler_b() {
    B_COUNT.fetch_add(1, Ordering::Relaxed);
}

fn drain_with_nothing_pending_is_noop() {
    reset_for_test();
    A_COUNT.store(0, Ordering::Relaxed);
    register(SoftIrq::SerialRx, handler_a);
    drain();
    assert_eq!(A_COUNT.load(Ordering::Relaxed), 0);
}

fn unregistered_vector_is_silently_dropped() {
    reset_for_test();
    raise(SoftIrq::PS2Rx);
    drain();
}

fn multiple_raises_coalesce_to_one_run() {
    reset_for_test();
    A_COUNT.store(0, Ordering::Relaxed);
    register(SoftIrq::SerialRx, handler_a);
    raise(SoftIrq::SerialRx);
    raise(SoftIrq::SerialRx);
    raise(SoftIrq::SerialRx);
    drain();
    assert_eq!(A_COUNT.load(Ordering::Relaxed), 1);
}

fn two_vectors_both_fire() {
    reset_for_test();
    A_COUNT.store(0, Ordering::Relaxed);
    B_COUNT.store(0, Ordering::Relaxed);
    register(SoftIrq::SerialRx, handler_a);
    register(SoftIrq::PS2Rx, handler_b);
    raise(SoftIrq::SerialRx);
    raise(SoftIrq::PS2Rx);
    drain();
    assert_eq!(A_COUNT.load(Ordering::Relaxed), 1);
    assert_eq!(B_COUNT.load(Ordering::Relaxed), 1);
}

fn raise_fires_handler_on_next_tick() {
    reset_for_test();
    RAN.store(0, Ordering::Relaxed);
    register(SoftIrq::SerialRx, ran_handler);
    raise(SoftIrq::SerialRx);
    // Let preempt_tick drain at least once. At 100 Hz a handful of
    // hlts is plenty.
    for _ in 0..10 {
        x86_64::instructions::hlt();
    }
    assert!(
        RAN.load(Ordering::Relaxed) >= 1,
        "softirq handler did not run"
    );
}

static LATCH_COUNT: AtomicU32 = AtomicU32::new(0);
fn latch_handler() {
    let n = LATCH_COUNT.fetch_add(1, Ordering::Relaxed);
    // Re-raise exactly once so the next drain runs us a second time.
    // Guarded so we don't loop forever if the drain somehow replays
    // inside the same call.
    if n == 0 {
        raise(SoftIrq::PS2Rx);
    }
}

fn re_raise_inside_handler_latches() {
    reset_for_test();
    LATCH_COUNT.store(0, Ordering::Relaxed);
    register(SoftIrq::PS2Rx, latch_handler);
    raise(SoftIrq::PS2Rx);
    for _ in 0..20 {
        x86_64::instructions::hlt();
    }
    assert!(
        LATCH_COUNT.load(Ordering::Relaxed) >= 2,
        "re-raised softirq did not fire a second time: {}",
        LATCH_COUNT.load(Ordering::Relaxed)
    );
}
