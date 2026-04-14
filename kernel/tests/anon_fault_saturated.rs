//! Integration test for #255: `AnonObject::fault` cache-hit and
//! `insert_existing_frame` must refuse to bump a frame whose refcount is
//! already pinned at `u16::MAX`, rather than silently saturating and
//! publishing a reference the refcount cannot represent (UAF on the
//! matching drop).

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::sync::atomic::Ordering;

use vibix::mem::refcount;
use vibix::mem::vmobject::{Access, AnonObject, VmFault, VmObject};
use vibix::{
    exit_qemu, serial_println, task,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

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
        (
            "fault_cache_hit_refuses_saturated_frame",
            &(fault_cache_hit_refuses_saturated_frame as fn()),
        ),
        (
            "insert_existing_frame_refuses_saturated",
            &(insert_existing_frame_refuses_saturated as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

/// Prime the given frame's refcount to `value` and return the amount we
/// bumped it by, so the caller can restore it before drop. Uses the raw
/// slot because `inc_refcount` saturates silently and `try_inc_refcount`
/// would refuse past MAX.
fn bump_refcount_to(phys: u64, value: u16) -> u16 {
    let slot = refcount::page_refcount(phys);
    let cur = slot.load(Ordering::Relaxed);
    assert!(value >= cur, "bump_refcount_to can only raise the slot");
    slot.store(value, Ordering::Relaxed);
    value - cur
}

/// Restore a previously-bumped slot by subtracting `delta`. The object's
/// `Drop` will still balance the natural refcount; we only need to undo
/// the artificial inflation before that runs.
fn unbump_refcount(phys: u64, delta: u16) {
    let slot = refcount::page_refcount(phys);
    let cur = slot.load(Ordering::Relaxed);
    assert!(cur >= delta, "unbump underflow");
    slot.store(cur - delta, Ordering::Relaxed);
}

/// Cache-hit fault with the frame's refcount already at `u16::MAX` must
/// return `VmFault::RefcountSaturated` rather than publishing a new
/// reference the refcount cannot track.
fn fault_cache_hit_refuses_saturated_frame() {
    // Fault once through a fresh object so the cache holds a real frame
    // whose refcount we control. Write-access avoids any future CoW
    // demotion that might add more references.
    let obj = AnonObject::new(Some(1));
    let phys = obj
        .fault(0, Access::Write)
        .expect("initial fault must succeed");

    // Pin the slot at MAX; the next fault is a cache hit, which today
    // does a checked increment and must refuse.
    let delta = bump_refcount_to(phys, u16::MAX);

    match obj.fault(0, Access::Read) {
        Err(VmFault::RefcountSaturated) => {}
        Err(other) => panic!("expected RefcountSaturated, got {other:?}"),
        Ok(_) => panic!("fault must refuse to bump a saturated refcount"),
    }

    // Slot is still at MAX — the checked increment did not corrupt it.
    assert_eq!(
        refcount::page_refcount(phys).load(Ordering::Relaxed),
        u16::MAX,
        "refused fault must not move the refcount slot",
    );

    // Cache entry is still there: frame_at returns the same frame. The
    // refused fault only blocks the increment, it does not evict.
    assert_eq!(obj.frame_at(0), Some(phys));

    // Undo the artificial inflation so the object's Drop balances.
    unbump_refcount(phys, delta);
    drop(obj);
}

/// `insert_existing_frame` on a frame whose refcount is already at
/// `u16::MAX` must return `Err(Saturated)` and must not insert the frame
/// into the cache (otherwise `Drop` would later decrement a reference
/// the refcount never recorded).
fn insert_existing_frame_refuses_saturated() {
    // Allocate a frame via a throw-away object, then detach it: we keep
    // the refcount slot alive but leave the target object with an empty
    // cache so we are the only one trying to insert.
    let scratch = AnonObject::new(Some(1));
    let phys = scratch
        .fault(0, Access::Write)
        .expect("scratch fault must succeed");

    // Pin the slot at MAX and drive the target through the
    // public API. The bumped slot means `insert_existing_frame`
    // must refuse.
    let delta = bump_refcount_to(phys, u16::MAX);

    let target = AnonObject::new(Some(1));
    let result = target.insert_existing_frame(0, phys);
    assert!(
        matches!(result, Err(refcount::Saturated)),
        "expected Err(Saturated), got {result:?}",
    );

    // Target cache is still empty: frame_at returns None, so no dangling
    // reference will fire in Drop.
    assert_eq!(target.frame_at(0), None);

    // Slot still pinned at MAX; the refused call did not touch it.
    assert_eq!(
        refcount::page_refcount(phys).load(Ordering::Relaxed),
        u16::MAX,
    );

    unbump_refcount(phys, delta);
    drop(target);
    drop(scratch);
}
