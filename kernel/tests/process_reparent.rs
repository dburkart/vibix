//! Integration test: orphan reparenting — parent exits before child,
//! child is reparented to PID 1, and PID 1 reaps it.
//!
//! Exercises:
//!   - `process::reparent_children` moves orphans to PID 1.
//!   - After reparenting, PID 1 can reap the zombie orphan.
//!   - Multiple orphans are all reparented.
//!   - Reparenting preserves the child's exit status.
//!   - Grandchildren are reparented correctly (only direct children move).
//!   - An alive child reparented to PID 1 can later be reaped by PID 1.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use vibix::process::{self, test_helpers as h};
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    vibix::task::init();
    x86_64::instructions::interrupts::enable();
    serial_println!("process_reparent: init ok");
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
            "orphan_reparented_to_pid1",
            &(orphan_reparented_to_pid1 as fn()),
        ),
        (
            "pid1_reaps_reparented_zombie",
            &(pid1_reaps_reparented_zombie as fn()),
        ),
        (
            "multiple_orphans_all_reparented",
            &(multiple_orphans_all_reparented as fn()),
        ),
        (
            "reparent_preserves_exit_status",
            &(reparent_preserves_exit_status as fn()),
        ),
        (
            "grandchild_stays_with_intermediate_parent",
            &(grandchild_stays_with_intermediate_parent as fn()),
        ),
        (
            "alive_orphan_reparented_then_zombie_reaped_by_pid1",
            &(alive_orphan_reparented_then_zombie_reaped_by_pid1 as fn()),
        ),
        (
            "reparent_no_children_is_noop",
            &(reparent_no_children_is_noop as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

/// When a parent process exits, `reparent_children` moves its children
/// to PID 1. Verify via `parent_pid_of`.
fn orphan_reparented_to_pid1() {
    h::reset_table();

    // PID 1 (init).
    h::insert(1, 0, 1, 1);
    // Parent PID 100 with child PID 200.
    h::insert(100, 1, 1, 1);
    h::insert(200, 100, 1, 1);

    // Verify child's parent is 100.
    assert_eq!(process::parent_pid_of(200), 100);

    // Parent 100 exits — reparent its children.
    process::reparent_children(100);

    // Child 200 should now be parented to PID 1.
    assert_eq!(process::parent_pid_of(200), 1);

    h::reset_table();
}

/// After reparenting a zombie child to PID 1, PID 1 can reap it.
fn pid1_reaps_reparented_zombie() {
    h::reset_table();

    h::insert(1, 0, 1, 1);
    h::insert(100, 1, 1, 1);
    h::insert(200, 100, 1, 1);

    // Child exits first (becomes zombie under parent 100).
    process::mark_zombie(200, 42);

    // Parent 100 exits — reparent zombie child to PID 1.
    process::reparent_children(100);

    // PID 1 should be able to reap the zombie.
    let reaped = process::reap_child(1, 200);
    assert_eq!(
        reaped,
        Some((200, 42)),
        "PID 1 should reap the reparented zombie"
    );

    h::reset_table();
}

/// Multiple children of a dying parent are all reparented to PID 1.
fn multiple_orphans_all_reparented() {
    h::reset_table();

    h::insert(1, 0, 1, 1);
    h::insert(100, 1, 1, 1);
    h::insert(201, 100, 1, 1);
    h::insert(202, 100, 1, 1);
    h::insert(203, 100, 1, 1);

    process::reparent_children(100);

    assert_eq!(process::parent_pid_of(201), 1);
    assert_eq!(process::parent_pid_of(202), 1);
    assert_eq!(process::parent_pid_of(203), 1);

    h::reset_table();
}

/// Reparenting preserves the exit status of zombie children.
fn reparent_preserves_exit_status() {
    h::reset_table();

    h::insert(1, 0, 1, 1);
    h::insert(100, 1, 1, 1);
    h::insert(200, 100, 1, 1);
    h::insert(201, 100, 1, 1);

    // Children exit with different statuses.
    process::mark_zombie(200, 10);
    process::mark_zombie(201, 99);

    // Parent exits.
    process::reparent_children(100);

    // PID 1 reaps — statuses should be preserved.
    let r1 = process::reap_child(1, 200);
    assert_eq!(r1, Some((200, 10)), "exit status 10 not preserved");

    let r2 = process::reap_child(1, 201);
    assert_eq!(r2, Some((201, 99)), "exit status 99 not preserved");

    h::reset_table();
}

/// Grandchildren (children of a child) are NOT moved by
/// `reparent_children(parent)` — only direct children are affected.
fn grandchild_stays_with_intermediate_parent() {
    h::reset_table();

    h::insert(1, 0, 1, 1);
    h::insert(100, 1, 1, 1); // grandparent
    h::insert(200, 100, 1, 1); // child
    h::insert(300, 200, 1, 1); // grandchild

    // Grandparent 100 exits.
    process::reparent_children(100);

    // Child 200 is reparented to PID 1.
    assert_eq!(process::parent_pid_of(200), 1);

    // Grandchild 300 stays with child 200 (not touched).
    assert_eq!(process::parent_pid_of(300), 200);

    h::reset_table();
}

/// An alive orphan reparented to PID 1 can later exit and be reaped.
fn alive_orphan_reparented_then_zombie_reaped_by_pid1() {
    h::reset_table();

    h::insert(1, 0, 1, 1);
    h::insert(100, 1, 1, 1);
    h::insert(200, 100, 1, 1);

    // Parent exits first — child is reparented alive.
    process::reparent_children(100);
    assert_eq!(process::parent_pid_of(200), 1);

    // Verify PID 1 has children.
    assert!(process::has_children(1));

    // Child isn't zombie yet — can't reap.
    assert_eq!(process::reap_child(1, 200), None);

    // Child exits.
    process::mark_zombie(200, 77);

    // Now PID 1 can reap.
    let reaped = process::reap_child(1, 200);
    assert_eq!(reaped, Some((200, 77)));

    h::reset_table();
}

/// `reparent_children` on a pid with no children is a no-op.
fn reparent_no_children_is_noop() {
    h::reset_table();

    h::insert(1, 0, 1, 1);
    h::insert(100, 1, 1, 1);

    // 100 has no children — reparent should not panic or corrupt state.
    process::reparent_children(100);

    // PID 1 should have one child (100).
    assert!(process::has_children(1));

    h::reset_table();
}
