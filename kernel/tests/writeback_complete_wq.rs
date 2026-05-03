//! Integration test for issue #757: per-cache `writeback_complete_wq`
//! park/wake protocol.
//!
//! Three properties are exercised under the real round-robin scheduler
//! (the host stub in `mem::page_cache` cannot really park tasks, so the
//! park-side test must run on bare metal):
//!
//! 1. **Park while writeback in-flight.** A waiter calls
//!    `cache.wait_writeback_complete(|| in_flight)` and stays parked
//!    until the predicate goes false. We assert the waiter does not
//!    make progress before the wake.
//! 2. **`PG_WRITEBACK` clear wakes parked waiters.** After flipping the
//!    in-flight flag, the driver calls `page.end_writeback()` (which
//!    clears `PG_WRITEBACK` and notifies the cache wq). Every parked
//!    waiter wakes and progresses past the park.
//! 3. **`Drop` kick wakes parked waiters even without explicit
//!    `end_writeback`.** A separate workload installs a page, takes an
//!    extra `Arc::clone` (so dropping the cache index entry does not
//!    take strong-count to 0), parks a waiter on the cache wq, then
//!    drops the extra clone. The Drop notify on the surviving page
//!    fires the wake.
//!
//! These three properties are the contract documented in RFC 0007
//! §Eviction liveness — landing them unblocks #740 (CLOCK-Pro
//! direct-reclaim), which parks on the same wq.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use spin::Mutex as SpinMutex;

use vibix::mem::aops::AddressSpaceOps;
use vibix::mem::page_cache::{CachePage, InodeId, InstallOutcome, PageCache};
use vibix::sync::WaitQueue;
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
            "park_blocks_until_pg_writeback_clears",
            &(park_blocks_until_pg_writeback_clears as fn()),
        ),
        (
            "end_writeback_wakes_all_parked_waiters",
            &(end_writeback_wakes_all_parked_waiters as fn()),
        ),
        (
            "cachepage_drop_wakes_parked_waiters",
            &(cachepage_drop_wakes_parked_waiters as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// --- Test fixture ---------------------------------------------------------

/// Trivial in-memory `AddressSpaceOps` so [`PageCache::new`] is happy.
/// The wq tests never invoke `readpage` / `writepage`, so all four hooks
/// can return placeholder values; the test only exercises the install-
/// then-park / wake protocol.
struct NullOps;

impl AddressSpaceOps for NullOps {
    fn readpage(&self, _pgoff: u64, _buf: &mut [u8; 4096]) -> Result<usize, i64> {
        // Required-method contract: assert_no_spinlocks_held first.
        // The wq tests never invoke this — it's only here so the impl
        // type-checks.
        vibix::debug_lockdep::assert_no_spinlocks_held("NullOps::readpage");
        Ok(4096)
    }
    fn writepage(&self, _pgoff: u64, _buf: &[u8; 4096]) -> Result<(), i64> {
        vibix::debug_lockdep::assert_no_spinlocks_held("NullOps::writepage");
        Ok(())
    }
}

fn fresh_cache() -> Arc<PageCache> {
    let ops: Arc<dyn AddressSpaceOps> = Arc::new(NullOps);
    Arc::new(PageCache::new(InodeId::new(0xfeed_face, 1), 0, ops))
}

/// Allocate a fresh frame so each test gets a non-aliased `phys`.
/// The wq tests never actually dereference the frame, but the cache
/// holds a `frame::put` discipline (will land in #740) so honest
/// allocation keeps invariants happy.
fn fresh_phys() -> u64 {
    vibix::mem::frame::alloc().expect("frame::alloc")
}

/// Driver-side park: spin-with-`hlt` until `parked()` reports `expected`
/// waiters have actually enqueued themselves on the wq under test.
/// Same pattern as `blocking_sync.rs::wait_for_parked`.
fn wait_for_parked<F: Fn() -> usize>(parked: F, expected: usize, deadline_ticks: usize) {
    for _ in 0..deadline_ticks {
        if parked() >= expected {
            return;
        }
        x86_64::instructions::hlt();
    }
    if parked() >= expected {
        return;
    }
    panic!(
        "waiters didn't park in time: parked={}/{}",
        parked(),
        expected
    );
}

// --- park_blocks_until_pg_writeback_clears -------------------------------

static T1_CACHE: SpinMutex<Option<Arc<PageCache>>> = SpinMutex::new(None);
static T1_INFLIGHT: AtomicBool = AtomicBool::new(false);
static T1_PROGRESS: AtomicUsize = AtomicUsize::new(0);
static T1_PAGE: SpinMutex<Option<Arc<CachePage>>> = SpinMutex::new(None);

fn t1_waiter() -> ! {
    let cache = T1_CACHE.lock().clone().expect("T1_CACHE not set");
    cache.wait_writeback_complete(|| T1_INFLIGHT.load(Ordering::SeqCst));
    T1_PROGRESS.fetch_add(1, Ordering::SeqCst);
    task::exit();
}

fn park_blocks_until_pg_writeback_clears() {
    let cache = fresh_cache();
    let stub = match cache.install_or_get(0, || CachePage::new_locked(fresh_phys(), 0)) {
        InstallOutcome::InstalledNew(p) => p,
        InstallOutcome::AlreadyPresent(_) => unreachable!(),
    };
    stub.publish_uptodate_and_unlock();
    stub.begin_writeback();

    *T1_CACHE.lock() = Some(Arc::clone(&cache));
    *T1_PAGE.lock() = Some(Arc::clone(&stub));
    T1_INFLIGHT.store(true, Ordering::SeqCst);
    T1_PROGRESS.store(0, Ordering::SeqCst);

    task::spawn(t1_waiter);

    // Wait until the worker has actually parked on the cache wq.
    let wq: Arc<WaitQueue> = cache.writeback_complete_wq();
    wait_for_parked(|| wq.waiter_count(), 1, 200);

    // Critical assertion: the waiter has not made progress while the
    // in-flight flag is still set. (We've idled enough hlt cycles for
    // a runaway worker to fall through; if it had, this would be 1.)
    assert_eq!(
        T1_PROGRESS.load(Ordering::SeqCst),
        0,
        "waiter progressed past the park before the wake fired"
    );

    // Flip the predicate, then conclude writeback. end_writeback's
    // notify_all on the cache wq is the wake that frees the parker.
    T1_INFLIGHT.store(false, Ordering::SeqCst);
    stub.end_writeback();

    // Worker should observe the wake and bump the counter.
    for _ in 0..1_000 {
        if T1_PROGRESS.load(Ordering::SeqCst) == 1 {
            break;
        }
        x86_64::instructions::hlt();
    }
    assert_eq!(
        T1_PROGRESS.load(Ordering::SeqCst),
        1,
        "end_writeback didn't wake the parked waiter"
    );

    // Cleanup hand-offs.
    *T1_CACHE.lock() = None;
    *T1_PAGE.lock() = None;
}

// --- end_writeback_wakes_all_parked_waiters ------------------------------

static T2_CACHE: SpinMutex<Option<Arc<PageCache>>> = SpinMutex::new(None);
static T2_INFLIGHT: AtomicBool = AtomicBool::new(false);
static T2_WOKEN: AtomicUsize = AtomicUsize::new(0);

fn t2_waiter() -> ! {
    let cache = T2_CACHE.lock().clone().expect("T2_CACHE not set");
    cache.wait_writeback_complete(|| T2_INFLIGHT.load(Ordering::SeqCst));
    T2_WOKEN.fetch_add(1, Ordering::SeqCst);
    task::exit();
}

fn end_writeback_wakes_all_parked_waiters() {
    // Multiple parked waiters: a single end_writeback's notify_all
    // must wake every one of them.
    let cache = fresh_cache();
    let stub = match cache.install_or_get(0, || CachePage::new_locked(fresh_phys(), 0)) {
        InstallOutcome::InstalledNew(p) => p,
        InstallOutcome::AlreadyPresent(_) => unreachable!(),
    };
    stub.publish_uptodate_and_unlock();
    stub.begin_writeback();

    *T2_CACHE.lock() = Some(Arc::clone(&cache));
    T2_INFLIGHT.store(true, Ordering::SeqCst);
    T2_WOKEN.store(0, Ordering::SeqCst);

    task::spawn(t2_waiter);
    task::spawn(t2_waiter);
    task::spawn(t2_waiter);

    let wq: Arc<WaitQueue> = cache.writeback_complete_wq();
    wait_for_parked(|| wq.waiter_count(), 3, 200);
    assert_eq!(
        T2_WOKEN.load(Ordering::SeqCst),
        0,
        "waiters woke before the wake fired"
    );

    // Flip predicate, conclude writeback — one notify_all wakes all 3.
    T2_INFLIGHT.store(false, Ordering::SeqCst);
    stub.end_writeback();

    for _ in 0..2_000 {
        if T2_WOKEN.load(Ordering::SeqCst) == 3 {
            break;
        }
        x86_64::instructions::hlt();
    }
    assert_eq!(
        T2_WOKEN.load(Ordering::SeqCst),
        3,
        "end_writeback's notify_all didn't wake every parked waiter"
    );

    *T2_CACHE.lock() = None;
}

// --- cachepage_drop_wakes_parked_waiters ---------------------------------

static T3_CACHE: SpinMutex<Option<Arc<PageCache>>> = SpinMutex::new(None);
static T3_PINNED: AtomicBool = AtomicBool::new(false);
static T3_PROGRESS: AtomicUsize = AtomicUsize::new(0);

fn t3_waiter() -> ! {
    let cache = T3_CACHE.lock().clone().expect("T3_CACHE not set");
    cache.wait_writeback_complete(|| T3_PINNED.load(Ordering::SeqCst));
    T3_PROGRESS.fetch_add(1, Ordering::SeqCst);
    task::exit();
}

fn cachepage_drop_wakes_parked_waiters() {
    // The Drop kick: a CachePage that gets dropped *without* an
    // explicit `end_writeback` must still wake direct-reclaim parkers.
    // Models the path RFC 0007 §Eviction liveness item 3(b) calls out:
    // an `Arc::clone`-pinned page becoming unpinned should give the
    // parker a retry opportunity.
    let cache = fresh_cache();
    let stub = match cache.install_or_get(0, || CachePage::new_locked(fresh_phys(), 0)) {
        InstallOutcome::InstalledNew(p) => p,
        InstallOutcome::AlreadyPresent(_) => unreachable!(),
    };
    stub.publish_uptodate_and_unlock();

    *T3_CACHE.lock() = Some(Arc::clone(&cache));
    // Predicate: parked while the extra clone exists. We'll flip it
    // *and* drop the clone in lockstep.
    T3_PINNED.store(true, Ordering::SeqCst);
    T3_PROGRESS.store(0, Ordering::SeqCst);

    // Take a separate clone that mirrors the "in-flight fault clone"
    // RFC 0007 §Refcount discipline describes. We then evict the
    // page from the cache index *and* drop our own outer `stub` so
    // this clone is the sole strong-count holder.
    let extra_clone = Arc::clone(&stub);
    cache.inner.lock().pages.remove(&0);
    drop(stub); // strong_count: index gone, outer gone, only `extra_clone` left.

    task::spawn(t3_waiter);

    let wq: Arc<WaitQueue> = cache.writeback_complete_wq();
    wait_for_parked(|| wq.waiter_count(), 1, 200);
    assert_eq!(
        T3_PROGRESS.load(Ordering::SeqCst),
        0,
        "waiter progressed before the Drop kick"
    );

    // Flip the predicate, then drop the last strong holder. Drop
    // fires `parent_wb_wq.notify_all()` which wakes the parker.
    T3_PINNED.store(false, Ordering::SeqCst);
    drop(extra_clone);

    for _ in 0..1_000 {
        if T3_PROGRESS.load(Ordering::SeqCst) == 1 {
            break;
        }
        x86_64::instructions::hlt();
    }
    assert_eq!(
        T3_PROGRESS.load(Ordering::SeqCst),
        1,
        "CachePage Drop kick didn't wake the parked waiter"
    );

    *T3_CACHE.lock() = None;
}
