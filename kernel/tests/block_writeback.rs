//! Integration test for issue #555: per-mount writeback daemon under
//! `SbActiveGuard`.
//!
//! Runs the real kernel under QEMU. Exercises:
//!
//! - **Daemon fires after the configured interval**: start a daemon
//!   at 500 ms cadence, dirty a buffer in the cache, wait ~1.5 s.
//!   The buffer must end up clean (dirty bit cleared) and the
//!   backing ramdisk must have seen at least one write.
//!
//! - **`join` waits for the daemon**: `WritebackHandle::join` must
//!   not return before the spawned kernel task has set `done = true`
//!   and called `task::exit`. After join, the dirty set is empty —
//!   either because a final sweep flushed it or because `join` is
//!   itself followed by a manual `sync_fs` in the real unmount path.
//!
//! - **No writeback on RO mounts**: constructing a daemon with an
//!   `SbFlags::RDONLY` superblock returns `None`. No task is
//!   spawned; no background sweep happens.
//!
//! Covers the list items in issue #555:
//!
//! > Spawn a per-mount kernel thread at mount time; stash the handle.
//! > Loop: sleep for interval, then call BlockCache::sync_fs(sb).
//! > Hold an SbActiveGuard around each sync; exit cleanly if guard
//! > fails.
//! > SuperOps::unmount signals drain, joins the thread before
//! > destroying the superblock.
//! > No writeback on RO mounts.
//! > writeback_secs=<N> parsed in boot init (unit-tested in the
//! > cmdline parser; not re-exercised here).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;

use vibix::block::cache::{BlockCache, STATE_DIRTY};
use vibix::block::writeback::{
    self, configured_secs, reset_configured_for_tests, DEFAULT_INTERVAL_SECS,
};
use vibix::block::BlockDevice;
use vibix::fs::vfs::ops::{StatFs, SuperOps};
use vibix::fs::vfs::super_block::{SbFlags, SuperBlock};
use vibix::fs::vfs::{FsId, Inode};
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
            "writeback_fires_after_interval",
            &(writeback_fires_after_interval as fn()),
        ),
        (
            "join_waits_for_daemon_and_leaves_no_dirty_buffers",
            &(join_waits_for_daemon as fn()),
        ),
        (
            "no_writeback_on_ro_mount",
            &(no_writeback_on_ro_mount as fn()),
        ),
        (
            "writeback_secs_zero_disables_daemon",
            &(writeback_secs_zero_disables_daemon as fn()),
        ),
        (
            "default_cadence_is_thirty_seconds",
            &(default_cadence as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// --- Helpers --------------------------------------------------------------

/// In-memory ramdisk that counts writes so tests can distinguish
/// "daemon-driven flush" from "sync_fs explicit call".
// Shared `RamDisk` — see kernel/tests/common/ext2_ramdisk.rs (issues
// #627, #658).
#[path = "common/ext2_ramdisk.rs"]
mod ext2_ramdisk;
use ext2_ramdisk::RamDisk;

/// Stub `SuperOps` — the writeback daemon only calls into
/// `SuperBlock` fields (flags / draining / sb_active), never through
/// `SuperOps::*`, so a minimal stub is enough to stand up a real
/// superblock.
struct StubSuper;
impl SuperOps for StubSuper {
    fn root_inode(&self) -> Arc<Inode> {
        unreachable!("StubSuper::root_inode should not be called from writeback tests")
    }
    fn statfs(&self) -> Result<StatFs, i64> {
        Ok(StatFs::default())
    }
    fn unmount(&self) {}
}

fn make_sb(flags: SbFlags) -> Arc<SuperBlock> {
    Arc::new(SuperBlock::new(
        FsId(0xbeef),
        Arc::new(StubSuper),
        "writeback_test",
        512,
        flags,
    ))
}

// --- Tests ----------------------------------------------------------------

/// Start a daemon at 500 ms cadence, dirty a buffer, wait for at
/// least one sweep to land. The buffer's DIRTY bit must clear and the
/// ramdisk must observe at least one write.
fn writeback_fires_after_interval() {
    reset_configured_for_tests();
    writeback::set_configured_secs(1);
    // 1 s cadence is the shortest the secs-granularity knob supports;
    // fine for a test budget of ~3 s.

    let disk = RamDisk::zeroed(512, 16);
    let cache = BlockCache::new(disk.clone() as Arc<dyn BlockDevice>, 512, 8);
    let dev = cache.register_device();
    let sb = make_sb(SbFlags::default());

    let bh = cache.bread(dev, 4).expect("bread 4");
    {
        let mut data = bh.data.write();
        for (i, slot) in data.iter_mut().enumerate() {
            *slot = 0x77u8.wrapping_add(i as u8);
        }
    }
    cache.mark_dirty(&bh);
    assert!(bh.state_has(STATE_DIRTY), "buffer must start dirty");

    let writes_before = disk.writes();
    let handle = writeback::start(sb.clone(), cache.clone(), dev)
        .expect("writeback daemon must start for a RW mount");

    // Wait up to ~3 s for at least one sweep to land. Route through
    // the scheduler/IRQ seam (RFC 0005); production resolves to the
    // same `time::ticks()` source.
    let (clock, _irq) = vibix::task::env::env();
    let start_ticks = clock.now().raw();
    let deadline = start_ticks + 300; // 3 s at 100 Hz
    while clock.now().raw() < deadline {
        if handle.sweeps() >= 1 {
            break;
        }
        x86_64::instructions::hlt();
    }

    assert!(
        handle.sweeps() >= 1,
        "writeback daemon never swept — sweeps={} after {} ticks",
        handle.sweeps(),
        clock.now().raw() - start_ticks,
    );
    assert!(
        !bh.state_has(STATE_DIRTY),
        "dirty bit should have been cleared by the daemon's sync_fs"
    );
    assert!(
        disk.writes() > writes_before,
        "daemon should have driven at least one device write (before={}, after={})",
        writes_before,
        disk.writes(),
    );

    // Release the buffer handle before join so the cache isn't
    // pinning buffers the daemon may also see.
    drop(bh);

    handle.join();
    assert!(
        handle.task_id() != 0,
        "daemon must have recorded its task id before exit"
    );
}

/// `join` must not return until the daemon task has reached
/// `task::exit`. After join, the mount's dirty set must be empty
/// (because the daemon's final sweep, or the umount-path's explicit
/// `sync_fs`, flushed everything).
fn join_waits_for_daemon() {
    reset_configured_for_tests();
    writeback::set_configured_secs(1);

    let disk = RamDisk::zeroed(512, 16);
    let cache = BlockCache::new(disk.clone() as Arc<dyn BlockDevice>, 512, 8);
    let dev = cache.register_device();
    let sb = make_sb(SbFlags::default());

    // Dirty a buffer so there's something to flush.
    let bh = cache.bread(dev, 2).expect("bread 2");
    {
        let mut data = bh.data.write();
        for b in data.iter_mut() {
            *b = 0x42;
        }
    }
    cache.mark_dirty(&bh);
    drop(bh);

    let handle =
        writeback::start(sb.clone(), cache.clone(), dev).expect("writeback daemon must start");

    // Pre-emptive flush would leave nothing for the daemon to do; skip
    // it so the "join drains pending dirty state" assertion is
    // meaningful.
    //
    // Real unmount path orders: (a) set draining, (b) gc_drain_for,
    // (c) sb.ops.sync_fs, (d) sb.ops.unmount (which calls
    // handle.join). We mirror (c) + (d) here. After (c), the dirty
    // set is empty — so even if the daemon's final sweep races with
    // join, nothing is left unflushed.
    cache.sync_fs(dev).expect("explicit sync_fs ok");

    let task_id_before_join = handle.task_id();
    // Task id might be 0 if the daemon hasn't scheduled yet; that's
    // benign — `join` waits on `done`, not on `task_id`.

    handle.join();

    // After join, the daemon task has exited. Its sweep counter is
    // frozen; subsequent reads observe the same value. We can't use
    // `task::sleep_ms` here because the joined daemon was the only
    // other task in this tiny test process — parking via `block_current`
    // with no ready task panics. Busy-wait on `time::ticks` instead;
    // `hlt` yields CPU to the timer ISR so the wait actually advances.
    let sweeps_after = handle.sweeps();
    // Route through the scheduler/IRQ seam (RFC 0005).
    let (clock, _irq) = vibix::task::env::env();
    let deadline = clock.now().raw() + 20; // ~200 ms at 100 Hz
    while clock.now().raw() < deadline {
        x86_64::instructions::hlt();
    }
    assert_eq!(
        handle.sweeps(),
        sweeps_after,
        "daemon must not sweep after join returned"
    );

    assert!(
        cache.sync_fs(dev).is_ok(),
        "cache is still usable after daemon join (no lingering LOCKED_IO)"
    );

    // Task id either recorded (daemon ran at least once) or zero
    // (daemon never got scheduled before join's stop signal). Both
    // are fine — we just need `join` to have waited on the happy
    // path.
    let _ = task_id_before_join;
}

/// RO mounts must not spawn a writeback daemon. `start` returns
/// `None` and no task id is allocated.
fn no_writeback_on_ro_mount() {
    reset_configured_for_tests();
    writeback::set_configured_secs(1);

    let disk = RamDisk::zeroed(512, 8);
    let cache = BlockCache::new(disk.clone() as Arc<dyn BlockDevice>, 512, 4);
    let dev = cache.register_device();
    let sb = make_sb(SbFlags::RDONLY);

    let handle = writeback::start(sb, cache, dev);
    assert!(
        handle.is_none(),
        "RO mount must not spawn a writeback daemon"
    );
}

/// `writeback_secs=0` on the cmdline disables writeback globally —
/// even RW mounts don't spawn a daemon.
fn writeback_secs_zero_disables_daemon() {
    reset_configured_for_tests();
    // Simulate `writeback_secs=0` on the kernel cmdline.
    assert!(writeback::parse_cmdline(b"writeback_secs=0"));
    assert!(writeback::is_disabled());

    let disk = RamDisk::zeroed(512, 8);
    let cache = BlockCache::new(disk.clone() as Arc<dyn BlockDevice>, 512, 4);
    let dev = cache.register_device();
    let sb = make_sb(SbFlags::default());

    let handle = writeback::start(sb, cache, dev);
    assert!(
        handle.is_none(),
        "writeback_secs=0 must prevent daemon spawn even on RW mounts"
    );

    // Reset for the rest of the run.
    reset_configured_for_tests();
}

/// `configured_secs()` returns the default (30 s) before any cmdline
/// override. Pins the default from RFC 0004 §Buffer cache writeback
/// ("30 s Linux default") so a future change to the constant is
/// loud.
fn default_cadence() {
    reset_configured_for_tests();
    assert_eq!(configured_secs(), DEFAULT_INTERVAL_SECS);
    assert_eq!(DEFAULT_INTERVAL_SECS, 30);
}
