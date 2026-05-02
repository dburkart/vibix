//! Per-mount writeback daemon.
//!
//! Implements RFC 0004 §Buffer cache writeback (Workstream C, wave 1,
//! issue #555). Each call to [`start`] spawns one kernel task that:
//!
//! 1. Sleeps for the configured writeback interval (default 30 s,
//!    configurable via `writeback_secs=<N>` on the kernel command
//!    line).
//! 2. Acquires an [`SbActiveGuard`] on the mount's superblock to pin it
//!    for the duration of the flush.
//! 3. Calls [`BlockCache::sync_fs`] with the mount's [`DeviceId`],
//!    which flushes every dirty buffer belonging to this mount.
//! 4. Drops the guard and repeats.
//!
//! Shutdown is driven by [`WritebackHandle::join`]:
//!
//! - `join` sets the daemon's `stop` flag, `notify`s the daemon's
//!   sleeper waitqueue, and parks on a second waitqueue until the
//!   daemon publishes `done = true` right before it calls
//!   [`crate::task::exit`].
//! - The daemon exits cleanly on the next loop iteration after
//!   observing `stop = true` (either via an explicit join, or because
//!   [`SbActiveGuard::try_acquire`] returned `ENOENT` — the superblock
//!   has gone `draining` out from under us).
//!
//! The guard is released across the sleep. Linux's `pdflush`/`flusher`
//! does the same for the same reason: holding an SB pin while parked
//! on a long timer would block `umount` for up to the interval.
//!
//! Read-only mounts never spawn a daemon — there is nothing to flush.
//! Likewise, an `interval_secs` of `0` is the documented "writeback
//! disabled" signal.

use core::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Cmdline knob — portable to host so the parser can be unit-tested
// without pulling in target-only `task` / `sync` symbols.
// ---------------------------------------------------------------------------

/// Compile-time default. Matches Linux's `dirty_writeback_centisecs`
/// coarse granularity (5 s soft / 30 s hard) — we pick the hard cadence
/// because we don't yet track per-buffer dirty age.
pub const DEFAULT_INTERVAL_SECS: u64 = 30;

/// Sentinel value in [`CONFIGURED_SECS`] meaning "writeback
/// disabled". `0` already means "use default"; we pick `u64::MAX` so
/// any plausible future value (hours, days) remains distinct.
pub const DISABLE_SENTINEL: u64 = u64::MAX;

/// Kernel-cmdline override, in seconds. `0` means "use
/// [`DEFAULT_INTERVAL_SECS`]"; [`DISABLE_SENTINEL`] means "writeback
/// disabled"; any other value replaces the default for every
/// subsequent [`start`] call.
static CONFIGURED_SECS: AtomicU64 = AtomicU64::new(0);

/// Install a kernel-cmdline `writeback_secs=<N>` override. Called once
/// at boot after parsing the Limine cmdline string. A value of `0`
/// means "disable writeback" (no daemon is ever spawned); any other
/// value replaces [`DEFAULT_INTERVAL_SECS`] for every subsequent
/// [`start`] call.
///
/// Calling this with a value higher than what [`start`] would pick up
/// on its own (e.g. from a test fixture after some mounts have
/// already been created) is legal but only affects future mounts; the
/// daemons spun up earlier continue on their original cadence until
/// they exit.
pub fn set_configured_secs(secs: u64) {
    CONFIGURED_SECS.store(secs, Ordering::SeqCst);
}

/// Current writeback interval in seconds. Reflects the most recent
/// [`set_configured_secs`] value, falling back to
/// [`DEFAULT_INTERVAL_SECS`] if no override has been installed.
pub fn configured_secs() -> u64 {
    let override_ = CONFIGURED_SECS.load(Ordering::SeqCst);
    if override_ == 0 {
        DEFAULT_INTERVAL_SECS
    } else {
        override_
    }
}

/// Return `true` if the configured cadence explicitly disables
/// writeback. Used by [`start`] to short-circuit; also exposed so
/// tests and the shell's `mount` builtin can report "writeback
/// disabled" without recomputing the logic.
pub fn is_disabled() -> bool {
    CONFIGURED_SECS.load(Ordering::SeqCst) == DISABLE_SENTINEL
}

/// Parse a kernel command-line string, looking for
/// `writeback_secs=<N>`. Whitespace-delimited; `N` must parse as a
/// `u64` or the token is silently ignored (we'd rather continue
/// booting with the default than panic on a typo).
///
/// The parser recognises:
///
/// - `writeback_secs=0` → treated as "disable writeback" (alias for
///   the sentinel).
/// - `writeback_secs=N` for any other `N` → override the default to N
///   seconds.
///
/// Multiple occurrences: last one wins, matching how Linux handles
/// duplicate cmdline parameters.
///
/// Returns `true` if any `writeback_secs=…` token was found (so the
/// caller can log that the override was applied); `false` otherwise.
pub fn parse_cmdline(cmdline: &[u8]) -> bool {
    const PREFIX: &[u8] = b"writeback_secs=";
    let mut matched = false;
    let mut i = 0;
    while i < cmdline.len() {
        while i < cmdline.len() && is_ws(cmdline[i]) {
            i += 1;
        }
        let start = i;
        while i < cmdline.len() && !is_ws(cmdline[i]) {
            i += 1;
        }
        let token = &cmdline[start..i];
        if let Some(rest) = token.strip_prefix(PREFIX) {
            if let Some(secs) = parse_u64(rest) {
                if secs == 0 {
                    set_configured_secs(DISABLE_SENTINEL);
                } else {
                    set_configured_secs(secs);
                }
                matched = true;
            }
            // Unparseable value → ignore; boot continues with the
            // previously-set (or default) cadence.
        }
    }
    matched
}

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

fn parse_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut acc: u64 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(acc)
}

/// Reset the configured-seconds atomic. Test-only hook so integration
/// and unit tests can leave the global in a deterministic state
/// between runs — in production the value is set exactly once at
/// boot.
#[doc(hidden)]
pub fn reset_configured_for_tests() {
    CONFIGURED_SECS.store(0, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// Daemon — target-only. The parser above is portable; the daemon needs
// `task` and `WaitQueue`, which exist only on the kernel target.
// ---------------------------------------------------------------------------

#[cfg(target_os = "none")]
mod daemon {
    use super::{configured_secs, is_disabled, DISABLE_SENTINEL};

    use alloc::collections::VecDeque;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use spin::Mutex;

    use crate::fs::vfs::super_block::{SbActiveGuard, SbFlags, SuperBlock};
    use crate::sync::WaitQueue;
    use crate::task;

    use super::super::cache::{BlockCache, DeviceId};

    /// Stash for daemon-spawn parameters. `task::spawn` takes a bare
    /// `fn() -> !`, so we hand the per-daemon state off through this
    /// FIFO: [`start`] pushes the state, spawns the entry function,
    /// and the entry function pops its own state on first run. A
    /// FIFO (rather than a single-slot mutex) means two mounts can
    /// race their `start` calls without either caller stalling
    /// waiting for the other's daemon to boot.
    static SPAWN_QUEUE: Mutex<VecDeque<Arc<WritebackState>>> = Mutex::new(VecDeque::new());

    /// Per-daemon state shared between the caller of [`start`] (who
    /// holds the [`WritebackHandle`]) and the spawned kernel task.
    pub(super) struct WritebackState {
        /// Strong reference to the pinned superblock. The daemon
        /// holds this for its whole lifetime — even when the mount's
        /// `MountEdge` has been taken out of the table by Phase A of
        /// `unmount`, the daemon can still read `sb.draining` and
        /// exit cleanly on the next sweep.
        sb: Arc<SuperBlock>,
        /// The `BlockCache` whose dirty buffers we flush. One cache
        /// per mount in the current design, but `DeviceId` is
        /// carried separately so a future shared-cache layout works
        /// without API churn.
        cache: Arc<BlockCache>,
        device_id: DeviceId,
        /// Flush cadence in seconds. Copied from
        /// [`configured_secs`] at daemon-spawn time; never mutated
        /// after construction, so a runtime cmdline override
        /// doesn't shift an existing daemon's cadence.
        interval_secs: u64,
        /// `join` / `unmount` sets this to request a clean daemon
        /// exit. Checked both on wake and at the top of every loop
        /// iteration — a join racing with the sleep wakes the daemon
        /// so it observes `stop` promptly instead of waiting out the
        /// full interval.
        pub(super) stop: AtomicBool,
        /// Published by the daemon right before it calls
        /// [`task::exit`]; read by [`WritebackHandle::join`] to know
        /// when the task has actually left the scheduler.
        pub(super) done: AtomicBool,
        /// Waitqueue the daemon parks on between sweeps. `join`
        /// notifies this queue after setting `stop` so the daemon
        /// wakes promptly.
        pub(super) sleep_wq: WaitQueue,
        /// Waitqueue `join` parks on until the daemon publishes
        /// `done`.
        pub(super) done_wq: WaitQueue,
        /// Task id of the spawned daemon. Written by the daemon on
        /// its first run (so diagnostic logs can correlate "mount X"
        /// with "task Y"). Reads are best-effort — the join path
        /// doesn't depend on this value.
        pub(super) task_id: AtomicUsize,
        /// Monotonic counter of completed sweeps. Bumped once per
        /// loop iteration after `sync_fs` returns (error or
        /// success — a failed sync still counts as "the daemon
        /// attempted a sweep"). Exposed via
        /// [`WritebackHandle::sweeps`] so integration tests can
        /// wait for at least one sweep to land before asserting
        /// post-conditions.
        sweeps: core::sync::atomic::AtomicU64,
    }

    /// RAII handle returned by [`start`]. The owner (typically the
    /// concrete `SuperOps::unmount` implementation for a
    /// block-backed FS) calls [`WritebackHandle::join`] before
    /// returning from its `unmount` path so the daemon is guaranteed
    /// not to touch the superblock after `unmount` completes.
    ///
    /// Dropping a handle without calling `join` is a leak, not a
    /// use-after-free: the daemon holds its own `Arc<SuperBlock>`
    /// and will keep running (and keep the SB alive) until it next
    /// notices `draining`. The debug-build `Drop` impl logs a warning
    /// so accidental leaks show up in CI.
    pub struct WritebackHandle {
        state: Arc<WritebackState>,
    }

    impl WritebackHandle {
        /// Ask the daemon to stop and wait for it to leave the
        /// scheduler.
        ///
        /// Idempotent: calling `join` twice is harmless (the second
        /// call observes `done = true` immediately and returns
        /// without parking).
        ///
        /// Called from `SuperOps::unmount` in Phase B (after
        /// `MountTable::unmount` has already set
        /// `sb.draining = true`). That flag alone is enough to make
        /// the daemon exit on its next wake, but `join` shortcuts
        /// the wait by setting `stop` and nudging the sleep
        /// waitqueue so the daemon doesn't have to serve out the
        /// rest of its current interval.
        pub fn join(&self) {
            self.state.stop.store(true, Ordering::SeqCst);
            // Wake the daemon if it's parked on its sleep waitqueue.
            // (If it's currently between sleep and sync_fs, the
            // next loop-top check of `stop` catches it.)
            self.state.sleep_wq.notify_all();
            // Park until the daemon sets `done = true` right before
            // `task::exit`. `wait_while` handles the lost-wakeup
            // race — see `WaitQueue::wait_while` docs.
            self.state
                .done_wq
                .wait_while(|| !self.state.done.load(Ordering::SeqCst));
        }

        /// Task id of the spawned daemon, if the daemon has begun
        /// executing. Diagnostic only; returns `0` before the
        /// daemon's first instruction (i.e. between `task::spawn`
        /// and the entry function's first load).
        pub fn task_id(&self) -> usize {
            self.state.task_id.load(Ordering::Relaxed)
        }

        /// Number of sweeps the daemon has completed. Exposed so
        /// integration tests can spin until they observe at least
        /// one successful writeback without having to inspect the
        /// block cache's dirty set directly. Reads the
        /// `WritebackState`'s internal counter that
        /// [`writeback_loop`] bumps after each `sync_fs` call
        /// (regardless of whether the call errored — the daemon
        /// treats errors as "retry next sweep" per the
        /// `sync_fs` contract).
        pub fn sweeps(&self) -> u64 {
            self.state.sweeps.load(Ordering::Relaxed)
        }
    }

    impl Drop for WritebackHandle {
        fn drop(&mut self) {
            if !self.state.done.load(Ordering::Relaxed) {
                debug_assert!(
                    false,
                    "WritebackHandle dropped without join(): daemon task id {} may outlive the handle. \
                     Call handle.join() from SuperOps::unmount before detaching.",
                    self.state.task_id.load(Ordering::Relaxed),
                );
            }
        }
    }

    /// Spawn a per-mount writeback daemon. Returns `None` if the
    /// mount is read-only or the configured cadence disables
    /// writeback (`writeback_secs=0` on the cmdline).
    pub fn start(
        sb: Arc<SuperBlock>,
        cache: Arc<BlockCache>,
        device_id: DeviceId,
    ) -> Option<WritebackHandle> {
        if sb.flags.contains(SbFlags::RDONLY) {
            return None;
        }
        let secs = configured_secs();
        if secs == 0 || secs == DISABLE_SENTINEL || is_disabled() {
            return None;
        }

        let state = Arc::new(WritebackState {
            sb,
            cache,
            device_id,
            interval_secs: secs,
            stop: AtomicBool::new(false),
            done: AtomicBool::new(false),
            sleep_wq: WaitQueue::new(),
            done_wq: WaitQueue::new(),
            task_id: AtomicUsize::new(0),
            sweeps: core::sync::atomic::AtomicU64::new(0),
        });

        SPAWN_QUEUE.lock().push_back(Arc::clone(&state));
        task::spawn(writeback_entry);

        Some(WritebackHandle { state })
    }

    impl WritebackState {
        fn bump_sweeps(&self) {
            self.sweeps.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn writeback_entry() -> ! {
        let state = {
            let mut q = SPAWN_QUEUE.lock();
            q.pop_front().expect(
                "writeback_entry: spawn queue empty — writeback_entry must only be \
                 reached through writeback::start",
            )
        };

        state.task_id.store(task::current_id(), Ordering::Relaxed);

        writeback_loop(&state);

        // Publish `done` before waking joiners so `done_wq.wait_while`'s
        // condition (`!done`) evaluates to `false` on the joiner's
        // re-check. Release pairs with the joiner's Acquire load on
        // re-check via the SeqCst store inside `notify_all`.
        state.done.store(true, Ordering::SeqCst);
        state.done_wq.notify_all();

        drop(state);

        task::exit();
    }

    fn writeback_loop(state: &Arc<WritebackState>) {
        let interval_ms = state.interval_secs.saturating_mul(1000);
        loop {
            if state.stop.load(Ordering::SeqCst) {
                return;
            }

            park_ms_interruptible(state, interval_ms);

            if state.stop.load(Ordering::SeqCst) {
                return;
            }

            let guard = match SbActiveGuard::try_acquire(&state.sb) {
                Ok(g) => g,
                Err(_) => {
                    // Superblock is draining. Exit cleanly; unmount's
                    // explicit `sync_fs` will pick up any buffers we
                    // haven't flushed yet.
                    return;
                }
            };

            if let Err(e) = state.cache.sync_fs(state.device_id) {
                crate::serial_println!(
                    "writeback: sync_fs failed on fs_id={} device={:?}: {:?}",
                    state.sb.fs_id.0,
                    state.device_id,
                    e,
                );
            }

            // RFC 0007 §MAP_SHARED writeback (issue #755): after the
            // buffer-cache flush, walk every superblock-mounted inode's
            // `mapping` and call `writepage` on each dirty `pgoff`.
            // Snapshot-then-writepage discipline: dirty pgoffs are
            // collected under `cache.inner.lock()` (via
            // [`PageCache::snapshot_dirty`]), the lock is dropped, and
            // then `writepage` runs against the snapshot.
            //
            // Skip-on-shutdown: re-check `sb.draining` between inodes
            // so a `sys_umount` racing the sweep observes a prompt
            // exit rather than serving the entire inode list. The bare
            // hook here is what the issue calls for; #760 will harden
            // the predicate (e.g. by promoting the check into a real
            // `SbActiveGuard::is_draining` query path).
            sweep_inode_mappings(state);

            state.bump_sweeps();
            drop(guard);
        }
    }

    /// Page-cache walk half of one writeback sweep. Iterates every
    /// inode the superblock's [`SuperOps::for_each_mapped_inode`] hook
    /// surfaces, snapshots each inode's dirty pgoff set under the
    /// page-cache mutex, and runs `writepage` on the snapshot with the
    /// mutex dropped. Errors are logged and the dirty bit is left set
    /// so the next sweep retries — matches the buffer-cache `sync_fs`
    /// best-effort contract (RFC 0004 §Buffer cache, normative invariant
    /// #4: a flush failure does not lose enrolment).
    ///
    /// `feature = "page_cache"` gates the body so a kernel built without
    /// the page-cache wave-2 surface still compiles cleanly. With the
    /// feature off, the function is an empty no-op — the buffer-cache
    /// flush above is the daemon's only effect, which is the
    /// pre-#755 behaviour.
    #[cfg(feature = "page_cache")]
    fn sweep_inode_mappings(state: &Arc<WritebackState>) {
        use crate::mem::page_cache::{CachePage, PG_DIRTY};
        use crate::mem::paging;
        use alloc::vec::Vec;
        use core::sync::atomic::Ordering;

        // Collect inodes-with-mappings into a `Vec` so the walk runs
        // outside whatever lock the FS driver's registry uses to back
        // `for_each_mapped_inode`. RFC 0007 §Lock-order ladder forbids
        // calling `writepage` while holding any spinlock; the
        // collected `Arc<Inode>`s are independent strong refs that we
        // can iterate freely.
        let mut inodes: Vec<Arc<crate::fs::vfs::Inode>> = Vec::new();
        state.sb.ops.for_each_mapped_inode(&mut |inode| {
            inodes.push(Arc::clone(inode));
        });

        for inode in inodes {
            // Skip-on-shutdown: bail out promptly if `sys_umount` set
            // `sb.draining` between snapshots. Issue #760 hardens this
            // predicate further; the bare check here is sufficient
            // for the per-sweep correctness contract.
            if state.sb.draining.load(Ordering::SeqCst) {
                return;
            }
            if state.stop.load(Ordering::SeqCst) {
                return;
            }

            // Acquire the per-inode mapping read-side. `mapping` is
            // the install-once slot; if it's `None` the inode never
            // participated in the page cache and there is nothing to
            // sweep.
            let pc = match inode.mapping.read().as_ref() {
                Some(pc) => Arc::clone(pc),
                None => continue,
            };

            // Snapshot under `cache.inner`. Returned vector clones the
            // per-pgoff `Arc<CachePage>` strong refs so the walk that
            // follows does not alias the BTreeMap behind the mutex.
            let snapshot: Vec<(u64, Arc<CachePage>)> = pc.snapshot_dirty();
            if snapshot.is_empty() {
                continue;
            }

            let ops = pc.ops();
            for (pgoff, page) in snapshot {
                // Re-check shutdown between pages too — a many-page
                // dirty inode is the worst-case wait an unmount might
                // see if we only re-checked between inodes.
                if state.sb.draining.load(Ordering::SeqCst) || state.stop.load(Ordering::SeqCst) {
                    return;
                }

                // Mark `PG_WRITEBACK` so a concurrent
                // `mark_page_dirty` keeps the page on the dirty index
                // (RFC 0007 §MAP_SHARED writeback). The bit is cleared
                // unconditionally after `writepage` returns — error or
                // success — via [`CachePage::end_writeback`].
                page.begin_writeback();

                // Copy the cached page bytes out of the HHDM-mapped
                // backing frame into a stack-resident `[u8; 4096]`.
                // The trait method takes a fixed-shape buffer (RFC
                // 0007 §AddressSpaceOps page-buffer shape); the copy
                // is what lets writepage run against an immutable
                // snapshot while the page is logically released for
                // concurrent writers.
                let mut buf = [0u8; 4096];
                // SAFETY: `page.phys` is a 4 KiB-aligned physical
                // frame address held alive by `page` (which we own a
                // strong Arc to). Limine's HHDM linearly maps every
                // physical frame as RW kernel memory; the read is
                // bounded to the 4 KiB frame and the source pointer
                // stays valid for the duration of the copy because
                // `page`'s drop runs after this scope.
                unsafe {
                    let hhdm = paging::hhdm_offset();
                    let src = (hhdm.as_u64() + page.phys) as *const u8;
                    core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), 4096);
                }

                match ops.writepage(pgoff, &buf) {
                    Ok(()) => {
                        // Successful flush: clear the per-page
                        // `PG_DIRTY` bit and remove the pgoff from the
                        // mapping's dirty index. `clear_page_dirty`
                        // does both atomically under `cache.inner`.
                        pc.clear_page_dirty(pgoff);
                    }
                    Err(errno) => {
                        // Errseq-style sticky-EIO: bump the wb_err
                        // counter (consumed by `OpenFile::fsync`).
                        // The dirty bit is *left set* so the next
                        // sweep retries — matches RFC 0007 §writepage
                        // failure semantics. Per-page state.fetch_or
                        // is unnecessary because `mark_page_dirty`'s
                        // invariant already keeps the bit set.
                        pc.bump_wb_err();
                        // Defence-in-depth: explicitly preserve
                        // `PG_DIRTY` in case some racy clearer cleared
                        // it during the unlocked copy/writepage
                        // window.
                        page.state.fetch_or(PG_DIRTY, Ordering::Release);
                        crate::serial_println!(
                            "writeback: writepage(fs_id={} ino={} pgoff={}) failed: {}",
                            state.sb.fs_id.0,
                            inode.ino,
                            pgoff,
                            errno,
                        );
                    }
                }

                // Conclude writeback. `end_writeback` clears
                // `PG_WRITEBACK` with `Release` and notifies any
                // truncate parked on the page's waitqueue.
                page.end_writeback();
            }
        }
    }

    /// Compile-out stub when `feature = "page_cache"` is off — the
    /// daemon's pre-#755 buffer-cache-only behaviour.
    #[cfg(not(feature = "page_cache"))]
    fn sweep_inode_mappings(_state: &Arc<WritebackState>) {}

    /// Park the current task for up to `ms` milliseconds, returning
    /// early if `state.stop` is set and the daemon's sleep waitqueue
    /// is notified. Uses [`task::enqueue_wakeup`] for the deadline
    /// side and the waitqueue's `wait_while` for the early-wake
    /// side; the two compose because `stop` is set *before*
    /// `sleep_wq.notify_all`, so the condition on re-check is
    /// always `false` when a notify wakes us.
    fn park_ms_interruptible(state: &Arc<WritebackState>, ms: u64) {
        if state.stop.load(Ordering::SeqCst) {
            return;
        }
        // Routed through the scheduler/IRQ seam (RFC 0005) so the
        // simulator and mock tests can drive the writeback daemon's
        // sleep deterministically. Production resolves to `HwClock`
        // over `crate::time::*` — semantically identical.
        use crate::task::env;
        use crate::time::TICK_MS;
        let (clock, _irq) = env::env();
        let ticks_to_wait = ms.div_ceil(TICK_MS).max(1);
        let deadline = clock.now().saturating_add(ticks_to_wait);
        clock.enqueue_wakeup(deadline, task::current_id());

        state.sleep_wq.wait_while(|| {
            if state.stop.load(Ordering::SeqCst) {
                return false;
            }
            clock.now() < deadline
        });
    }
}

#[cfg(target_os = "none")]
pub use daemon::{start, WritebackHandle};

#[cfg(test)]
mod tests {
    use super::*;
    use spin::Mutex;

    /// Serialise tests that mutate [`CONFIGURED_SECS`]. libtest runs
    /// `#[test]`s in parallel by default, so without this lock two
    /// parsing tests would race on the shared atomic.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn parse_cmdline_sets_override() {
        let _g = TEST_LOCK.lock();
        reset_configured_for_tests();
        assert!(parse_cmdline(b"writeback_secs=7 other_opt=1"));
        assert_eq!(configured_secs(), 7);
    }

    #[test]
    fn parse_cmdline_zero_disables() {
        let _g = TEST_LOCK.lock();
        reset_configured_for_tests();
        assert!(parse_cmdline(b"writeback_secs=0"));
        assert!(is_disabled());
    }

    #[test]
    fn parse_cmdline_missing_returns_default() {
        let _g = TEST_LOCK.lock();
        reset_configured_for_tests();
        assert!(!parse_cmdline(b"some_other_flag=9"));
        assert_eq!(configured_secs(), DEFAULT_INTERVAL_SECS);
    }

    #[test]
    fn parse_cmdline_garbage_value_ignored() {
        let _g = TEST_LOCK.lock();
        reset_configured_for_tests();
        assert!(!parse_cmdline(b"writeback_secs=abc"));
        assert_eq!(configured_secs(), DEFAULT_INTERVAL_SECS);
    }

    #[test]
    fn parse_cmdline_last_wins() {
        let _g = TEST_LOCK.lock();
        reset_configured_for_tests();
        assert!(parse_cmdline(b"writeback_secs=3 writeback_secs=9"));
        assert_eq!(configured_secs(), 9);
    }

    #[test]
    fn parse_cmdline_handles_tabs_and_newlines() {
        let _g = TEST_LOCK.lock();
        reset_configured_for_tests();
        assert!(parse_cmdline(b"\twriteback_secs=11\n"));
        assert_eq!(configured_secs(), 11);
    }

    #[test]
    fn configured_secs_default_before_any_override() {
        let _g = TEST_LOCK.lock();
        reset_configured_for_tests();
        assert_eq!(configured_secs(), DEFAULT_INTERVAL_SECS);
    }

    #[test]
    fn disable_sentinel_reports_disabled() {
        let _g = TEST_LOCK.lock();
        reset_configured_for_tests();
        set_configured_secs(DISABLE_SENTINEL);
        assert!(is_disabled());
    }
}
