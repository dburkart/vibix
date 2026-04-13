//! Bounded multi-producer / multi-consumer blocking channel.
//!
//! Same bounded-queue shape as [`super::spsc`], but both endpoints
//! are [`Clone`] so any number of producer / consumer tasks can share
//! the channel. Internals are a [`spin::Mutex`]-protected [`VecDeque`]
//! plus the same two wait queues (`not_full`, `not_empty`); the
//! additional complexity over SPSC is endpoint-count bookkeeping for
//! the close / hang-up protocol.
//!
//! ## Close semantics
//!
//! When the last [`Sender`] is dropped the channel becomes *closed to
//! sends*. Any parked [`Receiver`] wakes, drains whatever is buffered,
//! then observes `None` from [`Receiver::recv`]. Symmetric when the
//! last [`Receiver`] is dropped: any parked [`Sender`] wakes and sees
//! [`Err`] from [`Sender::send`], the inner value returned to the
//! caller.
//!
//! Endpoint counts are tracked explicitly (`sender_count`,
//! `receiver_count`: `AtomicUsize`) rather than inferred from
//! [`Arc::strong_count`]. Both endpoints share a single `Arc`, so the
//! strong count can't distinguish "last sender" from "last receiver".
//!
//! ## Lock order
//!
//! Same as `super`: `WaitQueue.inner` → `buf` lock → `SCHED`. Endpoint
//! counts are atomics and take no lock at all.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

use super::WaitQueue;

struct Inner<T> {
    queue: VecDeque<T>,
    capacity: usize,
}

struct Shared<T> {
    buf: Mutex<Inner<T>>,
    not_full: WaitQueue,
    not_empty: WaitQueue,
    /// Number of live [`Sender`] handles. When this transitions to 0,
    /// the channel is closed to sends and any parked receivers are
    /// woken so they can observe `None`.
    sender_count: AtomicUsize,
    /// Number of live [`Receiver`] handles. When this transitions to
    /// 0, parked senders wake and their `send` calls return `Err`.
    receiver_count: AtomicUsize,
}

/// Producer half of an MPMC channel. [`Clone`]able; each clone counts
/// as one live sender for close-detection purposes.
pub struct Sender<T> {
    shared: Arc<Shared<T>>,
}

/// Consumer half of an MPMC channel. [`Clone`]able; each clone counts
/// as one live receiver.
pub struct Receiver<T> {
    shared: Arc<Shared<T>>,
}

/// Error type for [`Sender::try_send`]. Distinguishes the two
/// non-success cases because callers typically want different
/// behaviour: `Full` may retry later, `Closed` should abandon.
#[derive(Debug)]
pub enum TrySendError<T> {
    /// Channel is at capacity right now.
    Full(T),
    /// Every [`Receiver`] has been dropped; further sends are
    /// impossible.
    Closed(T),
}

impl<T> TrySendError<T> {
    /// Consume the error and return the value that could not be sent.
    pub fn into_inner(self) -> T {
        match self {
            TrySendError::Full(v) | TrySendError::Closed(v) => v,
        }
    }
}

/// Error type for [`Receiver::try_recv`].
#[derive(Debug, PartialEq, Eq)]
pub enum TryRecvError {
    /// Queue is empty but the channel is still open.
    Empty,
    /// Every [`Sender`] has been dropped and the queue is drained.
    Closed,
}

/// Create an MPMC channel with room for `capacity` unreceived items.
///
/// # Panics
///
/// Panics if `capacity == 0`; zero-capacity rendezvous channels are
/// a separate (substantially more involved) shape and not supported
/// here.
pub fn channel<T>(capacity: usize) -> (Sender<T>, Receiver<T>) {
    assert!(capacity > 0, "mpmc::channel capacity must be > 0");
    let shared = Arc::new(Shared {
        buf: Mutex::new(Inner {
            queue: VecDeque::with_capacity(capacity),
            capacity,
        }),
        not_full: WaitQueue::new(),
        not_empty: WaitQueue::new(),
        sender_count: AtomicUsize::new(1),
        receiver_count: AtomicUsize::new(1),
    });
    (
        Sender {
            shared: shared.clone(),
        },
        Receiver { shared },
    )
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        // Bump before handing out the new handle. The existing `self`
        // already counts for >= 1, so the count is strictly positive
        // throughout — no 0 → 1 race with a concurrent `drop` of the
        // "last" sender (there isn't one while `self` lives).
        self.shared.sender_count.fetch_add(1, Ordering::Relaxed);
        Self {
            shared: self.shared.clone(),
        }
    }
}

impl<T> Clone for Receiver<T> {
    fn clone(&self) -> Self {
        self.shared.receiver_count.fetch_add(1, Ordering::Relaxed);
        Self {
            shared: self.shared.clone(),
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        // AcqRel: any queue writes published under `buf` before this
        // drop must be visible to a receiver that wakes on the
        // close-notify below and loads `sender_count` with Acquire.
        let prev = self.shared.sender_count.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 {
            // Last sender gone: wake every parked receiver so it can
            // drain whatever is buffered and then observe the closed
            // state.
            self.shared.not_empty.notify_all();
        }
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let prev = self.shared.receiver_count.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 {
            // Last receiver gone: wake every parked sender so each
            // can return `Err(val)`.
            self.shared.not_full.notify_all();
        }
    }
}

impl<T> Sender<T> {
    /// Send `val`, parking until the channel has space or every
    /// [`Receiver`] has been dropped.
    ///
    /// Returns `Ok(())` on successful enqueue, `Err(val)` if the
    /// channel is closed. A closed-detection that fires while parked
    /// still returns `Err(val)` — the value is never dropped on the
    /// floor.
    pub fn send(&self, val: T) -> Result<(), T> {
        let mut slot = Some(val);
        loop {
            // Fast path: check closed, then try to push.
            if self.shared.receiver_count.load(Ordering::Acquire) == 0 {
                return Err(slot.take().expect("send slot populated"));
            }
            {
                let mut inner = self.shared.buf.lock();
                if inner.queue.len() < inner.capacity {
                    inner
                        .queue
                        .push_back(slot.take().expect("send slot populated"));
                    drop(inner);
                    self.shared.not_empty.notify_one();
                    return Ok(());
                }
            }
            // Slow path: park until space or close. The cond re-reads
            // closed under the waitqueue lock so a close that fires
            // between our check and the park is caught by either the
            // cond or the `wake_pending` flag (see waitqueue module
            // docs).
            self.shared.not_full.wait_while(|| {
                if self.shared.receiver_count.load(Ordering::Acquire) == 0 {
                    return false;
                }
                let inner = self.shared.buf.lock();
                inner.queue.len() >= inner.capacity
            });
        }
    }

    /// Non-blocking send. Returns a [`TrySendError`] that
    /// distinguishes "full right now" from "channel closed".
    pub fn try_send(&self, val: T) -> Result<(), TrySendError<T>> {
        if self.shared.receiver_count.load(Ordering::Acquire) == 0 {
            return Err(TrySendError::Closed(val));
        }
        let mut inner = self.shared.buf.lock();
        if inner.queue.len() < inner.capacity {
            inner.queue.push_back(val);
            drop(inner);
            self.shared.not_empty.notify_one();
            Ok(())
        } else {
            Err(TrySendError::Full(val))
        }
    }
}

impl<T> Receiver<T> {
    /// Receive one item, parking until one is available. Returns
    /// `None` once every [`Sender`] has been dropped *and* the
    /// internal queue has been drained.
    pub fn recv(&self) -> Option<T> {
        loop {
            // Drain-first: buffered items win over close detection.
            // A receiver that had some in flight when the last
            // sender dropped must still get them.
            {
                let mut inner = self.shared.buf.lock();
                if let Some(val) = inner.queue.pop_front() {
                    drop(inner);
                    self.shared.not_full.notify_one();
                    return Some(val);
                }
            }
            if self.shared.sender_count.load(Ordering::Acquire) == 0 {
                return None;
            }
            // Park until a sender pushes or the last sender drops.
            self.shared.not_empty.wait_while(|| {
                if self.shared.sender_count.load(Ordering::Acquire) == 0 {
                    return false;
                }
                let inner = self.shared.buf.lock();
                inner.queue.is_empty()
            });
        }
    }

    /// Non-blocking recv. Returns [`TryRecvError::Empty`] if the
    /// queue has nothing right now, [`TryRecvError::Closed`] if the
    /// queue is drained *and* every sender is gone.
    pub fn try_recv(&self) -> Result<T, TryRecvError> {
        let mut inner = self.shared.buf.lock();
        if let Some(val) = inner.queue.pop_front() {
            drop(inner);
            self.shared.not_full.notify_one();
            Ok(val)
        } else if self.shared.sender_count.load(Ordering::Acquire) == 0 {
            Err(TryRecvError::Closed)
        } else {
            Err(TryRecvError::Empty)
        }
    }
}
