//! Bounded single-producer / single-consumer blocking channel.
//!
//! Why SPSC alongside [`super::mpmc`]: the endpoint-unique shape
//! covers the common "producer task hands work to a worker task"
//! pattern without paying for the MPMC counters on every clone/drop.
//! `Sender` and `Receiver` are intentionally `!Clone` here — callers
//! who need fan-in / fan-out reach for `mpmc` instead.
//!
//! Capacity is fixed at construction. `send` / `recv` park via
//! [`WaitQueue`] when the queue is full / empty; `try_send` /
//! `try_recv` never park.
//!
//! ## Close semantics
//!
//! Dropping the [`Sender`] wakes any parked [`Receiver`]; once the
//! buffered queue is drained, `recv` returns `None`. Symmetric when
//! the [`Receiver`] is dropped: the parked `Sender`'s `send` returns
//! `Err(val)` so the caller can recover the value.
//!
//! Because each side has exactly one endpoint, close state is two
//! `AtomicBool`s (`sender_closed`, `receiver_closed`) rather than the
//! reference counts `mpmc` needs.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
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
    /// Set in `Drop for Sender`. Observed by a parked / about-to-park
    /// receiver to distinguish "queue happens to be empty" from
    /// "no more data will ever arrive".
    sender_closed: AtomicBool,
    /// Set in `Drop for Receiver`. Observed by the sender to return
    /// `Err(val)` instead of blocking forever on a full queue.
    receiver_closed: AtomicBool,
}

/// Producer half of an SPSC channel.
pub struct Sender<T> {
    shared: Arc<Shared<T>>,
}

/// Consumer half of an SPSC channel.
pub struct Receiver<T> {
    shared: Arc<Shared<T>>,
}

/// Error returned by [`Sender::try_send`] when the push did not land.
#[derive(Debug)]
pub enum TrySendError<T> {
    /// Queue is at capacity right now.
    Full(T),
    /// [`Receiver`] has been dropped; the channel is closed.
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

/// Error returned by [`Receiver::try_recv`] when no value was popped.
#[derive(Debug, PartialEq, Eq)]
pub enum TryRecvError {
    /// Queue is empty but the channel is still open.
    Empty,
    /// [`Sender`] has been dropped and the queue is drained.
    Closed,
}

/// Create an SPSC channel with room for `capacity` unreceived items.
///
/// # Panics
///
/// Panics if `capacity == 0`; a zero-capacity rendezvous channel is a
/// separate (and substantially more complex) shape.
pub fn channel<T>(capacity: usize) -> (Sender<T>, Receiver<T>) {
    assert!(capacity > 0, "spsc::channel capacity must be > 0");
    let shared = Arc::new(Shared {
        buf: Mutex::new(Inner {
            queue: VecDeque::with_capacity(capacity),
            capacity,
        }),
        not_full: WaitQueue::new(),
        not_empty: WaitQueue::new(),
        sender_closed: AtomicBool::new(false),
        receiver_closed: AtomicBool::new(false),
    });
    (
        Sender {
            shared: shared.clone(),
        },
        Receiver { shared },
    )
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        // Release so the receiver, when it loads `sender_closed` with
        // Acquire, also sees whatever was pushed before we dropped.
        self.shared.sender_closed.store(true, Ordering::Release);
        // Wake any parked receiver so it can drain the queue and then
        // observe closed.
        self.shared.not_empty.notify_all();
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        self.shared.receiver_closed.store(true, Ordering::Release);
        // Wake the parked sender (if any) so `send` returns `Err`.
        self.shared.not_full.notify_all();
    }
}

impl<T> Sender<T> {
    /// Send `val`, parking until the channel has space or the
    /// [`Receiver`] has been dropped.
    ///
    /// Returns `Ok(())` on successful enqueue, `Err(val)` if the
    /// channel is closed (receiver side dropped). The value is
    /// returned so callers can recover it.
    pub fn send(&self, val: T) -> Result<(), T> {
        let mut slot = Some(val);
        loop {
            // The closed-check + push MUST happen under one `buf`
            // lock acquisition — symmetric to the recv-side drain
            // check. Otherwise: sender loads `receiver_closed =
            // false`, receiver drops (setting the flag), sender
            // acquires buf, pushes, returns Ok with the item
            // stranded (no live receiver will ever pop it).
            {
                let mut inner = self.shared.buf.lock();
                if self.shared.receiver_closed.load(Ordering::Acquire) {
                    return Err(slot.take().expect("send slot populated"));
                }
                if inner.queue.len() < inner.capacity {
                    inner
                        .queue
                        .push_back(slot.take().expect("send slot populated"));
                    drop(inner);
                    self.shared.not_empty.notify_one();
                    return Ok(());
                }
            }
            // Full: park until the receiver pops or drops. Re-check
            // both predicates under the waitqueue lock so a close
            // that fires between check and park is caught here (or
            // via `wake_pending`; see waitqueue module docs).
            self.shared.not_full.wait_while(|| {
                if self.shared.receiver_closed.load(Ordering::Acquire) {
                    return false;
                }
                let inner = self.shared.buf.lock();
                inner.queue.len() >= inner.capacity
            });
        }
    }

    /// Number of receivers currently parked in `recv` waiting for an
    /// item. Test-only inspection point — lets a driver confirm the
    /// peer has actually reached its park before firing a wake. Not
    /// for production logic; the count can change the instant it's
    /// read.
    pub fn receivers_parked(&self) -> usize {
        self.shared.not_empty.waiter_count()
    }

    /// Non-blocking send. Returns [`TrySendError::Full`] when the
    /// queue is at capacity and [`TrySendError::Closed`] when the
    /// receiver has been dropped.
    pub fn try_send(&self, val: T) -> Result<(), TrySendError<T>> {
        let mut inner = self.shared.buf.lock();
        // Closed-check under the buf lock (see `send` for the race).
        if self.shared.receiver_closed.load(Ordering::Acquire) {
            return Err(TrySendError::Closed(val));
        }
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
    /// Receive one item, parking until one is available or the
    /// [`Sender`] is dropped and the queue is drained. Returns
    /// `None` only when the channel is closed *and* empty.
    pub fn recv(&self) -> Option<T> {
        loop {
            // Drain-first: buffered items beat close detection so a
            // receiver whose sender exited mid-stream still gets
            // everything that was in flight.
            //
            // The closed check MUST happen under the same `buf` lock
            // as the pop attempt. Otherwise a sender could push +
            // drop between our unlock and the `sender_closed` load:
            // its `notify_one` would fire into an empty waitqueue
            // (we're not parked yet), we'd then see `sender_closed`
            // and return None, stranding the item in the queue.
            {
                let mut inner = self.shared.buf.lock();
                if let Some(val) = inner.queue.pop_front() {
                    drop(inner);
                    self.shared.not_full.notify_one();
                    return Some(val);
                }
                if self.shared.sender_closed.load(Ordering::Acquire) {
                    return None;
                }
            }
            self.shared.not_empty.wait_while(|| {
                if self.shared.sender_closed.load(Ordering::Acquire) {
                    return false;
                }
                let inner = self.shared.buf.lock();
                inner.queue.is_empty()
            });
        }
    }

    /// Number of senders currently parked in `send` waiting for space.
    /// Test-only inspection point; see [`Sender::receivers_parked`] for
    /// rationale and caveats.
    pub fn senders_parked(&self) -> usize {
        self.shared.not_full.waiter_count()
    }

    /// Non-blocking recv. Returns [`TryRecvError::Empty`] when the
    /// queue is empty but the sender is still live, and
    /// [`TryRecvError::Closed`] when the queue is drained *and* the
    /// sender has been dropped.
    pub fn try_recv(&self) -> Result<T, TryRecvError> {
        let mut inner = self.shared.buf.lock();
        if let Some(val) = inner.queue.pop_front() {
            drop(inner);
            self.shared.not_full.notify_one();
            Ok(val)
        } else if self.shared.sender_closed.load(Ordering::Acquire) {
            Err(TryRecvError::Closed)
        } else {
            Err(TryRecvError::Empty)
        }
    }
}
