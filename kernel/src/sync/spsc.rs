//! Bounded single-producer / single-consumer blocking channel.
//!
//! Why SPSC first: the simpler shape that covers the typical
//! "producer task hands work to a worker task" pattern without the
//! extra synchronisation an MPMC channel needs. MPSC / MPMC variants
//! can be added as follow-ups once this has baked in-tree.
//!
//! Capacity is fixed at construction. `send` / `recv` park via
//! [`WaitQueue`] when the queue is full / empty; `try_send` /
//! `try_recv` never park.
//!
//! The `Sender` and `Receiver` each own one `Arc` handle to the shared
//! state; dropping all handles of one side does *not* currently signal
//! the other — a sender that finishes and drops its `Sender` will
//! leave the receiver waiting forever if the queue is empty. That's
//! fine for the primitives' in-kernel usage today (tasks don't exit
//! yet in M6) but is the natural follow-up shape for a channel-close
//! protocol.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
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
}

/// Producer half of an SPSC channel.
pub struct Sender<T> {
    shared: Arc<Shared<T>>,
}

/// Consumer half of an SPSC channel.
pub struct Receiver<T> {
    shared: Arc<Shared<T>>,
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
    });
    (
        Sender {
            shared: shared.clone(),
        },
        Receiver { shared },
    )
}

impl<T> Sender<T> {
    /// Send `val`, parking until the channel has space.
    pub fn send(&self, val: T) {
        // `Option` dance because we might loop (park + retry) before
        // the push actually lands, and a bare `val` would be
        // borrow-checked as moved-on-previous-iteration.
        let mut slot = Some(val);
        loop {
            {
                let mut inner = self.shared.buf.lock();
                if inner.queue.len() < inner.capacity {
                    inner
                        .queue
                        .push_back(slot.take().expect("send slot populated"));
                    drop(inner);
                    self.shared.not_empty.notify_one();
                    return;
                }
            }
            // Full: park until the receiver pops at least one item.
            // Re-check `len >= capacity` under the waitqueue lock via
            // `wait_while`; `recv` calls `not_full.notify_one()` only
            // after it has popped, so on wakeup the condition can
            // differ — the loop retries in that case.
            self.shared.not_full.wait_while(|| {
                let inner = self.shared.buf.lock();
                inner.queue.len() >= inner.capacity
            });
        }
    }

    /// Non-blocking send. Returns `Err(val)` if the channel is full.
    pub fn try_send(&self, val: T) -> Result<(), T> {
        let mut inner = self.shared.buf.lock();
        if inner.queue.len() < inner.capacity {
            inner.queue.push_back(val);
            drop(inner);
            self.shared.not_empty.notify_one();
            Ok(())
        } else {
            Err(val)
        }
    }
}

impl<T> Receiver<T> {
    /// Receive one item, parking until one is available.
    pub fn recv(&self) -> T {
        loop {
            {
                let mut inner = self.shared.buf.lock();
                if let Some(val) = inner.queue.pop_front() {
                    drop(inner);
                    self.shared.not_full.notify_one();
                    return val;
                }
            }
            // Empty: park until the sender pushes.
            self.shared.not_empty.wait_while(|| {
                let inner = self.shared.buf.lock();
                inner.queue.is_empty()
            });
        }
    }

    /// Non-blocking recv. Returns `None` if the channel is empty.
    pub fn try_recv(&self) -> Option<T> {
        let mut inner = self.shared.buf.lock();
        if let Some(val) = inner.queue.pop_front() {
            drop(inner);
            self.shared.not_full.notify_one();
            Some(val)
        } else {
            None
        }
    }
}
