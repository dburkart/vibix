//! Keyboard input path: an interrupt-safe scancode ring fed by the
//! keyboard ISR and drained on the consumer side, plus a `pc-keyboard`
//! state machine that turns scancodes into `DecodedKey`s.
//!
//! The `RingBuffer` primitive is generic and kept free of kernel-only
//! dependencies so it's host-unit-testable.

use core::mem::MaybeUninit;

pub struct RingBuffer<T, const N: usize> {
    buf: [MaybeUninit<T>; N],
    head: usize,
    tail: usize,
    len: usize,
}

impl<T: Copy, const N: usize> RingBuffer<T, N> {
    pub const fn new() -> Self {
        Self {
            buf: [MaybeUninit::uninit(); N],
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    /// Push `v`. Returns `false` and drops the value if the ring is full.
    pub fn push(&mut self, v: T) -> bool {
        if self.len == N {
            return false;
        }
        self.buf[self.tail] = MaybeUninit::new(v);
        self.tail = (self.tail + 1) % N;
        self.len += 1;
        true
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let v = unsafe { self.buf[self.head].assume_init() };
        self.head = (self.head + 1) % N;
        self.len -= 1;
        Some(v)
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

impl<T: Copy, const N: usize> Default for RingBuffer<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "none")]
pub use kernel_side::*;

#[cfg(target_os = "none")]
mod kernel_side {
    use super::RingBuffer;
    use pc_keyboard::{layouts::Us104Key, DecodedKey, HandleControl, Keyboard, ScancodeSet1};
    use spin::{Lazy, Mutex};
    use x86_64::instructions::interrupts::without_interrupts;

    /// Scancodes land here from the keyboard ISR. Sized at 128: a human
    /// typist can't overflow it, and firmware key-repeat bursts are well
    /// under that between consumer polls.
    static SCANCODES: Mutex<RingBuffer<u8, 128>> = Mutex::new(RingBuffer::new());

    static KEYBOARD: Lazy<Mutex<Keyboard<Us104Key, ScancodeSet1>>> = Lazy::new(|| {
        Mutex::new(Keyboard::new(
            ScancodeSet1::new(),
            Us104Key,
            HandleControl::Ignore,
        ))
    });

    /// Called from the keyboard ISR. Interrupts are already disabled.
    pub fn push_scancode_from_isr(code: u8) {
        SCANCODES.lock().push(code);
    }

    pub fn try_read_scancode() -> Option<u8> {
        without_interrupts(|| SCANCODES.lock().pop())
    }

    /// Block (via `hlt`) until a decoded key is available.
    pub fn read_key() -> DecodedKey {
        loop {
            while let Some(code) = try_read_scancode() {
                let mut kbd = KEYBOARD.lock();
                if let Ok(Some(event)) = kbd.add_byte(code) {
                    if let Some(key) = kbd.process_keyevent(event) {
                        return key;
                    }
                }
            }
            x86_64::instructions::interrupts::enable_and_hlt();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_pop_fifo_order() {
        let mut r: RingBuffer<u8, 4> = RingBuffer::new();
        assert!(r.push(1));
        assert!(r.push(2));
        assert!(r.push(3));
        assert_eq!(r.pop(), Some(1));
        assert_eq!(r.pop(), Some(2));
        assert_eq!(r.pop(), Some(3));
        assert_eq!(r.pop(), None);
    }

    #[test]
    fn pop_on_empty_returns_none() {
        let mut r: RingBuffer<u8, 4> = RingBuffer::new();
        assert_eq!(r.pop(), None);
        assert!(r.is_empty());
    }

    #[test]
    fn overflow_drops_new_value_and_preserves_old() {
        let mut r: RingBuffer<u8, 2> = RingBuffer::new();
        assert!(r.push(1));
        assert!(r.push(2));
        assert!(!r.push(3)); // dropped
        assert_eq!(r.pop(), Some(1));
        assert_eq!(r.pop(), Some(2));
        assert_eq!(r.pop(), None);
    }

    #[test]
    fn wraps_around() {
        let mut r: RingBuffer<u8, 3> = RingBuffer::new();
        r.push(1);
        r.push(2);
        assert_eq!(r.pop(), Some(1));
        r.push(3);
        r.push(4); // wraps tail to 1
        assert_eq!(r.pop(), Some(2));
        assert_eq!(r.pop(), Some(3));
        assert_eq!(r.pop(), Some(4));
        assert_eq!(r.pop(), None);
    }

    #[test]
    fn len_tracks_occupancy() {
        let mut r: RingBuffer<u8, 4> = RingBuffer::new();
        assert_eq!(r.len(), 0);
        r.push(1);
        r.push(2);
        assert_eq!(r.len(), 2);
        r.pop();
        assert_eq!(r.len(), 1);
    }
}
