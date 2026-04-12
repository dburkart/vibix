//! Legacy 8259 PIC pair, remapped past the CPU exception vectors.
//!
//! Vectors 0x00–0x1F are reserved for CPU exceptions, so we remap the
//! master PIC to 0x20–0x27 and the slave to 0x28–0x2F. `init()` must
//! run after the IDT is loaded so we don't take an IRQ into a stale
//! handler; callers still gate `sti` until they're ready.

use pic8259::ChainedPics;
use spin::Mutex;

pub const PIC_1_OFFSET: u8 = 0x20;
pub const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

pub static PICS: Mutex<ChainedPics> =
    Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });

pub fn init() {
    let mut pics = PICS.lock();
    unsafe {
        pics.initialize();
        // Unmask IRQ0 (timer) and IRQ1 (keyboard); keep everything else
        // masked until we wire up a device for it.
        pics.write_masks(0b1111_1100, 0b1111_1111);
    }
    crate::serial_println!("PIC remapped to {:#x}/{:#x}", PIC_1_OFFSET, PIC_2_OFFSET);
}

/// Safely notify end-of-interrupt for a vector previously raised by the
/// PIC. Called from ISRs.
pub fn notify_eoi(vector: u8) {
    unsafe { PICS.lock().notify_end_of_interrupt(vector) };
}
