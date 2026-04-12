//! Legacy 8259 PIC pair — remapped and then fully disabled.
//!
//! The APIC (see `apic.rs`) drives interrupts on this kernel. We still
//! run through the 8259 init sequence once at boot so any leftover IRQ
//! lines raised by firmware land on our remapped (0x20+) vectors
//! rather than smashing into CPU exception vectors, then we mask every
//! line on both chips. EOI goes through the LAPIC now.

use pic8259::ChainedPics;
use spin::Mutex;

pub const PIC_1_OFFSET: u8 = 0x20;
pub const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

pub static PICS: Mutex<ChainedPics> =
    Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });

pub fn init_and_disable() {
    let mut pics = PICS.lock();
    unsafe {
        pics.initialize();
        // Mask every line — the IOAPIC routes IRQs now.
        pics.write_masks(0xFF, 0xFF);
    }
    crate::serial_println!("PIC remapped to {:#x}/{:#x} and masked", PIC_1_OFFSET, PIC_2_OFFSET);
}

/// End-of-interrupt. Forwarded to the LAPIC — the 8259 is fully masked
/// and never delivers here.
pub fn notify_eoi(_vector: u8) {
    super::apic::lapic_eoi();
}
