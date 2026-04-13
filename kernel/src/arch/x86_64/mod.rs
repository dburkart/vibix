pub mod apic;
pub mod backtrace;
pub mod fpu;
pub mod gdt;
pub mod idt;
pub mod interrupts;
pub mod ist_guard;
pub mod pic;

/// Bring up arch-specific interrupt plumbing that doesn't depend on
/// the kernel mapper. Interrupts stay disabled throughout.
pub fn init() {
    // Feature detection first — everything below may query cpu::has().
    crate::cpu::init();
    // FPU init needs CR0/CR4 writes but no heap, so it fits here —
    // ahead of task::init() which spawns the first saving task.
    fpu::init();
    gdt::init();
    idt::init();
    // Remap + mask the 8259 before touching ACPI/APIC. Leaving it in
    // its reset state would fire legacy IRQs into CPU exception
    // vectors as soon as we `sti`.
    pic::init_and_disable();
}

/// Bring up ACPI + APIC. Must run after `mem::init` — the ACPI
/// parser and APIC drivers lean on the kernel mapper to map ACPI
/// tables (in BIOS/ACPI-reclaimable memory) and LAPIC/IOAPIC MMIO
/// regions into the HHDM window.
pub fn init_apic(rsdp_phys: usize, hhdm_offset: u64) {
    crate::acpi::init(rsdp_phys, hhdm_offset);
    apic::init_bsp(hhdm_offset);
    apic::ioapic_init(hhdm_offset);
    apic::route_legacy_irq(0, interrupts::InterruptIndex::Timer.as_u8());
    apic::route_legacy_irq(1, interrupts::InterruptIndex::Keyboard.as_u8());
    apic::route_legacy_irq(4, interrupts::InterruptIndex::Serial.as_u8());
    // Enable RX IER only after the IOAPIC redirection for IRQ4 is in
    // place — otherwise the first byte raises against a masked vector.
    crate::serial::enable_rx_interrupts();
}
