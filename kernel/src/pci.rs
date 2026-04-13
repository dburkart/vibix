//! Legacy PCI configuration-space enumeration via I/O ports 0xCF8/0xCFC.
//!
//! Call [`scan`] once after `mem::init()` to populate a process-wide list
//! of visible devices on bus 0. After that, [`devices`] hands out an
//! iterator over the snapshot.
//!
//! This is deliberately minimal:
//!
//! - Legacy port access only — no MMIO / ECAM / MCFG (#42 out of scope).
//! - Bus 0 only — the brute-force recursive walk of PCI bridges is a
//!   follow-up once a bridge actually lives on a real board under QEMU.
//! - Read-only; no BAR sizing, no bus-mastering flip, no MSI/MSI-X.
//!
//! The header parser ([`Device::from_raw`]) is host-testable: it takes
//! raw config dwords and produces a [`Device`], so the decoding logic
//! can be exercised under `cargo test --lib` without any port I/O.

use alloc::vec::Vec;
use spin::Once;

/// CONFIG_ADDRESS port.
pub const CONFIG_ADDRESS: u16 = 0xCF8;
/// CONFIG_DATA port.
pub const CONFIG_DATA: u16 = 0xCFC;

/// `(bus, device, function)` tuple for a PCI endpoint.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Address {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl Address {
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device,
            function,
        }
    }

    /// CONFIG_ADDRESS dword for `offset` (must be dword-aligned).
    pub const fn config_dword(self, offset: u8) -> u32 {
        let bus = self.bus as u32;
        let dev = (self.device as u32) & 0x1F;
        let fun = (self.function as u32) & 0x07;
        let off = (offset as u32) & 0xFC;
        0x8000_0000 | (bus << 16) | (dev << 11) | (fun << 8) | off
    }
}

/// One Base Address Register slot. We store the raw dword; the helpers
/// below decode its fields.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Bar(pub u32);

impl Bar {
    pub fn is_io(self) -> bool {
        self.0 & 0x1 != 0
    }
    pub fn is_mem(self) -> bool {
        self.0 & 0x1 == 0
    }
    /// 64-bit memory BAR (consumes the next BAR slot for the high dword).
    pub fn is_64bit(self) -> bool {
        self.is_mem() && ((self.0 >> 1) & 0x3) == 0x2
    }
    /// Base address (low dword) with the type flags masked out.
    ///
    /// For 64-bit memory BARs ([`is_64bit`](Self::is_64bit) is true) this
    /// only exposes the low 32 bits; use [`addr64`](Self::addr64) with the
    /// adjacent BAR slot to recover the full 64-bit base.
    pub fn addr(self) -> u32 {
        if self.is_io() {
            self.0 & 0xFFFF_FFFC
        } else {
            self.0 & 0xFFFF_FFF0
        }
    }
    /// Full 64-bit base for a 64-bit memory BAR, combining this slot (low
    /// dword) with the adjacent slot that holds the high dword.
    pub fn addr64(self, next: Bar) -> u64 {
        ((next.0 as u64) << 32) | ((self.0 as u64) & 0xFFFF_FFF0)
    }
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// One enumerated PCI function.
#[derive(Copy, Clone, Debug)]
pub struct Device {
    pub addr: Address,
    pub vendor_id: u16,
    pub device_id: u16,
    pub revision: u8,
    pub prog_if: u8,
    pub subclass: u8,
    pub class: u8,
    /// Low 7 bits of the header-type byte (multifunction bit stripped).
    pub header_type: u8,
    /// Raw BARs. Only populated for type-0 headers; zeroed for bridges.
    pub bars: [Bar; 6],
}

impl Device {
    /// Build a [`Device`] from the raw config dwords.
    ///
    /// - `dw0` = offset 0x00 (vendor/device).
    /// - `dw2` = offset 0x08 (revision/class/subclass/prog_if).
    /// - `dw3` = offset 0x0C (cache-line size/latency/header-type/BIST).
    /// - `bars` = raw dwords at 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24.
    ///   Pass zeros for non-type-0 headers; the function itself does not
    ///   inspect the header type to decide.
    ///
    /// The multifunction bit (bit 7) is stripped from `header_type`; the
    /// caller uses [`Device::is_multifunction_byte`] on the raw byte when
    /// walking functions 1..8 during enumeration.
    pub const fn from_raw(addr: Address, dw0: u32, dw2: u32, dw3: u32, bars: [u32; 6]) -> Self {
        let vendor_id = (dw0 & 0xFFFF) as u16;
        let device_id = ((dw0 >> 16) & 0xFFFF) as u16;

        let revision = (dw2 & 0xFF) as u8;
        let prog_if = ((dw2 >> 8) & 0xFF) as u8;
        let subclass = ((dw2 >> 16) & 0xFF) as u8;
        let class = ((dw2 >> 24) & 0xFF) as u8;

        let header_type = (((dw3 >> 16) & 0xFF) as u8) & 0x7F;

        let bars = [
            Bar(bars[0]),
            Bar(bars[1]),
            Bar(bars[2]),
            Bar(bars[3]),
            Bar(bars[4]),
            Bar(bars[5]),
        ];

        Self {
            addr,
            vendor_id,
            device_id,
            revision,
            prog_if,
            subclass,
            class,
            header_type,
            bars,
        }
    }

    /// Low-friction "is this the multifunction bit set?" check against
    /// the raw header-type byte at offset 0x0E. The scan uses this on
    /// function 0 to decide whether to probe functions 1..8.
    pub const fn is_multifunction_byte(raw_header_type: u8) -> bool {
        raw_header_type & 0x80 != 0
    }

    /// Short human-readable class name for the `pci` shell builtin.
    pub fn class_name(&self) -> &'static str {
        match (self.class, self.subclass) {
            (0x00, _) => "unclassified",
            (0x01, 0x00) => "scsi",
            (0x01, 0x01) => "ide",
            (0x01, 0x06) => "sata",
            (0x01, 0x08) => "nvme",
            (0x01, _) => "storage",
            (0x02, _) => "network",
            (0x03, 0x00) => "vga",
            (0x03, _) => "display",
            (0x04, _) => "multimedia",
            (0x06, 0x00) => "host-bridge",
            (0x06, 0x01) => "isa-bridge",
            (0x06, 0x04) => "pci-bridge",
            (0x06, _) => "bridge",
            (0x07, _) => "comm",
            (0x0C, 0x03) => "usb",
            (0x0C, _) => "serial-bus",
            _ => "other",
        }
    }
}

/// Snapshot of the enumerated device list. `None` before [`scan`] runs.
static DEVICES: Once<Vec<Device>> = Once::new();

/// Iterator handed out by [`devices`].
pub struct DevicesIter {
    inner: core::slice::Iter<'static, Device>,
}

impl Iterator for DevicesIter {
    type Item = &'static Device;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

/// Iterate over the scanned devices. Returns an empty iterator if
/// [`scan`] has not yet been called.
pub fn devices() -> DevicesIter {
    DevicesIter {
        inner: match DEVICES.get() {
            Some(v) => v.iter(),
            None => [].iter(),
        },
    }
}

/// Number of enumerated devices. Convenience for the shell builtin and
/// integration tests.
pub fn device_count() -> usize {
    DEVICES.get().map_or(0, |v| v.len())
}

// -- on-target port I/O + scan ------------------------------------------

#[cfg(target_os = "none")]
mod target {
    use super::{Address, Device, CONFIG_ADDRESS, CONFIG_DATA, DEVICES};
    use alloc::vec::Vec;
    use spin::Mutex;
    use x86_64::instructions::port::Port;

    /// Serializes the CONFIG_ADDRESS/CONFIG_DATA pair. PCI config access
    /// is two separate port writes; any preemption or other CPU between
    /// the writes corrupts the transaction. We grab this mutex and
    /// additionally suppress local IRQs for the duration of each access.
    static CFG_LOCK: Mutex<()> = Mutex::new(());

    /// Read a 32-bit word from the PCI config space at `addr + offset`.
    ///
    /// `offset` must be dword-aligned; the low two bits are masked off
    /// by [`super::Address::config_dword`] so mis-aligned offsets degrade
    /// to the aligned dword rather than returning garbage.
    ///
    /// # Safety
    /// Issues raw OUT/IN to 0xCF8/0xCFC. These ports are a known, fixed
    /// hardware interface — the unsafety is entirely about holding the
    /// `CFG_LOCK` for the two-step transaction, which this function does.
    pub unsafe fn config_read32(addr: Address, offset: u8) -> u32 {
        let mut value: u32 = 0;
        // Suppress IRQs *before* acquiring CFG_LOCK. Acquiring the lock
        // first leaves a window where a timer tick can preempt the
        // holder; on a single CPU the preempted task can never run
        // again, and any other task calling config_read32 would spin on
        // the lock forever.
        x86_64::instructions::interrupts::without_interrupts(|| {
            let _guard = CFG_LOCK.lock();
            let mut a: Port<u32> = Port::new(CONFIG_ADDRESS);
            let mut d: Port<u32> = Port::new(CONFIG_DATA);
            a.write(addr.config_dword(offset));
            value = d.read();
        });
        value
    }

    fn read_device(addr: Address) -> Option<Device> {
        // SAFETY: see config_read32 — the fixed hardware interface.
        let dw0 = unsafe { config_read32(addr, 0x00) };
        let vendor = (dw0 & 0xFFFF) as u16;
        if vendor == 0xFFFF {
            return None;
        }
        let dw2 = unsafe { config_read32(addr, 0x08) };
        let dw3 = unsafe { config_read32(addr, 0x0C) };
        let raw_header = ((dw3 >> 16) & 0xFF) as u8;
        let header_kind = raw_header & 0x7F;
        // Only type-0 endpoints expose six BARs at 0x10..0x28. Type-1
        // (PCI-to-PCI bridge) has two BARs plus bus-number registers;
        // type-2 (CardBus) has its own layout. For the scope of this
        // issue we only populate BARs for type 0.
        let mut bars = [0u32; 6];
        if header_kind == 0x00 {
            for (i, slot) in bars.iter_mut().enumerate() {
                *slot = unsafe { config_read32(addr, 0x10 + (i as u8) * 4) };
            }
        }
        Some(Device::from_raw(addr, dw0, dw2, dw3, bars))
    }

    /// Enumerate bus 0. Safe to call exactly once after `mem::init()`;
    /// subsequent calls are no-ops.
    pub fn scan() {
        DEVICES.call_once(|| {
            let mut out: Vec<Device> = Vec::new();
            for device in 0..32u8 {
                let addr0 = Address::new(0, device, 0);
                let d0 = match read_device(addr0) {
                    Some(d) => d,
                    None => continue,
                };
                // Re-read the raw header byte so we can consult the
                // multifunction bit without having stored it on Device.
                let dw3 = unsafe { config_read32(addr0, 0x0C) };
                let raw_header = ((dw3 >> 16) & 0xFF) as u8;
                out.push(d0);
                if Device::is_multifunction_byte(raw_header) {
                    for function in 1..8u8 {
                        let addr = Address::new(0, device, function);
                        if let Some(d) = read_device(addr) {
                            out.push(d);
                        }
                    }
                }
            }
            out
        });
        let n = super::device_count();
        crate::serial_println!("pci: {} device(s) on bus 0", n);
        // One-line-per-device summary so the boot log shows the full
        // inventory without needing to run the shell builtin.
        for d in super::devices() {
            crate::serial_println!(
                "pci:   {:02x}:{:02x}.{:x} {:04x}:{:04x} class {:02x}:{:02x} pi={:02x} ({})",
                d.addr.bus,
                d.addr.device,
                d.addr.function,
                d.vendor_id,
                d.device_id,
                d.class,
                d.subclass,
                d.prog_if,
                d.class_name(),
            );
        }
    }
}

#[cfg(target_os = "none")]
pub use target::{config_read32, scan};

// -- host unit tests ----------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_config_dword_encodes_all_fields() {
        let a = Address::new(0x12, 0x1F, 0x07);
        // bits: enable=0x80000000 | bus<<16 | dev<<11 | fn<<8 | (offset&0xFC)
        assert_eq!(
            a.config_dword(0x14),
            0x8000_0000 | (0x12 << 16) | (0x1F << 11) | (0x07 << 8) | 0x14
        );
        // Offset low 2 bits are masked.
        assert_eq!(a.config_dword(0x17), a.config_dword(0x14));
    }

    #[test]
    fn from_raw_decodes_type0_fields() {
        // Example: QEMU's i440FX host bridge (8086:1237), class 06:00.
        let dw0 = 0x1237_8086;
        let dw2 = 0x0600_0002; // rev=02, pi=00, subclass=00, class=06
        let dw3 = 0x0000_0000; // header_type=0x00
        let d = Device::from_raw(Address::new(0, 0, 0), dw0, dw2, dw3, [0; 6]);
        assert_eq!(d.vendor_id, 0x8086);
        assert_eq!(d.device_id, 0x1237);
        assert_eq!(d.revision, 0x02);
        assert_eq!(d.prog_if, 0x00);
        assert_eq!(d.subclass, 0x00);
        assert_eq!(d.class, 0x06);
        assert_eq!(d.header_type, 0x00);
        assert_eq!(d.class_name(), "host-bridge");
    }

    #[test]
    fn multifunction_bit_stripped_from_header_type() {
        // header_type byte 0x80 means "type 0, multifunction".
        let dw3 = 0x0080_0000;
        let d = Device::from_raw(Address::new(0, 0, 0), 0x1234_5678, 0, dw3, [0; 6]);
        assert_eq!(d.header_type, 0x00);
        assert!(Device::is_multifunction_byte(0x80));
        assert!(!Device::is_multifunction_byte(0x00));
    }

    #[test]
    fn bar_decodes_io_vs_memory() {
        let io = Bar(0x0000_C001); // IO, base 0xC000
        assert!(io.is_io());
        assert!(!io.is_mem());
        assert_eq!(io.addr(), 0xC000);

        let mem32 = Bar(0xFEBC_0000); // 32-bit memory BAR
        assert!(mem32.is_mem());
        assert!(!mem32.is_64bit());
        assert_eq!(mem32.addr(), 0xFEBC_0000);

        let mem64 = Bar(0xFEBC_0004); // type = 0b10 (64-bit memory)
        assert!(mem64.is_mem());
        assert!(mem64.is_64bit());
    }
}
