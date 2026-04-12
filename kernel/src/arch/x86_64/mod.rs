pub mod gdt;
pub mod idt;

pub fn init() {
    gdt::init();
    idt::init();
}
