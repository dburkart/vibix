//! Minimal serial output for diagnostic messages.
//!
//! Writes to fd 1 (stdout, which is the serial console on vibix).

/// Write a byte slice to stdout (serial).
pub fn puts(msg: &[u8]) {
    if msg.is_empty() {
        return;
    }
    unsafe {
        let _: i64;
        core::arch::asm!(
            "syscall",
            inlateout("rax") 1u64 => _,
            inlateout("rdi") 1u64 => _,
            inlateout("rsi") msg.as_ptr() as u64 => _,
            inlateout("rdx") msg.len() as u64 => _,
            lateout("rcx") _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("r10") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
}

/// Print a u64 as hexadecimal (useful for diagnostic output).
#[allow(dead_code)]
pub fn put_hex(val: u64) {
    let mut buf = [b'0'; 18]; // "0x" + 16 hex digits
    buf[0] = b'0';
    buf[1] = b'x';
    let hex = b"0123456789abcdef";
    for i in 0..16 {
        buf[17 - i] = hex[((val >> (i * 4)) & 0xF) as usize];
    }
    puts(&buf);
}
