//! Random bytes for vibix via the `getrandom` syscall (nr 318).

/// Fill `buf` with random bytes from the kernel's CSPRNG.
pub fn fill_bytes(buf: &mut [u8]) {
    // getrandom(buf, len, flags=0)
    let ret = unsafe {
        vibix_abi::syscall::syscall3(
            318, // SYS_getrandom
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            0, // flags
        )
    };
    if ret < 0 {
        panic!("getrandom syscall failed with errno {}", -ret);
    }
    // If we got fewer bytes than requested, loop (should not happen with flags=0).
    let mut filled = ret as usize;
    while filled < buf.len() {
        let ret = unsafe {
            vibix_abi::syscall::syscall3(
                318,
                buf[filled..].as_mut_ptr() as u64,
                (buf.len() - filled) as u64,
                0,
            )
        };
        if ret < 0 {
            panic!("getrandom syscall failed with errno {}", -ret);
        }
        filled += ret as usize;
    }
}
