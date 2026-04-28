//! libFuzzer target for the ext2 mount + read paths (#677).
//!
//! Gated behind the `libfuzzer` feature so a plain
//! `cargo build -p vibix-ext2-fuzz` does not try to link
//! `libfuzzer-sys`. Run locally with:
//!
//! ```text
//! cd kernel/fuzz
//! cargo +nightly fuzz run ext2_mount
//! ```
//!
//! The CI lane drives the same `fuzz_one` driver via
//! `ext2_fuzz_runner` — see `cargo xtask fuzz ext2`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = vibix_ext2_fuzz::fuzz_one(data);
});
