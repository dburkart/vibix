//! Emits compile-time build metadata used by the `kernel::build_info`
//! module: short git SHA, an ISO-8601 build timestamp, and the cargo
//! profile name. Falls back to `"unknown"` for the SHA when the tree
//! isn't a git checkout so tarball builds don't break.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let sha = git_short_sha().unwrap_or_else(|| "unknown".to_string());
    let ts = build_timestamp();
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string());
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "unknown".to_string());

    println!("cargo:rustc-env=VIBIX_GIT_SHA={}", sha);
    println!("cargo:rustc-env=VIBIX_BUILD_TIMESTAMP={}", ts);
    println!("cargo:rustc-env=VIBIX_BUILD_PROFILE={}", profile);
    println!("cargo:rustc-env=VIBIX_TARGET_ARCH={}", arch);

    // Only rebuild when the HEAD ref or the packed-refs file changes —
    // not on every source edit. Paths are relative to the workspace
    // root; `..` steps out of `kernel/`.
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/refs/heads");
    println!("cargo:rerun-if-changed=../.git/packed-refs");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
}

fn git_short_sha() -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let sha = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if sha.is_empty() {
        None
    } else {
        Some(sha)
    }
}

fn build_timestamp() -> String {
    let epoch = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs())
        })
        .unwrap_or(0);
    format_epoch(epoch)
}

/// Format seconds-since-epoch as `YYYY-MM-DDTHH:MM:SSZ` (ISO-8601 UTC).
/// No external dep — proleptic Gregorian calendar with a leap-year cycle
/// that is correct for every year in the foreseeable future.
fn format_epoch(epoch: u64) -> String {
    let secs = epoch % 60;
    let mins = (epoch / 60) % 60;
    let hours = (epoch / 3600) % 24;
    let mut days = epoch / 86_400;

    let mut year: u64 = 1970;
    loop {
        let ydays = if is_leap(year) { 366 } else { 365 };
        if days < ydays {
            break;
        }
        days -= ydays;
        year += 1;
    }

    let month_lens = [
        31u64,
        if is_leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u64;
    for &len in &month_lens {
        if days < len {
            break;
        }
        days -= len;
        month += 1;
    }
    let day = days + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, mins, secs
    )
}

fn is_leap(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}
