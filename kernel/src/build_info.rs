//! Compile-time build metadata baked in by `build.rs`.
//!
//! The values below are populated via `cargo:rustc-env=` directives, so
//! they are plain string literals — usable from `no_std` contexts and
//! from host unit tests alike.

pub const KERNEL_NAME: &str = "vibix";
pub const ARCH: &str = env!("VIBIX_TARGET_ARCH");

/// Kernel "release" string — mirrors Linux's `uname -r` slot. We don't
/// yet version the kernel independently of the workspace, so the crate
/// version is the most meaningful identifier a user can grep for.
pub const RELEASE: &str = env!("CARGO_PKG_VERSION");

/// Short git SHA of the tree the kernel was built from, or `"unknown"`
/// when the tree wasn't a git checkout at build time.
pub const GIT_SHA: &str = env!("VIBIX_GIT_SHA");

/// ISO-8601 UTC timestamp captured at build time. Honors
/// `SOURCE_DATE_EPOCH` for reproducible builds.
pub const BUILD_TIMESTAMP: &str = env!("VIBIX_BUILD_TIMESTAMP");

/// Cargo profile name (`"debug"`, `"release"`, …).
pub const PROFILE: &str = env!("VIBIX_BUILD_PROFILE");
