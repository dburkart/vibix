//! Kernel-command-line parsing for root-filesystem selection.
//!
//! Issue #577 (RFC 0004 Workstream F). Extracts `root=<source>` and
//! `rootflags=<csv>` from the Limine-provided cmdline string so the
//! boot path can choose between mounting ext2 on virtio-blk, falling
//! back to the Limine-delivered tarfs module, or a throwaway ramfs.
//!
//! The parser is deliberately tolerant: unknown tokens are ignored
//! (future knobs coexist without a dispatch switch here), and a second
//! occurrence of `root=` or `rootflags=` wins (last-writer-wins, same
//! policy as `writeback_secs`). An empty or missing `root=` resolves
//! to [`RootSource::Default`], which the mount path interprets as
//! "prefer ext2 on the default block device, fall back to tarfs then
//! ramfs."
//!
//! # Accepted `root=` values
//!
//! | Token            | Resolves to           |
//! |------------------|-----------------------|
//! | `/dev/vda`       | `RootSource::VirtioBlk` (try ext2 on virtio-blk) |
//! | `ext2`           | `RootSource::VirtioBlk` (alias, no `/dev/` prefix) |
//! | `tarfs-module`   | `RootSource::TarfsModule` |
//! | `ramfs`          | `RootSource::Ramfs`   |
//! | *(unset)*        | `RootSource::Default` (auto-probe) |
//! | *(other)*        | `RootSource::Default` (unknown → defer to auto-probe + log) |
//!
//! # Accepted `rootflags=` tokens
//!
//! Comma-separated; whitespace around commas is stripped; unknown
//! tokens are silently dropped (bubbles up as "nothing set").
//!
//! - `ro` → [`MountFlags::RDONLY`]
//! - `nosuid` → [`MountFlags::NOSUID`]
//! - `noexec` → [`MountFlags::NOEXEC`]
//! - `nodev` → [`MountFlags::NODEV`]
//!
//! `rw` is accepted and explicitly clears `RDONLY` — this lets the
//! cmdline override a default-RO policy (which #577 installs so the
//! orphan-replay path can be exercised in CI before we flip to RW by
//! default).

// `MountFlags` from `crate::fs::vfs::dentry` is only compiled on
// `target_os = "none"`, but the parser has to run on the host too
// (unit tests). Rather than branch the struct, declare a local
// newtype here whose bit layout matches `vfs::dentry::MountFlags`
// exactly and provide a free conversion function in the kernel
// target. The constants below pin the layout so drift is a
// compile-time break on the target build.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub struct MountFlags(pub u32);

impl MountFlags {
    pub const RDONLY: MountFlags = MountFlags(1 << 0);
    pub const NOEXEC: MountFlags = MountFlags(1 << 1);
    pub const NOSUID: MountFlags = MountFlags(1 << 2);
    pub const NODEV: MountFlags = MountFlags(1 << 3);

    pub const fn contains(self, other: MountFlags) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl core::ops::BitOr for MountFlags {
    type Output = MountFlags;
    fn bitor(self, rhs: Self) -> Self {
        MountFlags(self.0 | rhs.0)
    }
}

#[cfg(target_os = "none")]
impl From<MountFlags> for crate::fs::vfs::dentry::MountFlags {
    fn from(f: MountFlags) -> Self {
        crate::fs::vfs::dentry::MountFlags(f.0)
    }
}

// Bit-layout pin — any divergence from the vfs::dentry copy is a
// compile-time break on the target build.
#[cfg(target_os = "none")]
const _: () = {
    assert!(MountFlags::RDONLY.0 == crate::fs::vfs::dentry::MountFlags::RDONLY.0);
    assert!(MountFlags::NOEXEC.0 == crate::fs::vfs::dentry::MountFlags::NOEXEC.0);
    assert!(MountFlags::NOSUID.0 == crate::fs::vfs::dentry::MountFlags::NOSUID.0);
    assert!(MountFlags::NODEV.0 == crate::fs::vfs::dentry::MountFlags::NODEV.0);
};

/// Root-filesystem source as resolved from the cmdline `root=` token.
///
/// See the module docstring for the token → variant table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootSource {
    /// No explicit `root=` on the cmdline (or an unrecognised value).
    /// The boot path should try the preferred sources in order:
    /// ext2-on-virtio-blk → tarfs module → ramfs.
    Default,
    /// `root=/dev/vda` or `root=ext2`. Try to mount ext2 on the default
    /// block device; fall back on failure.
    VirtioBlk,
    /// `root=tarfs-module`. Mount the Limine `rootfs.tar` module via
    /// TarFs at `/`, ignoring any block device.
    TarfsModule,
    /// `root=ramfs`. Mount a synthesised, empty RamFs at `/`. Matches
    /// the historical host-test fallback behaviour.
    Ramfs,
}

/// Result of parsing `root=` + `rootflags=` from the kernel cmdline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootArgs {
    pub source: RootSource,
    /// Mount flags derived from `rootflags=…`. Zero means "no flags
    /// set" — downstream callers decide the default (today RW until
    /// #564's orphan-replay soak has completed in CI).
    pub mount_flags: MountFlags,
    /// Tri-state: `Some(true)` ⇒ `rootflags=ro` seen; `Some(false)`
    /// ⇒ `rootflags=rw` seen; `None` ⇒ neither, defer to the
    /// built-in default. Distinguishing "unset" from "explicitly rw"
    /// matters so a `rootflags=rw` cmdline overrides a default-RO
    /// policy without surprise.
    pub explicit_ro: Option<bool>,
}

impl RootArgs {
    /// Parser output when no cmdline knobs apply.
    pub const fn auto() -> Self {
        Self {
            source: RootSource::Default,
            mount_flags: MountFlags(0),
            explicit_ro: None,
        }
    }
}

impl Default for RootArgs {
    fn default() -> Self {
        Self::auto()
    }
}

/// Whitespace predicate — space, tab, newline, CR. Matches
/// `block::writeback::parse_cmdline`.
fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

/// Parse `cmdline` for `root=` and `rootflags=` tokens. Returns
/// `RootArgs::auto()` when neither appears. See module docs for the
/// accepted value set.
pub fn parse(cmdline: &[u8]) -> RootArgs {
    let mut out = RootArgs::auto();

    let mut i = 0;
    while i < cmdline.len() {
        // Skip inter-token whitespace.
        while i < cmdline.len() && is_ws(cmdline[i]) {
            i += 1;
        }
        let start = i;
        while i < cmdline.len() && !is_ws(cmdline[i]) {
            i += 1;
        }
        let token = &cmdline[start..i];
        if token.is_empty() {
            continue;
        }
        if let Some(val) = strip_prefix(token, b"root=") {
            out.source = parse_source(val);
        } else if let Some(val) = strip_prefix(token, b"rootflags=") {
            // Last-wins at the token level: reset before applying so
            // `rootflags=ro rootflags=nosuid` yields just NOSUID (no
            // carry-over of RDONLY). Matches the module docstring.
            out.mount_flags = MountFlags(0);
            out.explicit_ro = None;
            apply_rootflags(&mut out, val);
        }
    }
    out
}

fn strip_prefix<'a>(token: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if token.len() >= prefix.len() && &token[..prefix.len()] == prefix {
        Some(&token[prefix.len()..])
    } else {
        None
    }
}

fn parse_source(val: &[u8]) -> RootSource {
    match val {
        b"/dev/vda" | b"ext2" => RootSource::VirtioBlk,
        b"tarfs-module" | b"tarfs" => RootSource::TarfsModule,
        b"ramfs" => RootSource::Ramfs,
        b"" => RootSource::Default,
        // Unknown sources defer to the auto-probe so a typo doesn't
        // lock the kernel out of booting. The mount path logs which
        // source it actually picked.
        _ => RootSource::Default,
    }
}

fn apply_rootflags(out: &mut RootArgs, csv: &[u8]) {
    for item in csv.split(|&b| b == b',') {
        let item = trim_ws(item);
        if item.is_empty() {
            continue;
        }
        match item {
            b"ro" => {
                out.mount_flags = out.mount_flags | MountFlags::RDONLY;
                out.explicit_ro = Some(true);
            }
            b"rw" => {
                out.mount_flags = MountFlags(out.mount_flags.0 & !MountFlags::RDONLY.0);
                out.explicit_ro = Some(false);
            }
            b"nosuid" => {
                out.mount_flags = out.mount_flags | MountFlags::NOSUID;
            }
            b"noexec" => {
                out.mount_flags = out.mount_flags | MountFlags::NOEXEC;
            }
            b"nodev" => {
                out.mount_flags = out.mount_flags | MountFlags::NODEV;
            }
            _ => {}
        }
    }
}

fn trim_ws(mut s: &[u8]) -> &[u8] {
    while let Some((&b, rest)) = s.split_first() {
        if is_ws(b) {
            s = rest;
        } else {
            break;
        }
    }
    while let Some((&b, rest)) = s.split_last() {
        if is_ws(b) {
            s = rest;
        } else {
            break;
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_cmdline_is_auto() {
        let r = parse(b"");
        assert_eq!(r.source, RootSource::Default);
        assert_eq!(r.mount_flags, MountFlags(0));
        assert_eq!(r.explicit_ro, None);
    }

    #[test]
    fn no_root_token_is_auto() {
        let r = parse(b"writeback_secs=5 other=1");
        assert_eq!(r.source, RootSource::Default);
        assert_eq!(r.mount_flags, MountFlags(0));
    }

    #[test]
    fn root_dev_vda_maps_to_virtio_blk() {
        let r = parse(b"root=/dev/vda");
        assert_eq!(r.source, RootSource::VirtioBlk);
    }

    #[test]
    fn root_ext2_alias_maps_to_virtio_blk() {
        let r = parse(b"root=ext2");
        assert_eq!(r.source, RootSource::VirtioBlk);
    }

    #[test]
    fn root_tarfs_module_parses() {
        assert_eq!(parse(b"root=tarfs-module").source, RootSource::TarfsModule);
        assert_eq!(parse(b"root=tarfs").source, RootSource::TarfsModule);
    }

    #[test]
    fn root_ramfs_parses() {
        assert_eq!(parse(b"root=ramfs").source, RootSource::Ramfs);
    }

    #[test]
    fn unknown_root_value_falls_back_to_default() {
        // Typo or unsupported source must not lock the kernel out — the
        // mount path re-probes and logs.
        let r = parse(b"root=nfs://server/export");
        assert_eq!(r.source, RootSource::Default);
    }

    #[test]
    fn last_root_wins() {
        let r = parse(b"root=ramfs root=/dev/vda");
        assert_eq!(r.source, RootSource::VirtioBlk);
    }

    #[test]
    fn rootflags_ro_sets_rdonly_and_explicit_ro() {
        let r = parse(b"root=/dev/vda rootflags=ro");
        assert_eq!(r.source, RootSource::VirtioBlk);
        assert!(r.mount_flags.contains(MountFlags::RDONLY));
        assert_eq!(r.explicit_ro, Some(true));
    }

    #[test]
    fn rootflags_rw_clears_rdonly_and_flags_explicit_rw() {
        let r = parse(b"rootflags=rw");
        assert!(!r.mount_flags.contains(MountFlags::RDONLY));
        assert_eq!(r.explicit_ro, Some(false));
    }

    #[test]
    fn rootflags_csv_accumulates() {
        let r = parse(b"rootflags=ro,nosuid,noexec,nodev");
        assert!(r.mount_flags.contains(MountFlags::RDONLY));
        assert!(r.mount_flags.contains(MountFlags::NOSUID));
        assert!(r.mount_flags.contains(MountFlags::NOEXEC));
        assert!(r.mount_flags.contains(MountFlags::NODEV));
    }

    #[test]
    fn rootflags_ignores_unknown_tokens() {
        let r = parse(b"rootflags=ro,weird,nosuid");
        assert!(r.mount_flags.contains(MountFlags::RDONLY));
        assert!(r.mount_flags.contains(MountFlags::NOSUID));
    }

    #[test]
    fn last_rootflags_wins_per_flag_accumulation_not_overwrite() {
        // Semantically "last wins" at the token level: a later
        // `rootflags=` replaces a prior one, it doesn't union with it.
        // This matches writeback_secs's last-wins discipline and the
        // Linux convention.
        let r = parse(b"rootflags=ro rootflags=nosuid");
        assert!(!r.mount_flags.contains(MountFlags::RDONLY));
        assert!(r.mount_flags.contains(MountFlags::NOSUID));
        assert_eq!(r.explicit_ro, None);
    }

    #[test]
    fn handles_tabs_and_newlines_between_tokens() {
        let r = parse(b"\troot=ramfs\nrootflags=ro\t");
        assert_eq!(r.source, RootSource::Ramfs);
        assert!(r.mount_flags.contains(MountFlags::RDONLY));
    }

    #[test]
    fn non_cmdline_option_prefix_is_not_a_false_match() {
        // `xroot=/dev/vda` must not be read as `root=`.
        let r = parse(b"xroot=/dev/vda");
        assert_eq!(r.source, RootSource::Default);
        // `rootflags_extra=ro` must not be read as `rootflags=`.
        let r = parse(b"rootflags_extra=ro");
        assert_eq!(r.explicit_ro, None);
    }

    #[test]
    fn auto_default_roundtrip() {
        let a = RootArgs::auto();
        assert_eq!(a, RootArgs::default());
        assert_eq!(a.source, RootSource::Default);
        assert_eq!(a.mount_flags, MountFlags(0));
        assert_eq!(a.explicit_ro, None);
    }
}
