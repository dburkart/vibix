//! Deterministic ext2 rootfs image builder.
//!
//! Produces `target/vibix-root.ext2`, a 64 MiB ext2 filesystem image that
//! is **byte-identical across runs** so CI diffs of the image are
//! meaningful and boot failures reproduce without host-randomness noise.
//!
//! ## Determinism strategy
//!
//! ext2 images built by `mkfs.ext2` default to three host-dependent
//! values: a random UUID, a random hash seed, and current wall-clock
//! timestamps in the superblock plus every inode. We pin each of these:
//!
//! - **UUID**: `-U <FIXED_UUID>`.
//! - **Timestamps**: `E2FSPROGS_FAKE_TIME=<FIXED_EPOCH>` (e2fsprogs
//!   honours this env var in every `time()` call, pinning `s_mtime`,
//!   `s_wtime`, `s_lastcheck`, and every inode's a/c/m/crtime).
//! - **Hash seed**: the `-E hash_seed=` option is silently ignored when
//!   the `dir_index` feature is disabled (which it is — RFC 0004 pins
//!   `-O ^dir_index,^has_journal,^ext_attr`), so mkfs still writes a
//!   random 16-byte `s_hash_seed` at superblock offset 236. We overwrite
//!   those 16 bytes in-place after mkfs returns.
//!
//! We then drive `debugfs` (also under `E2FSPROGS_FAKE_TIME`) to
//! populate a fixed directory tree plus a `/init` file with uid/gid 0
//! and known timestamps. `mkfs.ext2 -d` would work for content but
//! inherits the host caller's uid/gid on copied files, which is not
//! reproducible across developer machines vs. CI runners.
//!
//! ## Feature set
//!
//! The on-disk feature flags match RFC 0004 §Boot path exactly:
//! `-O ^dir_index,^has_journal,^ext_attr`. Everything else (filetype,
//! sparse_super, large_file, etc.) follows the e2fsprogs default for
//! `-t ext2`. 128-byte inodes keep the image within the MVP driver's
//! supported size class; 4 KiB blocks match the kernel's page size.

use std::error::Error;
use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

type R<T> = Result<T, Box<dyn Error>>;

/// Fixed superblock UUID. Matches the value referenced in the
/// workstream-F issue (#579). Any future driver test that wants to
/// assert mount-by-UUID should read this constant.
const FIXED_UUID: &str = "a1a2a3a4-0000-1111-2222-333344445555";

/// Fixed SOURCE_DATE_EPOCH-style timestamp pinned into every metadata
/// block. 2023-11-14 22:13:20 UTC — the same `1_700_000_000` constant
/// suggested in the RFC; arbitrary but committed-to so image diffs are
/// stable.
const FIXED_EPOCH: u64 = 1_700_000_000;

/// Fixed 16-byte `s_hash_seed`. The value encodes the ASCII string
/// `deadbeef-c0de-c0de-c0de-decadeb0ef00` as a UUID's bytes; its
/// concrete contents are unimportant, only that they are stable. See
/// the module-level docstring for why mkfs's `-E hash_seed=` option
/// cannot be used here.
const FIXED_HASH_SEED: [u8; 16] = [
    0xde, 0xad, 0xbe, 0xef, 0xc0, 0xde, 0xc0, 0xde, 0xc0, 0xde, 0xde, 0xca, 0xde, 0xb0, 0xef, 0x00,
];

/// Superblock lives at byte offset 1024; `s_hash_seed` is at offset
/// 236 inside the superblock (see `struct ext2_super_block` in
/// `include/linux/ext2_fs.h`), so the absolute file offset is 1260.
const HASH_SEED_ABS_OFFSET: u64 = 1024 + 236;

/// Label pinned into the superblock. `mount -L vibix-root` resolves to
/// this image; the driver does not yet honour labels but setting it
/// removes one more source of byte-level drift.
const LABEL: &str = "vibix-root";

/// Image size. 64 MiB is large enough for a small userspace fixture
/// tree (pjdfstest runners, some test binaries) without bloating CI
/// artefacts.
const IMAGE_SIZE_BYTES: u64 = 64 * 1024 * 1024;

/// Block size. Matches the kernel's 4 KiB page size.
const BLOCK_SIZE: u32 = 4096;

/// Inode size. 128 bytes keeps the image inside the MVP driver's
/// supported profile (`EXT4_ISIZE_BASE == 128`).
const INODE_SIZE: u32 = 128;

/// Pre-allocated inode count. 2048 is ample for the fixture tree and
/// whatever pjdfstest scratches into the image, and keeps the image
/// small.
const INODE_COUNT: u32 = 2048;

/// Output artefact path relative to the workspace root.
pub fn image_path(workspace_root: &Path) -> PathBuf {
    workspace_root.join("target").join("vibix-root.ext2")
}

/// Expected-hash file path relative to the workspace root.
///
/// Committed to VCS so CI can detect image-content drift (a mkfs
/// upgrade or a fixture tree change). See `build()` for the
/// hash-drift failure mode.
pub fn expected_hash_path(workspace_root: &Path) -> PathBuf {
    workspace_root
        .join("tests")
        .join("fixtures")
        .join("ext2_image.sha256")
}

/// Build the deterministic ext2 image at `target/vibix-root.ext2`.
///
/// Steps:
/// 1. Zero-truncate the output file to `IMAGE_SIZE_BYTES`.
/// 2. Run `mkfs.ext2` under `E2FSPROGS_FAKE_TIME` with pinned
///    UUID / feature flags.
/// 3. Run `debugfs -w` (also under `E2FSPROGS_FAKE_TIME`) to create
///    the fixture tree and `/init`, explicitly zeroing uid/gid and
///    re-stamping every inode's timestamps to `FIXED_EPOCH`.
/// 4. Overwrite the 16-byte `s_hash_seed` at offset 1260 with
///    `FIXED_HASH_SEED`.
/// 5. Compute the image's SHA-256 and compare it to the committed
///    expected-hash file. If the file is absent, write it (first run
///    / `update_hash = true`). If present and it differs, return an
///    error so CI catches the drift.
///
/// `init_src`, if `Some`, is the host path of the binary to publish as
/// `/init`. Pass `None` to generate a placeholder (`#!vibix-init`
/// sentinel) — useful when the real userspace_init binary isn't built
/// yet (e.g. CI's first bootstrap run before the kernel-side mount
/// plumbing lands in #577).
pub fn build(workspace_root: &Path, init_src: Option<&Path>, update_hash: bool) -> R<PathBuf> {
    let out = image_path(workspace_root);
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent)?;
    }

    // Step 1: zero-fill the file.
    {
        let f = fs::File::create(&out)?;
        f.set_len(IMAGE_SIZE_BYTES)?;
    }

    // Step 2: mkfs.ext2 with pinned everything.
    run_mkfs(&out)?;

    // Step 3: populate the fixture tree via debugfs. Staging a copy of
    // the init binary under `target/` keeps the path short (debugfs
    // `write` tokenises on whitespace, so paths with embedded spaces
    // would break) and makes the command transcript reproducible.
    let init_bin = stage_init(workspace_root, init_src)?;
    run_debugfs_populate(&out, &init_bin)?;

    // Step 4: pin s_hash_seed in the superblock.
    pin_hash_seed(&out)?;

    // Step 5: hash-drift gate.
    let got = sha256_hex(&out)?;
    let expected_path = expected_hash_path(workspace_root);
    match fs::read_to_string(&expected_path) {
        Ok(s) => {
            let expected = s.trim();
            if expected != got {
                if update_hash {
                    if let Some(parent) = expected_path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::write(&expected_path, format!("{got}\n"))?;
                    eprintln!("→ ext2-image: updated {}", expected_path.display());
                } else {
                    return Err(format!(
                        "ext2-image hash drift\n  expected: {expected}\n       got: {got}\n\
                         run `cargo xtask ext2-image --update-hash` to accept the new hash \
                         if the change is intentional."
                    )
                    .into());
                }
            }
        }
        Err(_) => {
            if let Some(parent) = expected_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&expected_path, format!("{got}\n"))?;
            eprintln!("→ ext2-image: seeded {}", expected_path.display());
        }
    }

    println!("→ ext2-image: {} (sha256 {})", out.display(), got);
    Ok(out)
}

/// Stage the `/init` payload under `target/` so debugfs sees a short,
/// whitespace-free path. If `init_src` is `None`, write a small
/// placeholder — the kernel ext2 mount plumbing lands in #577 and the
/// image is useful to build independently of that work.
fn stage_init(workspace_root: &Path, init_src: Option<&Path>) -> R<PathBuf> {
    let staged = workspace_root.join("target").join("vibix-root-init.bin");
    if let Some(parent) = staged.parent() {
        fs::create_dir_all(parent)?;
    }
    match init_src {
        Some(src) => {
            fs::copy(src, &staged)?;
        }
        None => {
            // Placeholder content — the literal bytes are irrelevant
            // for the determinism test, but stable content keeps the
            // image hash stable until a real init payload arrives.
            fs::write(&staged, b"#!vibix-init placeholder\n")?;
        }
    }
    Ok(staged)
}

fn run_mkfs(image: &Path) -> R<()> {
    let status = Command::new("mkfs.ext2")
        .env("E2FSPROGS_FAKE_TIME", FIXED_EPOCH.to_string())
        .args([
            "-q",
            "-F",
            "-L",
            LABEL,
            "-U",
            FIXED_UUID,
            "-O",
            "^dir_index,^has_journal,^ext_attr",
            "-t",
            "ext2",
            "-b",
            &BLOCK_SIZE.to_string(),
            "-I",
            &INODE_SIZE.to_string(),
            "-N",
            &INODE_COUNT.to_string(),
            "-m",
            "0",
            "-E",
            "packed_meta_blocks=0",
        ])
        .arg(image)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| format!("mkfs.ext2: {e} (is e2fsprogs installed?)"))?;
    if !status.success() {
        return Err(format!("mkfs.ext2 failed: {status}").into());
    }
    Ok(())
}

/// Drive `debugfs -w` over a heredoc-style command stream. The script:
///
/// - Creates the fixture directory tree (`/bin`, `/tmp`, `/dev`,
///   `/etc`, `/etc/init`) used by RFC 0002 §Initialization order.
/// - Writes `/init` from the staged payload.
/// - Force-zeroes uid/gid on every new inode (the root directory
///   already has uid/gid 0 by virtue of the mkfs default) and pins
///   each inode's a/c/m/crtime to `FIXED_EPOCH`.
///
/// The `sif` (set inode field) command takes the field name verbatim;
/// the field list is documented in `debugfs(8)`.
fn run_debugfs_populate(image: &Path, init_bin: &Path) -> R<()> {
    let init_str = init_bin.to_str().ok_or("init path is not UTF-8")?;
    if init_str.chars().any(|c| c.is_whitespace()) {
        return Err(format!("init path contains whitespace: {init_str}").into());
    }

    // Build the debugfs script. Timestamp fields are pinned on every
    // inode we touched (root + the five directories + /init) so a
    // debugfs upgrade that changes default crtime behaviour can't drift
    // the image.
    let mut script = String::new();
    // Pin root-directory timestamps too — mkfs already set them to
    // FAKE_TIME but we belt-and-brace it so a future mkfs that stops
    // honouring E2FSPROGS_FAKE_TIME for the root dir wouldn't regress.
    stamp(&mut script, "/");
    for dir in ["/bin", "/tmp", "/dev", "/etc", "/etc/init"] {
        script.push_str(&format!("mkdir {dir}\n"));
        // set_current_time applies to the CWD-of-debugfs, not the file —
        // we use `sif` instead, which addresses the inode by path.
        stamp(&mut script, dir);
    }
    script.push_str(&format!("write {init_str} init\n"));
    script.push_str("sif /init mode 0100755\n");
    script.push_str("sif /init uid 0\n");
    script.push_str("sif /init gid 0\n");
    stamp(&mut script, "/init");

    let mut child = Command::new("debugfs")
        .env("E2FSPROGS_FAKE_TIME", FIXED_EPOCH.to_string())
        .args(["-w", "-f", "-"])
        .arg(image)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("debugfs: {e} (is e2fsprogs installed?)"))?;
    {
        let stdin = child.stdin.as_mut().ok_or("no debugfs stdin")?;
        stdin.write_all(script.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(format!(
            "debugfs populate failed: {}\n--- stderr ---\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
        )
        .into());
    }
    // debugfs prints warnings to stderr even on success for things
    // like "Allocated inode" — only fail on an explicit error exit.
    Ok(())
}

fn stamp(script: &mut String, path: &str) {
    script.push_str(&format!("sif {path} atime {FIXED_EPOCH}\n"));
    script.push_str(&format!("sif {path} ctime {FIXED_EPOCH}\n"));
    script.push_str(&format!("sif {path} mtime {FIXED_EPOCH}\n"));
    script.push_str(&format!("sif {path} crtime {FIXED_EPOCH}\n"));
}

/// Overwrite the 16-byte `s_hash_seed` at the pinned offset.
fn pin_hash_seed(image: &Path) -> R<()> {
    let mut f = fs::OpenOptions::new().write(true).open(image)?;
    f.seek(SeekFrom::Start(HASH_SEED_ABS_OFFSET))?;
    f.write_all(&FIXED_HASH_SEED)?;
    Ok(())
}

/// Minimal SHA-256 over the image file. Implemented inline to avoid
/// pulling a crate dep into xtask for a one-caller use; the constants
/// below are FIPS 180-4.
fn sha256_hex(path: &Path) -> R<String> {
    let bytes = fs::read(path)?;
    let digest = sha256(&bytes);
    let mut s = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    Ok(s)
}

// ------------- SHA-256 (FIPS 180-4, straight translation) ------------

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(msg: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // Pad: 0x80, then zeros, then 64-bit big-endian bit-length, so
    // total length ≡ 0 (mod 64).
    let bitlen: u64 = (msg.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(msg.len() + 73);
    padded.extend_from_slice(msg);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bitlen.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let mj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(mj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6234 test vector.
    #[test]
    fn sha256_empty_string() {
        let d = sha256(b"");
        let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// FIPS 180-2 Appendix B test vector 1.
    #[test]
    fn sha256_abc() {
        let d = sha256(b"abc");
        let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// FIPS 180-2 Appendix B test vector 2 (56-byte message —
    /// exercises the padding block boundary).
    #[test]
    fn sha256_double_block() {
        let d = sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }
}
