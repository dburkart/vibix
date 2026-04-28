//! Bounded-iteration corpus runner for the ext2 fuzz harness (#677).
//!
//! Walks every file under a corpus directory, calls
//! [`vibix_ext2_fuzz::fuzz_one`] on each, then runs a deterministic
//! mutation budget on top: byte flips, byte stores, and slice copies
//! seeded from a fixed RNG. The runner does **not** require
//! `cargo-fuzz` / libfuzzer-sys — it's a plain `cargo run` binary so
//! CI can exercise the harness on every PR without installing extra
//! tooling.
//!
//! Exit code is 0 on success, non-zero only if the harness itself
//! panics out-of-band (libstd catches it and aborts) — `fuzz_one` is
//! contract-bound never to panic, so any non-zero exit is itself a
//! finding.
//!
//! Usage (driven by `cargo xtask fuzz ext2`):
//!
//! ```text
//! ext2_fuzz_runner <corpus-dir> [--iters N] [--seed S]
//! ```

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use vibix_ext2_fuzz::{fuzz_one, FuzzExit};

/// Tiny SplitMix64 — deterministic, no external dep, "random enough"
/// for byte-flip fuzzing of small images.
struct SplitMix64(u64);
impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_add(0x9E37_79B9_7F4A_7C15))
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn next_usize(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next() as usize) % bound
        }
    }
}

fn parse_arg<T: std::str::FromStr>(args: &[String], flag: &str) -> Option<T> {
    let prefix = format!("{flag}=");
    for a in args {
        if let Some(rest) = a.strip_prefix(&prefix) {
            if let Ok(v) = rest.parse::<T>() {
                return Some(v);
            }
        }
    }
    None
}

fn read_corpus_seeds(dir: &Path) -> std::io::Result<Vec<(PathBuf, Vec<u8>)>> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let bytes = fs::read(&path)?;
            out.push((path, bytes));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Synthesize the malformed-image scenarios called out in the body of
/// issue #677, derived from the golden image. We generate these
/// in-memory rather than committing eight binary blobs to the repo so
/// the PR diff stays human-readable; cargo-fuzz running the
/// `fuzz_targets/ext2_mount.rs` target uses the on-disk corpus
/// directory directly, while the smoke runner here mixes synthesized
/// scenarios in alongside whatever's on disk.
/// Each synthesized seed is paired with an `Option<FuzzExit>` describing
/// the expected outcome. `Some(v)` is an exact-match assertion: phase 1
/// must observe `fuzz_one(seed) == v` or CI fails. `None` means the
/// scenario doesn't have a structural validator yet (e.g. BGDT free-
/// count fields aren't sanity-checked) — the only contract is "must not
/// panic / OOB / hang", which is enforced by virtue of the runner not
/// crashing.
fn synthesize_malformed_seeds(golden: &[u8]) -> Vec<(String, Vec<u8>, Option<FuzzExit>)> {
    let mut out: Vec<(String, Vec<u8>, Option<FuzzExit>)> = Vec::new();

    // (a) zeroed superblock — magic and everything else is zero.
    {
        let mut img = golden.to_vec();
        for b in &mut img[1024..1024 + 1024] {
            *b = 0;
        }
        out.push((
            "synth:zeroed_superblock".into(),
            img,
            Some(FuzzExit::BadSuperblock),
        ));
    }

    // (b) bad magic — flip the EF53 to AABB.
    {
        let mut img = golden.to_vec();
        img[1024 + 56] = 0xAA;
        img[1024 + 57] = 0xBB;
        out.push((
            "synth:bad_magic".into(),
            img,
            Some(FuzzExit::BadSuperblock),
        ));
    }

    // (c) inflated `s_blocks_count`.
    {
        let mut img = golden.to_vec();
        img[1024 + 4..1024 + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        out.push((
            "synth:inflated_s_blocks_count".into(),
            img,
            Some(FuzzExit::BadSuperblock),
        ));
    }

    // (d) BGDT with negative-equivalent free counts (u16::MAX).
    //     Block size on golden.img is 1024, so BGDT lives at byte
    //     2048; first descriptor at 2048..2080.
    //
    //     The harness doesn't directly validate `bg_free_*_count`, but
    //     stomping u16::MAX into adjacent BGDT bytes typically tips a
    //     pointer field (bg_block_bitmap / bg_inode_bitmap /
    //     bg_inode_table) out of range too. In practice the verdict is
    //     `BadGroupDesc`; assert it explicitly so any drift trips CI.
    {
        let mut img = golden.to_vec();
        // bg_free_blocks_count at offset 12, bg_free_inodes_count at 14.
        img[2048 + 12..2048 + 14].copy_from_slice(&u16::MAX.to_le_bytes());
        img[2048 + 14..2048 + 16].copy_from_slice(&u16::MAX.to_le_bytes());
        out.push((
            "synth:bgdt_negative_free".into(),
            img,
            Some(FuzzExit::BadGroupDesc),
        ));
    }

    // (e) directory record `rec_len` overrun. The 64 KiB golden image
    //     places the root inode's first dir block at block 7 (byte
    //     7168) per `dumpe2fs`; the per-block dir iterator lays out
    //     `{ino, rec_len, name_len, file_type}` starting at offset 0,
    //     so `rec_len` is at offset 4..6. Bump it past the block to
    //     trigger the iterator's straddle check.
    {
        let mut img = golden.to_vec();
        img[7168 + 4..7168 + 6].copy_from_slice(&u16::MAX.to_le_bytes());
        out.push((
            "synth:dir_rec_len_overrun".into(),
            img,
            Some(FuzzExit::BadDirEntry),
        ));
    }

    // (f) indirect block pointing back at itself. Shape it via the
    //     root inode's i_block[12] (single-indirect slot). On
    //     golden.img the root inode is at byte 5248; i_block lives at
    //     +40, so i_block[12] is at byte 5248 + 40 + 48 = 5336.
    //
    //     Stage:
    //       - Pick a free-ish block number (block 30 on the 64-block
    //         image) and stamp it into i_block[12].
    //       - Write a single u32 self-pointer at that block, byte 0.
    //
    //     This corrupts the *root* inode's block list, so the verdict
    //     must surface as `BadRootInode` (the root walk's error remap).
    {
        let mut img = golden.to_vec();
        let ind_block: u32 = 30;
        let i_block_12_off = 5248 + 40 + 48;
        img[i_block_12_off..i_block_12_off + 4].copy_from_slice(&ind_block.to_le_bytes());
        let blk_off = (ind_block as usize) * 1024;
        img[blk_off..blk_off + 4].copy_from_slice(&ind_block.to_le_bytes());
        out.push((
            "synth:indirect_self_loop".into(),
            img,
            Some(FuzzExit::BadRootInode),
        ));
    }

    // (g) indirect block pointing out of range. Same i_block[12]
    //     trick on the root inode but the indirect block contains a
    //     u32 = u32::MAX. Same `BadRootInode` remap as (f).
    {
        let mut img = golden.to_vec();
        let ind_block: u32 = 31;
        let i_block_12_off = 5248 + 40 + 48;
        img[i_block_12_off..i_block_12_off + 4].copy_from_slice(&ind_block.to_le_bytes());
        let blk_off = (ind_block as usize) * 1024;
        img[blk_off..blk_off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        out.push((
            "synth:indirect_oob".into(),
            img,
            Some(FuzzExit::BadRootInode),
        ));
    }

    // (h) bad `s_log_block_size` (≥ 32 → block_size() returns None).
    {
        let mut img = golden.to_vec();
        img[1024 + 24..1024 + 28].copy_from_slice(&32u32.to_le_bytes());
        out.push((
            "synth:bad_log_block_size".into(),
            img,
            Some(FuzzExit::BadSuperblock),
        ));
    }

    out
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let corpus_dir = args
        .first()
        .map(PathBuf::from)
        .ok_or_else(|| "usage: ext2_fuzz_runner <corpus-dir> [--iters=N] [--seed=S]".to_string())?;
    let iters: usize = parse_arg::<usize>(&args, "--iters").unwrap_or(1000);
    let seed: u64 = parse_arg::<u64>(&args, "--seed").unwrap_or(0xDEAD_BEEF_FACE_F00D);

    // On-disk corpus seeds. Each is paired with `Some(FuzzExit::Ok)` —
    // committed seeds must walk cleanly, otherwise the corpus itself is
    // broken. Synthesized malformed seeds are appended below with their
    // own expected verdicts.
    let on_disk: Vec<(String, Vec<u8>)> = read_corpus_seeds(&corpus_dir)
        .map_err(|e| format!("read corpus {}: {e}", corpus_dir.display()))?
        .into_iter()
        .map(|(p, b)| (p.display().to_string(), b))
        .collect();
    if on_disk.is_empty() {
        return Err(format!(
            "corpus directory {} contained no seed files",
            corpus_dir.display()
        ));
    }
    let mut seeds: Vec<(String, Vec<u8>, Option<FuzzExit>)> = on_disk
        .into_iter()
        .map(|(label, bytes)| (label, bytes, Some(FuzzExit::Ok)))
        .collect();

    // Synthesize the issue-#677 malformed scenarios from the largest
    // committed seed (whichever it is, typically the golden 64 KiB
    // image) and append them. Done here so the PR diff doesn't have
    // to ship eight binary blobs.
    let largest = seeds
        .iter()
        .max_by_key(|(_, b, _)| b.len())
        .map(|(_, b, _)| b.clone())
        .unwrap_or_default();
    if largest.len() >= 65_536 {
        seeds.extend(synthesize_malformed_seeds(&largest));
    }

    println!(
        "ext2 fuzz runner: corpus={} seeds={} iters={} seed={:#x}",
        corpus_dir.display(),
        seeds.len(),
        iters,
        seed
    );

    // Phase 1: walk every seed verbatim. Each seed carries an expected
    // verdict (or `None` for "must not panic" probes); a mismatch is a
    // CI failure — silent verdict drift is exactly the regression class
    // this harness is meant to catch.
    let mut mismatches: Vec<String> = Vec::new();
    for (label, bytes, expected) in &seeds {
        let verdict = fuzz_one(bytes);
        match expected {
            Some(want) if verdict != *want => {
                let msg = format!("seed {label} -> {verdict:?} (expected {want:?})");
                println!("MISMATCH {msg}");
                mismatches.push(msg);
            }
            _ => println!("seed {label} -> {verdict:?}"),
        }
    }
    if !mismatches.is_empty() {
        return Err(format!(
            "{} seed verdict mismatch(es); harness contract drifted:\n  {}",
            mismatches.len(),
            mismatches.join("\n  ")
        ));
    }

    // Phase 2: bounded random mutations of each seed. Three primitive
    // mutators chosen for cheapness: single-byte XOR flip, single-byte
    // store, and 4-byte little-endian splat. Drive the loop directly
    // from `total < iters` — pre-splitting via `iters / seeds.len()`
    // floors the budget and zeroes out when iters < seeds.len().
    let mut rng = SplitMix64::new(seed);
    let mut total = 0usize;
    'outer: while total < iters {
        let mut made_progress = false;
        for (_label, base, _) in &seeds {
            if total >= iters {
                break 'outer;
            }
            if base.len() < 8 {
                continue;
            }
            made_progress = true;
            total += 1;
            let mut buf = base.clone();
            let n_mutations = 1 + rng.next_usize(4);
            for _ in 0..n_mutations {
                let pos = rng.next_usize(buf.len());
                match rng.next_usize(3) {
                    0 => buf[pos] ^= rng.next() as u8,
                    1 => buf[pos] = rng.next() as u8,
                    _ => {
                        // 4-byte splat: stomp a u32 LE at a 4-byte
                        // aligned position. This is what the issue
                        // body called out (rec_len overrun, pointer
                        // out-of-range) — cheaper than a full mutator
                        // engine.
                        let aligned = pos & !3;
                        if aligned + 4 <= buf.len() {
                            let v = (rng.next() as u32).to_le_bytes();
                            buf[aligned..aligned + 4].copy_from_slice(&v);
                        }
                    }
                }
            }
            let _ = fuzz_one(&buf);
        }
        if !made_progress {
            // Every seed was below the 8-byte mutation floor — nothing
            // left to mutate, so don't spin forever.
            break;
        }
    }
    println!("ext2 fuzz runner: completed {total} mutated iterations cleanly");
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ext2_fuzz_runner: {e}");
            ExitCode::from(2)
        }
    }
}
