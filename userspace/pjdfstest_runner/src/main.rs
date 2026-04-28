//! `pjdfstest_runner` — no_std PID-1 test executor for issue #642.
//!
//! Drives a small, hand-curated subset of pjdfstest-style POSIX
//! filesystem assertions inside vibix and emits the marker contract
//! the `cargo xtask pjdfstest` harness (#581/#641) parses off the
//! serial console:
//!
//! - `TEST_PASS:<name>`
//! - `TEST_FAIL:<name>:<reason>`
//! - `TEST_DONE` once every case has reported.
//!
//! ## Why no_std (option 2 from #642)
//!
//! The vendored `tests/pjdfstest` (saidsay-so/pjdfstest, 2-clause BSD)
//! is an ordinary `std` binary — `nix`, `tempfile`, `figment`,
//! `inventory`, … — none of which can build for vibix today because
//! there is no `x86_64-unknown-vibix` `std` target. Option 2 (per the
//! 2026-04-28 direction-pin comment on #642) is to rewrite **only the
//! executor** in no_std and call vibix syscalls directly. The
//! per-case definitions in `tests/pjdfstest/src/tests/` stay around
//! as a reference for the long-tail std-on-vibix port; this runner is
//! intentionally a minimal hand-curated subset chosen to:
//!
//!   1. Exercise the now-real POSIX surface (#650 setgroups, #653
//!      faccessat, #660 vfs_creds DAC enforcement, #661 orphan
//!      finalize, plus the always-present open / unlink / mkdir /
//!      link / symlink / chmod / readlink / chdir / getcwd path).
//!   2. Drive the harness's baseline off `0/0/0` so the CI gate
//!      landed in #643 actually has something to compare against.
//!   3. Stay under ~500 LoC so the executor is reviewable as a unit
//!      rather than a wholesale syscall layer.
//!
//! Coverage expansion (more cases, parameterised matrices, errno
//! assertion helpers) is explicitly deferred to a follow-up issue —
//! see the `Out of scope` block in #642.
//!
//! ## Syscall ABI
//!
//! Identical to `userspace/init/src/main.rs` and
//! `userspace/repro_fork/src/main.rs`: Linux x86_64
//! (rax=nr, rdi/rsi/rdx/r10/r8/r9 = args, return in rax). Per
//! issue #531, every inline-asm syscall block declares **all** SysV
//! caller-saved GPRs as `inlateout`/`lateout` because the vibix
//! SYSRETQ path only restores `rcx` and `r11`.
//!
//! ## What "PASS" means here
//!
//! Each case is a closure returning `Result<(), TestErr>`. Pass means
//! the closure returned `Ok(())`; fail means it returned `Err` with a
//! short reason. Cases keep their own scratch namespace under
//! `/tmp/pjd-<case>/` to avoid cross-case interference. Cleanup is
//! best-effort: a failing case may leave files behind but never
//! aborts the whole run — pjdfstest's own cleanup model is the same.
//!
//! ## Why `/tmp` is the scratch root
//!
//! The deterministic ext2 image built by `xtask ext2_image` ships
//! `/tmp` as a 0755 dir owned by uid/gid 0 (see
//! `xtask/src/ext2_image.rs::run_debugfs_populate`). PID 1 here runs
//! as uid 0, so it can write into `/tmp` without setuid() games.
//! This deliberately does **not** exercise `pjdfstest`'s
//! credential-switching matrix — that's a follow-up.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

// ---------------------------------------------------------------------------
// Syscall numbers (mirrored from kernel/src/arch/x86_64/syscall.rs::syscall_nr)
// ---------------------------------------------------------------------------

const SYS_READ: u64 = 0;
const SYS_WRITE: u64 = 1;
const SYS_OPEN: u64 = 2;
const SYS_CLOSE: u64 = 3;
const SYS_LSEEK: u64 = 8;
const SYS_MKDIR: u64 = 83;
const SYS_RMDIR: u64 = 84;
const SYS_LINK: u64 = 86;
const SYS_UNLINK: u64 = 87;
const SYS_SYMLINK: u64 = 88;
const SYS_READLINK: u64 = 89;
const SYS_CHMOD: u64 = 90;
const SYS_CHDIR: u64 = 80;
const SYS_GETCWD: u64 = 79;
const SYS_GETUID: u64 = 102;
const SYS_EXIT: u64 = 60;

// open(2) flags — Linux x86_64 values, matching kernel/src/fs constants.
const O_RDONLY: i32 = 0;
const O_WRONLY: i32 = 1;
const O_RDWR: i32 = 2;
const O_CREAT: i32 = 0o100;
const O_EXCL: i32 = 0o200;
const O_TRUNC: i32 = 0o1000;

// Errno negatives we test against. Kernel returns these as -<errno>
// from the syscall return path; we negate before comparing.
const EEXIST: i64 = 17;
const ENOENT: i64 = 2;
const ENOTDIR: i64 = 20;

// ---------------------------------------------------------------------------
// Inline-asm syscall wrappers
// ---------------------------------------------------------------------------

#[inline(always)]
unsafe fn sc1(nr: u64, a0: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr => ret,
        inlateout("rdi") a0 => _,
        lateout("rcx") _,
        lateout("rdx") _,
        lateout("rsi") _,
        lateout("r8") _,
        lateout("r9") _,
        lateout("r10") _,
        lateout("r11") _,
        options(nostack),
    );
    ret
}

#[inline(always)]
unsafe fn sc2(nr: u64, a0: u64, a1: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr => ret,
        inlateout("rdi") a0 => _,
        inlateout("rsi") a1 => _,
        lateout("rcx") _,
        lateout("rdx") _,
        lateout("r8") _,
        lateout("r9") _,
        lateout("r10") _,
        lateout("r11") _,
        options(nostack),
    );
    ret
}

#[inline(always)]
unsafe fn sc3(nr: u64, a0: u64, a1: u64, a2: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr => ret,
        inlateout("rdi") a0 => _,
        inlateout("rsi") a1 => _,
        inlateout("rdx") a2 => _,
        lateout("rcx") _,
        lateout("r8") _,
        lateout("r9") _,
        lateout("r10") _,
        lateout("r11") _,
        options(nostack),
    );
    ret
}

// ---------------------------------------------------------------------------
// Thin POSIX wrappers — return raw kernel value (negative = -errno).
// ---------------------------------------------------------------------------

fn sys_write(fd: i32, buf: &[u8]) -> i64 {
    unsafe { sc3(SYS_WRITE, fd as u64, buf.as_ptr() as u64, buf.len() as u64) }
}

fn sys_read(fd: i32, buf: &mut [u8]) -> i64 {
    unsafe {
        sc3(
            SYS_READ,
            fd as u64,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
        )
    }
}

fn sys_open(path: &CStr, flags: i32, mode: u32) -> i64 {
    unsafe { sc3(SYS_OPEN, path.as_ptr() as u64, flags as u64, mode as u64) }
}

fn sys_close(fd: i32) -> i64 {
    unsafe { sc1(SYS_CLOSE, fd as u64) }
}

fn sys_mkdir(path: &CStr, mode: u32) -> i64 {
    unsafe { sc2(SYS_MKDIR, path.as_ptr() as u64, mode as u64) }
}

fn sys_rmdir(path: &CStr) -> i64 {
    unsafe { sc1(SYS_RMDIR, path.as_ptr() as u64) }
}

fn sys_unlink(path: &CStr) -> i64 {
    unsafe { sc1(SYS_UNLINK, path.as_ptr() as u64) }
}

fn sys_link(old: &CStr, new: &CStr) -> i64 {
    unsafe { sc2(SYS_LINK, old.as_ptr() as u64, new.as_ptr() as u64) }
}

fn sys_symlink(target: &CStr, linkpath: &CStr) -> i64 {
    unsafe {
        sc2(
            SYS_SYMLINK,
            target.as_ptr() as u64,
            linkpath.as_ptr() as u64,
        )
    }
}

fn sys_readlink(path: &CStr, buf: &mut [u8]) -> i64 {
    unsafe {
        sc3(
            SYS_READLINK,
            path.as_ptr() as u64,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
        )
    }
}

fn sys_chmod(path: &CStr, mode: u32) -> i64 {
    unsafe { sc2(SYS_CHMOD, path.as_ptr() as u64, mode as u64) }
}

fn sys_chdir(path: &CStr) -> i64 {
    unsafe { sc1(SYS_CHDIR, path.as_ptr() as u64) }
}

fn sys_getcwd(buf: &mut [u8]) -> i64 {
    unsafe { sc2(SYS_GETCWD, buf.as_mut_ptr() as u64, buf.len() as u64) }
}

fn sys_getuid() -> i64 {
    unsafe { sc1(SYS_GETUID, 0) }
}

fn sys_lseek(fd: i32, off: i64, whence: i32) -> i64 {
    unsafe { sc3(SYS_LSEEK, fd as u64, off as u64, whence as u64) }
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        sc1(SYS_EXIT, code as u64);
    }
    // Defensive — kernel doesn't return from EXIT.
    loop {
        core::hint::spin_loop();
    }
}

// ---------------------------------------------------------------------------
// Stack-only NUL-terminated path builder.
// ---------------------------------------------------------------------------
//
// `core::ffi::CStr` exists but constructing one from a runtime byte
// slice requires an allocator (`CString`). We're no_std + no alloc,
// so the runner uses a fixed-size on-stack buffer plus a thin slice
// wrapper that vends `*const u8`.

const PATH_MAX: usize = 256;

/// On-stack NUL-terminated path. `bytes[0..len]` are content (no NUL),
/// `bytes[len]` is `0`. `len` is < `PATH_MAX` so a trailing NUL always
/// fits.
struct CStr {
    bytes: [u8; PATH_MAX],
    len: usize,
}

impl CStr {
    /// Build from a `&[u8]` literal that does **not** contain its own
    /// NUL. Truncates at PATH_MAX-1 so the result is always
    /// NUL-terminated.
    const fn from_bytes(s: &[u8]) -> Self {
        let mut bytes = [0u8; PATH_MAX];
        let n = if s.len() < PATH_MAX - 1 {
            s.len()
        } else {
            PATH_MAX - 1
        };
        let mut i = 0;
        while i < n {
            bytes[i] = s[i];
            i += 1;
        }
        // bytes[n] is already 0 from the array initialiser.
        CStr { bytes, len: n }
    }

    fn as_ptr(&self) -> *const u8 {
        self.bytes.as_ptr()
    }
}

/// Concatenate a base path and a leaf into a fresh on-stack CStr.
/// Used so each case gets `/tmp/pjd-<case>/<leaf>` without an
/// allocator.
fn join(base: &[u8], leaf: &[u8]) -> CStr {
    let mut bytes = [0u8; PATH_MAX];
    let mut i = 0;
    while i < base.len() && i < PATH_MAX - 2 {
        bytes[i] = base[i];
        i += 1;
    }
    if i < PATH_MAX - 2 {
        bytes[i] = b'/';
        i += 1;
    }
    let mut j = 0;
    while j < leaf.len() && i < PATH_MAX - 1 {
        bytes[i] = leaf[j];
        i += 1;
        j += 1;
    }
    CStr { bytes, len: i }
}

// ---------------------------------------------------------------------------
// Marker emission
// ---------------------------------------------------------------------------

const STDOUT: i32 = 1;

/// Write a byte slice to stdout, ignoring short writes — the serial
/// backend on vibix is a single sink and either accepts the whole
/// chunk or panics, so a partial write here would mean something
/// fundamental is broken and ignoring it surfaces nothing useful.
fn write_all(buf: &[u8]) {
    let _ = sys_write(STDOUT, buf);
}

/// Format `i64` into a 24-byte stack buffer; returns the prefix length.
fn fmt_i64(n: i64, out: &mut [u8; 24]) -> usize {
    if n == 0 {
        out[0] = b'0';
        return 1;
    }
    let neg = n < 0;
    // Use absolute value via i128 so i64::MIN doesn't overflow `-n`.
    let mut x: u128 = if neg { -(n as i128) as u128 } else { n as u128 };
    let mut digits = [0u8; 24];
    let mut k = 0;
    while x > 0 {
        digits[k] = b'0' + (x % 10) as u8;
        x /= 10;
        k += 1;
    }
    let mut i = 0;
    if neg {
        out[i] = b'-';
        i += 1;
    }
    while k > 0 {
        k -= 1;
        out[i] = digits[k];
        i += 1;
    }
    i
}

/// Emit `TEST_PASS:<name>\n`.
fn emit_pass(name: &[u8]) {
    write_all(b"TEST_PASS:");
    write_all(name);
    write_all(b"\n");
}

/// Emit `TEST_FAIL:<name>:<reason> rc=<n>\n`. `rc` is the syscall
/// return value at the failure site (or 0 if the assertion was
/// content-based rather than errno-based).
fn emit_fail(name: &[u8], reason: &[u8], rc: i64) {
    write_all(b"TEST_FAIL:");
    write_all(name);
    write_all(b":");
    write_all(reason);
    write_all(b" rc=");
    let mut buf = [0u8; 24];
    let n = fmt_i64(rc, &mut buf);
    write_all(&buf[..n]);
    write_all(b"\n");
}

// ---------------------------------------------------------------------------
// Test-case glue
// ---------------------------------------------------------------------------

/// One case's failure: a static reason and the offending syscall
/// return value (for diagnostics; printed after the reason).
struct TestErr {
    reason: &'static [u8],
    rc: i64,
}

fn err(reason: &'static [u8], rc: i64) -> TestErr {
    TestErr { reason, rc }
}

/// Best-effort per-case scratch dir cleanup. Order matters — files
/// before their parent dir, ignored individually so a case that
/// already removed half its tree still cleans up.
fn cleanup_dir(dir: &CStr) {
    // We don't opendir/readdir here — every case below knows the
    // exact leaves it created. The `unlink_recursive` story is
    // future work.
    let _ = sys_rmdir(dir);
}

// Each case takes a `scratch: &CStr` (its private dir, already
// created) and returns Ok or Err. Wrapping the cases in a uniform
// signature keeps the run loop a flat array.
type CaseFn = fn(&CStr) -> Result<(), TestErr>;

struct Case {
    name: &'static [u8],
    /// Short slug used to mint `/tmp/pjd-<slug>` so two cases never
    /// race on the same path. ASCII only.
    slug: &'static [u8],
    run: CaseFn,
}

// ---------------------------------------------------------------------------
// Cases — POSIX surface assertions, hand-curated.
// ---------------------------------------------------------------------------
//
// The naming convention mirrors pjdfstest's `<op>/<assertion>` style
// so future expansion can drop into matching subtrees if/when the
// vendored runner's case definitions are mechanically translated.

/// open(O_CREAT|O_EXCL) creates a new file and returns a valid fd.
fn case_open_creat_excl(scratch: &CStr) -> Result<(), TestErr> {
    let path = join(&scratch.bytes[..scratch.len], b"newfile");
    let fd = sys_open(&path, O_RDWR | O_CREAT | O_EXCL, 0o644);
    if fd < 0 {
        return Err(err(b"open(O_CREAT|O_EXCL) failed", fd));
    }
    let close_rc = sys_close(fd as i32);
    if close_rc != 0 {
        return Err(err(b"close after create failed", close_rc));
    }
    let _ = sys_unlink(&path);
    Ok(())
}

/// open(O_CREAT|O_EXCL) on an existing file fails with -EEXIST.
fn case_open_excl_eexist(scratch: &CStr) -> Result<(), TestErr> {
    let path = join(&scratch.bytes[..scratch.len], b"exists");
    let fd = sys_open(&path, O_RDWR | O_CREAT, 0o644);
    if fd < 0 {
        return Err(err(b"first create failed", fd));
    }
    let _ = sys_close(fd as i32);
    let again = sys_open(&path, O_RDWR | O_CREAT | O_EXCL, 0o644);
    if again >= 0 {
        let _ = sys_close(again as i32);
        let _ = sys_unlink(&path);
        return Err(err(b"second create did not fail", again));
    }
    if again != -EEXIST {
        let _ = sys_unlink(&path);
        return Err(err(b"errno != EEXIST", again));
    }
    let _ = sys_unlink(&path);
    Ok(())
}

/// open() on a non-existent path without O_CREAT returns -ENOENT.
fn case_open_enoent(scratch: &CStr) -> Result<(), TestErr> {
    let path = join(&scratch.bytes[..scratch.len], b"nope");
    let fd = sys_open(&path, O_RDONLY, 0);
    if fd >= 0 {
        let _ = sys_close(fd as i32);
        return Err(err(b"open of missing file succeeded", fd));
    }
    if fd != -ENOENT {
        return Err(err(b"errno != ENOENT", fd));
    }
    Ok(())
}

/// write() then read() round-trips through a regular file.
fn case_write_read_roundtrip(scratch: &CStr) -> Result<(), TestErr> {
    let path = join(&scratch.bytes[..scratch.len], b"rw");
    let fd = sys_open(&path, O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 {
        return Err(err(b"open(O_CREAT|O_TRUNC) failed", fd));
    }
    let payload = b"vibix-pjdfstest-rw-roundtrip\n";
    let nw = sys_write(fd as i32, payload);
    if nw != payload.len() as i64 {
        let _ = sys_close(fd as i32);
        let _ = sys_unlink(&path);
        return Err(err(b"short write", nw));
    }
    // Rewind to offset 0 — write() advanced the per-fd offset.
    let off = sys_lseek(fd as i32, 0, 0 /* SEEK_SET */);
    if off != 0 {
        let _ = sys_close(fd as i32);
        let _ = sys_unlink(&path);
        return Err(err(b"lseek to 0 failed", off));
    }
    let mut buf = [0u8; 64];
    let nr = sys_read(fd as i32, &mut buf);
    if nr != payload.len() as i64 {
        let _ = sys_close(fd as i32);
        let _ = sys_unlink(&path);
        return Err(err(b"short read", nr));
    }
    if &buf[..payload.len()] != payload {
        let _ = sys_close(fd as i32);
        let _ = sys_unlink(&path);
        return Err(err(b"read content mismatch", 0));
    }
    let _ = sys_close(fd as i32);
    let _ = sys_unlink(&path);
    Ok(())
}

/// mkdir() then rmdir() round-trip.
fn case_mkdir_rmdir(scratch: &CStr) -> Result<(), TestErr> {
    let path = join(&scratch.bytes[..scratch.len], b"sub");
    let mk = sys_mkdir(&path, 0o755);
    if mk != 0 {
        return Err(err(b"mkdir failed", mk));
    }
    let rm = sys_rmdir(&path);
    if rm != 0 {
        return Err(err(b"rmdir failed", rm));
    }
    Ok(())
}

/// mkdir() on an existing path fails with -EEXIST.
fn case_mkdir_eexist(scratch: &CStr) -> Result<(), TestErr> {
    let path = join(&scratch.bytes[..scratch.len], b"dup");
    let mk1 = sys_mkdir(&path, 0o755);
    if mk1 != 0 {
        return Err(err(b"first mkdir failed", mk1));
    }
    let mk2 = sys_mkdir(&path, 0o755);
    if mk2 >= 0 {
        let _ = sys_rmdir(&path);
        return Err(err(b"second mkdir did not fail", mk2));
    }
    if mk2 != -EEXIST {
        let _ = sys_rmdir(&path);
        return Err(err(b"errno != EEXIST", mk2));
    }
    let _ = sys_rmdir(&path);
    Ok(())
}

/// rmdir() of a non-existent path fails with -ENOENT.
fn case_rmdir_enoent(scratch: &CStr) -> Result<(), TestErr> {
    let path = join(&scratch.bytes[..scratch.len], b"ghost");
    let rc = sys_rmdir(&path);
    if rc >= 0 {
        return Err(err(b"rmdir on missing dir succeeded", rc));
    }
    if rc != -ENOENT {
        return Err(err(b"errno != ENOENT", rc));
    }
    Ok(())
}

/// unlink() of a regular file removes it; subsequent open(O_RDONLY)
/// fails with -ENOENT.
fn case_unlink_removes(scratch: &CStr) -> Result<(), TestErr> {
    let path = join(&scratch.bytes[..scratch.len], b"victim");
    let fd = sys_open(&path, O_WRONLY | O_CREAT, 0o644);
    if fd < 0 {
        return Err(err(b"create victim failed", fd));
    }
    let _ = sys_close(fd as i32);
    let rc = sys_unlink(&path);
    if rc != 0 {
        return Err(err(b"unlink failed", rc));
    }
    let again = sys_open(&path, O_RDONLY, 0);
    if again >= 0 {
        let _ = sys_close(again as i32);
        return Err(err(b"path still resolvable after unlink", again));
    }
    if again != -ENOENT {
        return Err(err(b"errno != ENOENT after unlink", again));
    }
    Ok(())
}

/// link() creates a second name for an existing inode; both paths
/// resolve and unlinking one preserves the other.
fn case_link_two_names(scratch: &CStr) -> Result<(), TestErr> {
    let a = join(&scratch.bytes[..scratch.len], b"a");
    let b = join(&scratch.bytes[..scratch.len], b"b");
    let fd = sys_open(&a, O_WRONLY | O_CREAT, 0o644);
    if fd < 0 {
        return Err(err(b"create a failed", fd));
    }
    let _ = sys_close(fd as i32);
    let lk = sys_link(&a, &b);
    if lk != 0 {
        let _ = sys_unlink(&a);
        return Err(err(b"link(a,b) failed", lk));
    }
    let rm_a = sys_unlink(&a);
    if rm_a != 0 {
        let _ = sys_unlink(&b);
        return Err(err(b"unlink(a) failed", rm_a));
    }
    // b should still resolve.
    let fd2 = sys_open(&b, O_RDONLY, 0);
    if fd2 < 0 {
        return Err(err(b"open(b) after unlink(a) failed", fd2));
    }
    let _ = sys_close(fd2 as i32);
    let _ = sys_unlink(&b);
    Ok(())
}

/// symlink() + readlink() round-trip the link target bytes verbatim.
fn case_symlink_readlink(scratch: &CStr) -> Result<(), TestErr> {
    let link = join(&scratch.bytes[..scratch.len], b"sl");
    // Target is an arbitrary string — pjdfstest's symlink cases assert
    // that the byte sequence is preserved, not that the target exists.
    let target_bytes: &[u8] = b"/some/where";
    let target = CStr::from_bytes(target_bytes);
    let sl = sys_symlink(&target, &link);
    if sl != 0 {
        return Err(err(b"symlink failed", sl));
    }
    let mut buf = [0u8; 64];
    let n = sys_readlink(&link, &mut buf);
    if n < 0 {
        let _ = sys_unlink(&link);
        return Err(err(b"readlink failed", n));
    }
    if n as usize != target_bytes.len() {
        let _ = sys_unlink(&link);
        return Err(err(b"readlink length mismatch", n));
    }
    if &buf[..n as usize] != target_bytes {
        let _ = sys_unlink(&link);
        return Err(err(b"readlink content mismatch", 0));
    }
    let _ = sys_unlink(&link);
    Ok(())
}

/// chmod() updates the file mode bits; the change is observable via
/// open() succeeding/failing accordingly. We don't have stat() in the
/// runner so we settle for "chmod returned 0" — coverage of the bit
/// readback is deferred to the follow-up matrix.
fn case_chmod_returns_ok(scratch: &CStr) -> Result<(), TestErr> {
    let path = join(&scratch.bytes[..scratch.len], b"chm");
    let fd = sys_open(&path, O_WRONLY | O_CREAT, 0o644);
    if fd < 0 {
        return Err(err(b"create failed", fd));
    }
    let _ = sys_close(fd as i32);
    let rc = sys_chmod(&path, 0o600);
    if rc != 0 {
        let _ = sys_unlink(&path);
        return Err(err(b"chmod failed", rc));
    }
    let _ = sys_unlink(&path);
    Ok(())
}

/// chdir() into the scratch dir and getcwd() returns that path. This
/// also implicitly proves /tmp/pjd-<slug> resolves to the inode chdir
/// just walked into.
fn case_chdir_getcwd(scratch: &CStr) -> Result<(), TestErr> {
    let cd = sys_chdir(scratch);
    if cd != 0 {
        return Err(err(b"chdir failed", cd));
    }
    let mut buf = [0u8; 256];
    let n = sys_getcwd(&mut buf);
    if n <= 0 {
        return Err(err(b"getcwd failed", n));
    }
    // Linux's getcwd returns the length including the trailing NUL.
    let len = if buf[(n as usize).saturating_sub(1)] == 0 {
        (n as usize) - 1
    } else {
        n as usize
    };
    if &buf[..len] != &scratch.bytes[..scratch.len] {
        return Err(err(b"getcwd path mismatch", n));
    }
    // Restore cwd to root so subsequent cases with absolute paths
    // still work the same way regardless of order.
    let root = CStr::from_bytes(b"/");
    let _ = sys_chdir(&root);
    Ok(())
}

/// rmdir() on a regular file fails with -ENOTDIR.
fn case_rmdir_enotdir(scratch: &CStr) -> Result<(), TestErr> {
    let path = join(&scratch.bytes[..scratch.len], b"reg");
    let fd = sys_open(&path, O_WRONLY | O_CREAT, 0o644);
    if fd < 0 {
        return Err(err(b"create failed", fd));
    }
    let _ = sys_close(fd as i32);
    let rc = sys_rmdir(&path);
    if rc >= 0 {
        let _ = sys_unlink(&path);
        return Err(err(b"rmdir on regular file succeeded", rc));
    }
    if rc != -ENOTDIR {
        let _ = sys_unlink(&path);
        return Err(err(b"errno != ENOTDIR", rc));
    }
    let _ = sys_unlink(&path);
    Ok(())
}

/// getuid() in PID 1 of a fresh boot is 0 (the kernel-init creds).
/// Trivial smoke that the credential plumbing #547 / #660 isn't
/// returning -ENOSYS or junk.
fn case_getuid_root(_scratch: &CStr) -> Result<(), TestErr> {
    let uid = sys_getuid();
    if uid != 0 {
        return Err(err(b"uid != 0", uid));
    }
    Ok(())
}

const CASES: &[Case] = &[
    Case {
        name: b"open/creat_excl_creates",
        slug: b"openc",
        run: case_open_creat_excl,
    },
    Case {
        name: b"open/excl_eexist",
        slug: b"opene",
        run: case_open_excl_eexist,
    },
    Case {
        name: b"open/enoent",
        slug: b"openn",
        run: case_open_enoent,
    },
    Case {
        name: b"rw/write_read_roundtrip",
        slug: b"rwrt",
        run: case_write_read_roundtrip,
    },
    Case {
        name: b"mkdir/rmdir_roundtrip",
        slug: b"mkrm",
        run: case_mkdir_rmdir,
    },
    Case {
        name: b"mkdir/eexist",
        slug: b"mkex",
        run: case_mkdir_eexist,
    },
    Case {
        name: b"rmdir/enoent",
        slug: b"rmne",
        run: case_rmdir_enoent,
    },
    Case {
        name: b"unlink/removes_path",
        slug: b"unrm",
        run: case_unlink_removes,
    },
    Case {
        name: b"link/two_names_share_inode",
        slug: b"lk2n",
        run: case_link_two_names,
    },
    Case {
        name: b"symlink/readlink_roundtrip",
        slug: b"slrl",
        run: case_symlink_readlink,
    },
    Case {
        name: b"chmod/returns_ok",
        slug: b"chmd",
        run: case_chmod_returns_ok,
    },
    Case {
        name: b"chdir/getcwd_roundtrip",
        slug: b"cdcw",
        run: case_chdir_getcwd,
    },
    Case {
        name: b"rmdir/enotdir_on_regular",
        slug: b"rmrt",
        run: case_rmdir_enotdir,
    },
    Case {
        name: b"getuid/init_is_root",
        slug: b"guid",
        run: case_getuid_root,
    },
];

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

const TMP_PREFIX: &[u8] = b"/tmp/pjd-";

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Banner — useful when reading raw serial captures by hand.
    write_all(b"pjdfstest_runner: starting (no_std executor #642)\n");

    // Run each case with its own scratch dir. The dir is created
    // before the case runs and rmdir'd after — best-effort, so a
    // case that leaves files behind reports as a follow-up cleanup
    // failure rather than corrupting the next case.
    for c in CASES {
        let scratch = build_scratch(c.slug);

        // Create the scratch dir. Any error here is reported as a
        // case failure with reason "setup" so the harness still
        // sees a marker.
        let mk = sys_mkdir(&scratch, 0o755);
        if mk != 0 && mk != -EEXIST {
            emit_fail(c.name, b"scratch mkdir failed", mk);
            continue;
        }

        match (c.run)(&scratch) {
            Ok(()) => emit_pass(c.name),
            Err(e) => emit_fail(c.name, e.reason, e.rc),
        }

        cleanup_dir(&scratch);
    }

    // Sentinel that lets the xtask short-circuit its watchdog. Must
    // appear AFTER all per-case markers so the harness's transcript
    // already has the full result set when it stops capturing.
    write_all(b"TEST_DONE\n");

    // Exit cleanly. PID 1 exiting on vibix today does not auto-shutdown
    // QEMU — the harness's HARD_CAP / TEST_DONE-short-circuit paths
    // both handle that. A loop-forever fallback would needlessly
    // burn the watchdog's full budget on every run.
    sys_exit(0);
}

fn build_scratch(slug: &[u8]) -> CStr {
    // /tmp/pjd-<slug>
    let mut bytes = [0u8; PATH_MAX];
    let mut i = 0;
    while i < TMP_PREFIX.len() {
        bytes[i] = TMP_PREFIX[i];
        i += 1;
    }
    let mut j = 0;
    while j < slug.len() && i < PATH_MAX - 1 {
        bytes[i] = slug[j];
        i += 1;
        j += 1;
    }
    CStr { bytes, len: i }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_all(b"pjdfstest_runner: PANIC\n");
    sys_exit(127);
}
