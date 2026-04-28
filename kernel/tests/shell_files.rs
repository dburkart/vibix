//! Integration test: file-touching shell builtins (#395).
//!
//! Boots the kernel, runs each new builtin (`cd`, `pwd`, `ls`, `cat`,
//! `mkdir`, `rmdir`, `rm`, `touch`, `mv`, `cp`, `stat`) through
//! `dispatch_for_test`, and asserts the side-effects via direct VFS
//! observation rather than serial loopback. Serial loopback would be
//! ideal but every command's printed output is too long for the 16-byte
//! 16550 RX FIFO that `shell_introspection` relies on; we follow the
//! `shell_help` convention of "verify behaviour by side-effect, not
//! captured stdout" for the larger commands.
//!
//! Coverage:
//! - `pwd` / `cd` / `cd ..` round-trip leaves the task at root.
//! - `mkdir` + `ls` + `rmdir` of a fresh directory under `/tmp`.
//! - `touch` + `stat` + `rm` of a regular file under `/tmp`.
//! - `cp` copies file contents from `/tmp/src` to `/tmp/dst`.
//! - `mv` renames a file under `/tmp`.
//! - `cat` of `/tmp/<file>` after `cp` (smoke; reads via VFS to verify).
//! - `ls /dev` does not panic and contains at least one entry.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::panic::PanicInfo;

use vibix::{
    exit_qemu, serial_println,
    shell::{dispatch_for_test, vfs_helpers},
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    // The shell's `cd` builtin updates per-task CWD via
    // `task::set_current_cwd`, which is a no-op when no task is
    // installed as `current`. Install the bootstrap task so the test
    // runs under a real scheduler context — same approach as
    // `shell_smoke`.
    vibix::task::init();
    x86_64::instructions::interrupts::enable();
    run_tests();
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info)
}

fn run_tests() {
    let tests: &[(&str, &dyn Testable)] = &[
        ("pwd_and_cd_roundtrip", &(pwd_and_cd_roundtrip as fn())),
        ("mkdir_then_rmdir", &(mkdir_then_rmdir as fn())),
        ("touch_stat_rm", &(touch_stat_rm as fn())),
        ("cp_roundtrip", &(cp_roundtrip as fn())),
        ("mv_renames", &(mv_renames as fn())),
        ("cat_smokes", &(cat_smokes as fn())),
        ("ls_dev", &(ls_dev as fn())),
        ("cd_nonexistent_errors", &(cd_nonexistent_errors as fn())),
        ("rmdir_nonempty_errors", &(rmdir_nonempty_errors as fn())),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

/// Resolve a path and return whether it exists.
fn exists(path: &[u8]) -> bool {
    vfs_helpers::resolve(path, true).is_ok()
}

fn read_to_string(path: &[u8]) -> Option<Vec<u8>> {
    vfs_helpers::read_all(path).ok()
}

fn pwd_and_cd_roundtrip() {
    // Reset to root so we have a known starting point.
    dispatch_for_test("cd /");
    dispatch_for_test("pwd");
    // Move to /tmp (always a ramfs mount per vfs/init.rs).
    dispatch_for_test("cd /tmp");
    let cwd = vibix::task::current_cwd().expect("cwd set after cd /tmp");
    let path = vfs_helpers::dentry_path(&cwd);
    assert_eq!(path, "/tmp", "cd /tmp must move CWD; got {:?}", path);
    // .. back to root.
    dispatch_for_test("cd ..");
    let cwd2 = vibix::task::current_cwd().expect("cwd set after cd ..");
    let p2 = vfs_helpers::dentry_path(&cwd2);
    assert_eq!(p2, "/", "cd .. from /tmp must land at /; got {:?}", p2);
}

fn mkdir_then_rmdir() {
    dispatch_for_test("cd /");
    let dir: &str = "/tmp/shell_test_mkdir";
    // Pre-clean from any prior test partial run.
    let _ = vfs_helpers::rmdir(dir.as_bytes());
    dispatch_for_test("mkdir /tmp/shell_test_mkdir");
    assert!(exists(dir.as_bytes()), "mkdir should have created {}", dir);
    // ls of /tmp should now mention shell_test_mkdir; we verify via
    // direct getdents rather than serial capture.
    let r = vfs_helpers::resolve(b"/tmp", true).expect("/tmp resolves");
    let mut found = false;
    let _ = vfs_helpers::for_each_dirent(&r.inode, &r.dentry, |name, _kind| {
        if name == b"shell_test_mkdir" {
            found = true;
            return false;
        }
        true
    });
    assert!(found, "shell_test_mkdir missing from /tmp listing");
    dispatch_for_test("rmdir /tmp/shell_test_mkdir");
    assert!(!exists(dir.as_bytes()), "rmdir should have removed {}", dir);
}

fn touch_stat_rm() {
    dispatch_for_test("cd /");
    let path: &str = "/tmp/shell_test_touch";
    let _ = vfs_helpers::unlink(path.as_bytes());
    dispatch_for_test("touch /tmp/shell_test_touch");
    assert!(
        exists(path.as_bytes()),
        "touch should have created {}",
        path
    );
    // stat: just exercise the dispatch path; output goes to serial.
    dispatch_for_test("stat /tmp/shell_test_touch");
    dispatch_for_test("rm /tmp/shell_test_touch");
    assert!(!exists(path.as_bytes()), "rm should have removed {}", path);
}

fn cp_roundtrip() {
    dispatch_for_test("cd /");
    let src: &str = "/tmp/shell_test_src";
    let dst: &str = "/tmp/shell_test_dst";
    let _ = vfs_helpers::unlink(src.as_bytes());
    let _ = vfs_helpers::unlink(dst.as_bytes());
    // Seed src directly through the VFS helper (the shell has no
    // `echo > file` redirection yet).
    vfs_helpers::write_all(src.as_bytes(), b"hello-cp\n").expect("seed src");
    dispatch_for_test("cp /tmp/shell_test_src /tmp/shell_test_dst");
    let dst_bytes = read_to_string(dst.as_bytes()).expect("dst readable after cp");
    assert_eq!(
        &dst_bytes[..],
        b"hello-cp\n",
        "cp must copy contents byte-for-byte"
    );
    let _ = vfs_helpers::unlink(src.as_bytes());
    let _ = vfs_helpers::unlink(dst.as_bytes());
}

fn mv_renames() {
    dispatch_for_test("cd /");
    let src: &str = "/tmp/shell_test_mv_src";
    let dst: &str = "/tmp/shell_test_mv_dst";
    let _ = vfs_helpers::unlink(src.as_bytes());
    let _ = vfs_helpers::unlink(dst.as_bytes());
    vfs_helpers::write_all(src.as_bytes(), b"renameme\n").expect("seed mv src");
    dispatch_for_test("mv /tmp/shell_test_mv_src /tmp/shell_test_mv_dst");
    assert!(!exists(src.as_bytes()), "mv must remove source");
    let dst_bytes = read_to_string(dst.as_bytes()).expect("dst readable after mv");
    assert_eq!(&dst_bytes[..], b"renameme\n", "mv must preserve contents");
    let _ = vfs_helpers::unlink(dst.as_bytes());
}

fn cat_smokes() {
    dispatch_for_test("cd /");
    let path: &str = "/tmp/shell_test_cat";
    let _ = vfs_helpers::unlink(path.as_bytes());
    vfs_helpers::write_all(path.as_bytes(), b"one\ntwo\n").expect("seed cat target");
    // Smoke: cat must dispatch without panicking. Output goes to
    // serial; we confirm post-conditions on the file haven't changed.
    dispatch_for_test("cat /tmp/shell_test_cat");
    let bytes = read_to_string(path.as_bytes()).expect("cat must not modify file");
    assert_eq!(&bytes[..], b"one\ntwo\n");
    let _ = vfs_helpers::unlink(path.as_bytes());
}

fn ls_dev() {
    dispatch_for_test("cd /");
    // Just ensure ls /dev dispatches and the directory itself contains
    // at least the canonical "." / ".." pair plus one device.
    dispatch_for_test("ls /dev");
    let r = vfs_helpers::resolve(b"/dev", true).expect("/dev resolves");
    let mut count = 0usize;
    let _ = vfs_helpers::for_each_dirent(&r.inode, &r.dentry, |_name, _kind| {
        count += 1;
        true
    });
    assert!(count >= 2, "/dev should have at least . and ..");
}

fn cd_nonexistent_errors() {
    dispatch_for_test("cd /");
    // Should print an error but not panic, and CWD should stay at /.
    dispatch_for_test("cd /no/such/dir");
    let cwd = vibix::task::current_cwd().expect("cwd preserved");
    let p = vfs_helpers::dentry_path(&cwd);
    assert_eq!(p, "/", "failed cd must not move the CWD; got {:?}", p);
}

fn rmdir_nonempty_errors() {
    dispatch_for_test("cd /");
    let parent: &str = "/tmp/shell_test_nonempty";
    let child: &str = "/tmp/shell_test_nonempty/child";
    let _ = vfs_helpers::unlink(child.as_bytes());
    let _ = vfs_helpers::rmdir(parent.as_bytes());
    vfs_helpers::mkdir(parent.as_bytes(), 0o755).expect("mk parent");
    vfs_helpers::create_file(child.as_bytes(), 0o644).expect("mk child");
    dispatch_for_test("rmdir /tmp/shell_test_nonempty");
    assert!(exists(parent.as_bytes()), "rmdir must refuse non-empty dir");
    // Cleanup.
    let _ = vfs_helpers::unlink(child.as_bytes());
    let _ = vfs_helpers::rmdir(parent.as_bytes());
}

// Silence unused warnings in case rustc disagrees about `String` usage.
#[allow(dead_code)]
fn _string_unused(_s: String) {}
