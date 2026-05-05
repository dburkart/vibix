//! Compatibility shims for vibix (which lacks std::os::unix).

#[cfg(target_os = "vibix")]
pub fn symlink<P: AsRef<std::path::Path>, Q: AsRef<std::path::Path>>(
    original: P,
    link: Q,
) -> std::io::Result<()> {
    // std::fs::symlink is available on vibix through the sys layer
    crate::__std_symlink(original.as_ref(), link.as_ref())
}
