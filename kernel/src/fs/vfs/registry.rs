//! Filesystem-type registry — bind fstype string → factory closure.
//!
//! `mount(2)` accepts an `fstype` argument by *name* (e.g. `"ext2"`,
//! `"ramfs"`, `"tmpfs"`, `"devfs"`, `"tarfs"`). The VFS needs a way to
//! turn that string into an `Arc<dyn FileSystem>` at runtime without
//! hard-coding every fstype into the syscall entry point.
//!
//! ## Shape
//!
//! The registry is a small `Vec<Entry>` protected by a blocking
//! `BlockingRwLock`. Linear scan is fine — RFC 0004 §Mount API caps the
//! live fstype count in v1 at a handful (ramfs, tmpfs, devfs, tarfs,
//! ext2). Registration is idempotent on name: a second `register_filesystem`
//! with the same name replaces the previous factory.
//!
//! ## Factory signature
//!
//! A factory is an `Fn(MountSource<'_>) -> Result<Arc<dyn FileSystem>, i64>`.
//! It receives the mount source so fstypes that need backing state at
//! construction time (ext2 wants a block device) can reach for it;
//! pseudo-filesystems that ignore the source simply discard it.
//!
//! Factories run **before** `FileSystem::mount` — a factory returning
//! `ENODEV` is how "no block device found for this source" surfaces
//! through the `mount(2)` syscall.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::ops::{FileSystem, MountSource};
use crate::sync::BlockingRwLock;

/// A factory closure producing an `Arc<dyn FileSystem>` from a
/// [`MountSource`]. Boxed so the registry can own heterogeneous
/// closures behind a single vector.
pub type FsFactory =
    Box<dyn Fn(MountSource<'_>) -> Result<Arc<dyn FileSystem>, i64> + Send + Sync + 'static>;

struct Entry {
    name: String,
    factory: FsFactory,
}

static REGISTRY: BlockingRwLock<Vec<Entry>> = BlockingRwLock::new(Vec::new());

/// Register `factory` under the fstype name `name`. Idempotent: a second
/// registration for the same name replaces the earlier factory. Called
/// from each driver's boot-time init (ramfs/devfs/tarfs/ext2).
pub fn register_filesystem(name: &str, factory: FsFactory) {
    let mut table = REGISTRY.write();
    if let Some(slot) = table.iter_mut().find(|e| e.name == name) {
        slot.factory = factory;
        return;
    }
    table.push(Entry {
        name: name.to_string(),
        factory,
    });
}

/// Resolve an fstype name to a fresh `Arc<dyn FileSystem>` for a new
/// mount. Returns `EINVAL` if the name is not registered (matches
/// Linux's `mount(2)` error for unknown fstypes); otherwise returns
/// whatever the factory returns (including `ENODEV` if the source
/// couldn't be resolved).
pub fn lookup_and_build(name: &str, source: MountSource<'_>) -> Result<Arc<dyn FileSystem>, i64> {
    let table = REGISTRY.read();
    let entry = table
        .iter()
        .find(|e| e.name == name)
        .ok_or(crate::fs::EINVAL)?;
    (entry.factory)(source)
}

/// Test-only: clear the registry. Integration tests register their own
/// fstypes against a fresh state.
#[cfg(test)]
pub(crate) fn reset_for_tests() {
    REGISTRY.write().clear();
}

/// Return `true` if `name` is currently registered. Used by the
/// `mount(2)` syscall path for an early `EINVAL` *before* any path
/// walk, so a bad fstype fails without allocating walk state.
pub fn is_registered(name: &str) -> bool {
    REGISTRY.read().iter().any(|e| e.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::vfs::super_block::{SbFlags, SuperBlock};
    use crate::fs::vfs::{alloc_fs_id, MountFlags};
    use spin::Mutex;

    /// Integration-ordered registry tests mutate global state; serialise.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    struct StubFs {
        name: &'static str,
    }
    impl FileSystem for StubFs {
        fn name(&self) -> &'static str {
            self.name
        }
        fn mount(&self, _src: MountSource<'_>, _flags: MountFlags) -> Result<Arc<SuperBlock>, i64> {
            Err(crate::fs::EINVAL)
        }
    }

    struct StubSuper;
    impl crate::fs::vfs::ops::SuperOps for StubSuper {
        fn root_inode(&self) -> Arc<crate::fs::vfs::Inode> {
            unreachable!()
        }
        fn statfs(&self) -> Result<crate::fs::vfs::StatFs, i64> {
            Ok(Default::default())
        }
        fn unmount(&self) {}
    }

    fn make_stub_sb() -> Arc<SuperBlock> {
        Arc::new(SuperBlock::new(
            alloc_fs_id(),
            Arc::new(StubSuper),
            "stub",
            512,
            SbFlags::default(),
        ))
    }

    #[test]
    fn register_and_lookup_round_trip() {
        let _g = TEST_LOCK.lock();
        reset_for_tests();
        register_filesystem(
            "stub",
            Box::new(|_src| Ok(Arc::new(StubFs { name: "stub" }) as Arc<dyn FileSystem>)),
        );
        let fs = lookup_and_build("stub", MountSource::None).expect("registered");
        assert_eq!(fs.name(), "stub");
        assert!(is_registered("stub"));
    }

    #[test]
    fn unknown_fstype_returns_einval() {
        let _g = TEST_LOCK.lock();
        reset_for_tests();
        let r = lookup_and_build("nosuch", MountSource::None);
        assert_eq!(r.err(), Some(crate::fs::EINVAL));
        assert!(!is_registered("nosuch"));
    }

    #[test]
    fn reregistration_replaces_previous_factory() {
        let _g = TEST_LOCK.lock();
        reset_for_tests();
        register_filesystem(
            "replaceme",
            Box::new(|_src| Ok(Arc::new(StubFs { name: "first" }) as Arc<dyn FileSystem>)),
        );
        register_filesystem(
            "replaceme",
            Box::new(|_src| Ok(Arc::new(StubFs { name: "second" }) as Arc<dyn FileSystem>)),
        );
        let fs = lookup_and_build("replaceme", MountSource::None).expect("registered");
        assert_eq!(fs.name(), "second");
    }

    #[test]
    fn factory_error_propagates() {
        let _g = TEST_LOCK.lock();
        reset_for_tests();
        register_filesystem("enodev", Box::new(|_src| Err(crate::fs::ENODEV)));
        let r = lookup_and_build("enodev", MountSource::None);
        assert_eq!(r.err(), Some(crate::fs::ENODEV));
    }

    // Silence unused import warning when `make_stub_sb` is not needed
    // for every test; keep it around for future follow-ups.
    #[allow(dead_code)]
    fn _touch_sb(sb: Arc<SuperBlock>) {
        drop(sb);
    }

    #[test]
    fn make_stub_sb_produces_live_sb() {
        let _g = TEST_LOCK.lock();
        let sb = make_stub_sb();
        assert_eq!(sb.fs_type, "stub");
    }
}
