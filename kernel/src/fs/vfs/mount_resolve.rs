//! `mount(2)` source-path → block-device resolver.
//!
//! When userspace calls `mount("/dev/vda", "/mnt", "ext2", …)` the VFS
//! must turn the source path into a concrete `Arc<dyn BlockDevice>`
//! before the ext2 factory can produce a `FileSystem`. This module
//! owns that translation:
//!
//! 1. Walk the namespace from the global root with kernel credentials
//!    (the caller has already passed the `mount(2)` superuser gate).
//! 2. Confirm the resolved inode is `InodeKind::Blk` — anything else
//!    is `-ENOTDIR`-like nonsense for a mount source and surfaces as
//!    `-ENODEV`.
//! 3. Pull the backing handle via [`InodeOps::block_device`]; an inode
//!    that is `Blk` but doesn't carry a handle is a driver bug, also
//!    `-ENODEV`.
//!
//! Errors are deliberately collapsed onto `-ENODEV` for any failure
//! after the initial path-walk error — Linux's `mount(2)` reports
//! `ENOTBLK` for "not a block device" but vibix's errno set doesn't
//! carry that variant and the issue specifies `-ENODEV` as the single
//! catch-all for "source did not resolve to a usable block device."

use alloc::sync::Arc;

use super::mount_table::GlobalMountResolver;
use super::path_walk::{path_walk, LookupFlags, NameIdata};
use super::{root as vfs_root, Credential, InodeKind};
use crate::block::BlockDevice;
use crate::fs::ENODEV;

/// Resolve a `/dev/<name>`-style source path to its backing
/// [`BlockDevice`]. Returns `-ENOENT` when the path doesn't exist,
/// `-ENODEV` when it exists but is not a block-device inode (or the
/// inode's driver returns no handle).
///
/// The walk uses the kernel-internal credential so any mount(2) caller
/// that survived the `euid==0` gate gets through here regardless of
/// the per-component DAC bits — same posture as the rest of the
/// `mount(2)` implementation, which trusts the syscall-layer cred
/// check it already performed.
pub fn resolve_block_device(path: &[u8]) -> Result<Arc<dyn BlockDevice>, i64> {
    let root = vfs_root().ok_or(ENODEV)?;
    let mut nd = NameIdata::new(
        root.clone(),
        root,
        Credential::kernel(),
        LookupFlags::default() | LookupFlags::FOLLOW,
    )?;
    path_walk(&mut nd, path, &GlobalMountResolver)?;

    let inode_slot = nd.path.dentry.inode.read();
    let inode = inode_slot.as_ref().ok_or(ENODEV)?;
    if inode.kind != InodeKind::Blk {
        return Err(ENODEV);
    }
    inode.ops.block_device().ok_or(ENODEV)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{BlockDevice, BlockError};
    use crate::fs::vfs::devfs::{register_block_device, reset_block_device_registry_for_tests};
    use crate::fs::ENOENT;
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;
    use spin::Mutex;

    /// Minimal in-memory block device for the resolver tests. Not
    /// shared with `block::tests::RamBlockDevice` to avoid coupling
    /// that helper's visibility to this module.
    struct RamBlk {
        bs: u32,
        cap: u64,
        storage: Mutex<Vec<u8>>,
    }

    impl RamBlk {
        fn new(bs: u32, blocks: usize) -> Arc<Self> {
            Arc::new(Self {
                bs,
                cap: (bs as u64) * blocks as u64,
                storage: Mutex::new(vec![0u8; bs as usize * blocks]),
            })
        }
    }

    impl BlockDevice for RamBlk {
        fn read_at(&self, _o: u64, _b: &mut [u8]) -> Result<(), BlockError> {
            Ok(())
        }
        fn write_at(&self, _o: u64, _b: &[u8]) -> Result<(), BlockError> {
            Ok(())
        }
        fn block_size(&self) -> u32 {
            self.bs
        }
        fn capacity(&self) -> u64 {
            self.cap
        }
    }

    /// vfs::init is process-global; the resolver tests share that
    /// state with every other `init()` caller. Serialise on the same
    /// pattern the rest of the suite uses.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn resolves_registered_dev_path() {
        let _g = TEST_LOCK.lock();
        crate::fs::vfs::init::init();
        reset_block_device_registry_for_tests();
        let dev = RamBlk::new(512, 8);
        register_block_device("ramblk0", dev.clone() as Arc<dyn BlockDevice>);

        let resolved = resolve_block_device(b"/dev/ramblk0").expect("resolve registered device");
        assert!(Arc::ptr_eq(
            &(resolved as Arc<dyn BlockDevice>),
            &(dev as Arc<dyn BlockDevice>),
        ));
    }

    #[test]
    fn missing_path_returns_enoent() {
        let _g = TEST_LOCK.lock();
        crate::fs::vfs::init::init();
        reset_block_device_registry_for_tests();
        let r = resolve_block_device(b"/dev/nonexistent");
        assert_eq!(r.err(), Some(ENOENT));
    }

    #[test]
    fn non_block_path_returns_enodev() {
        // `/dev/null` exists but is a character device, not a block
        // device — must surface as ENODEV per the issue spec.
        let _g = TEST_LOCK.lock();
        crate::fs::vfs::init::init();
        reset_block_device_registry_for_tests();
        let r = resolve_block_device(b"/dev/null");
        assert_eq!(r.err(), Some(ENODEV));
    }
}
