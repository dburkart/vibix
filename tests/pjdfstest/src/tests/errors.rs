//! Helper functions for testing error handling.

pub(super) mod eexist;
pub(super) mod efault;
pub(super) mod eloop;
pub(super) mod enametoolong;
pub(super) mod enoent;
pub(super) mod enotdir;
pub(super) mod erofs;
// etxtbsy: stripped — vibix has no ETXTBSY semantics (no dynamic-exec write protection).
pub(super) mod exdev;
