//! Directory: `linux/`
//!
//! <https://github.com/torvalds/linux/tree/master/include/uapi/linux>

#[cfg(not(target_os = "vibix"))]
pub(crate) mod can;
pub(crate) mod keyctl;
pub(crate) mod membarrier;
pub(crate) mod netlink;
#[cfg(not(target_os = "vibix"))]
pub(crate) mod pidfd;
