//! Error decoding for vibix (Linux-compatible errno values).

use crate::io;

pub fn errno() -> i32 {
    // vibix uses TLS errno via vibix_abi.
    vibix_abi::errno::get_errno()
}

#[inline]
pub fn is_interrupted(errno: i32) -> bool {
    errno == 4 // EINTR
}

pub fn decode_error_kind(errno: i32) -> io::ErrorKind {
    // Linux errno values used by vibix.
    match errno {
        1 => io::ErrorKind::PermissionDenied,   // EPERM
        2 => io::ErrorKind::NotFound,           // ENOENT
        4 => io::ErrorKind::Interrupted,        // EINTR
        9 => io::ErrorKind::Other,              // EBADF
        11 => io::ErrorKind::WouldBlock,        // EAGAIN
        12 => io::ErrorKind::OutOfMemory,       // ENOMEM
        13 => io::ErrorKind::PermissionDenied,  // EACCES
        17 => io::ErrorKind::AlreadyExists,     // EEXIST
        20 => io::ErrorKind::Other,             // ENOTDIR
        21 => io::ErrorKind::Other,             // EISDIR
        22 => io::ErrorKind::InvalidInput,      // EINVAL
        28 => io::ErrorKind::Other,             // ENOSPC
        32 => io::ErrorKind::BrokenPipe,        // EPIPE
        95 => io::ErrorKind::Unsupported,       // EOPNOTSUPP
        98 => io::ErrorKind::AddrInUse,         // EADDRINUSE
        99 => io::ErrorKind::AddrNotAvailable,  // EADDRNOTAVAIL
        103 => io::ErrorKind::ConnectionAborted, // ECONNABORTED
        104 => io::ErrorKind::ConnectionReset,  // ECONNRESET
        107 => io::ErrorKind::NotConnected,     // ENOTCONN
        110 => io::ErrorKind::TimedOut,         // ETIMEDOUT
        111 => io::ErrorKind::ConnectionRefused, // ECONNREFUSED
        _ => io::ErrorKind::Uncategorized,
    }
}

pub fn error_string(errno: i32) -> String {
    // Minimal error string table for vibix.
    let s = match errno {
        1 => "Operation not permitted",
        2 => "No such file or directory",
        4 => "Interrupted system call",
        9 => "Bad file descriptor",
        11 => "Resource temporarily unavailable",
        12 => "Cannot allocate memory",
        13 => "Permission denied",
        17 => "File exists",
        20 => "Not a directory",
        21 => "Is a directory",
        22 => "Invalid argument",
        28 => "No space left on device",
        32 => "Broken pipe",
        95 => "Operation not supported",
        _ => "Unknown error",
    };
    s.to_string()
}
