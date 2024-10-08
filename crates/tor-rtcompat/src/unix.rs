//! Definitions related to unix socket support.
//!
//! To avoid confusion, don't import `SocketAddr` from this module directly;
//! instead, import the module and refer to `unix::SocketAddr`.

#[cfg(not(unix))]
use std::path::Path;

#[cfg(unix)]
pub use std::os::unix::net::SocketAddr;

/// Helper: construct an unnamed SocketAddr.
#[cfg(unix)]
pub(crate) fn new_unnamed_socketaddr() -> std::io::Result<SocketAddr> {
    // There SHOULD be a better way to do this in legitimate Rust!
    // But sadly, there isn't.
    SocketAddr::from_pathname("")
}

/// Address for an AF_UNIX socket.
///
/// (This is an uninhabited placeholder implementations for platforms without AF_UNIX support.)
///
/// Note that we currently include Windows on platforms without AF_UNIX support:
/// When we use Unix sockets in Arti, we rely on their filesystem-based security properties,
/// which we haven't yet had a chance to fully analyze on non-Unix platforms.
#[cfg(not(unix))]
#[derive(Debug, Clone)]
pub struct SocketAddr(void::Void);

#[cfg(not(unix))]
impl SocketAddr {
    /// Return true if this is an "unnamed" socket address.
    ///
    /// (Because this type is uninhabited, this method cannot actually be called.)
    pub fn is_unnamed(&self) -> bool {
        void::unreachable(self.0)
    }
    /// Return the pathname for this socket address, if it is "named".
    ///
    /// (Because this type is uninhabited, this method cannot actually be called.)
    pub fn as_pathname(&self) -> Option<&Path> {
        void::unreachable(self.0)
    }
    /// Attempt to construct an AF_UNIX socket address from the provided `path`.
    ///
    /// (Because this platform lacks AF_UNIX support, this method will always return an error.)
    pub fn from_pathname<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let _ = path;
        Err(NoUnixAddressSupport.into())
    }
}

/// Error: Unix addresses are not supported on this platform.
#[derive(Clone, Debug, Default, thiserror::Error)]
#[error("No support for AF_UNIX addresses on this platform")]
#[non_exhaustive]
pub struct NoUnixAddressSupport;

impl From<NoUnixAddressSupport> for std::io::Error {
    fn from(value: NoUnixAddressSupport) -> Self {
        std::io::Error::new(std::io::ErrorKind::Unsupported, value)
    }
}

/// Error: Tried to perform an operation on an unsupported kind of unix address.
///
/// (For example, you can't bind or connect to an unnamed address.)
#[derive(Clone, Debug, thiserror::Error)]
#[error("Operation not supported on this kind of AF_UNIX address")]
#[non_exhaustive]
pub struct UnsupportedUnixAddressType;

impl From<UnsupportedUnixAddressType> for std::io::Error {
    fn from(value: UnsupportedUnixAddressType) -> Self {
        std::io::Error::new(std::io::ErrorKind::Unsupported, value)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn unnamed() {
        let u = new_unnamed_socketaddr().expect("couldn't construct unnamed unix socketaddr");
        assert!(u.is_unnamed());
        assert!(u.as_pathname().is_none());

        let n = SocketAddr::from_pathname("/home/arachnidsGrip/.arti/SOCKET")
            .expect("Couldn't construct named socketaddr");
        assert!(!n.is_unnamed());
    }
}
