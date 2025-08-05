//! Functionality for working with AF\_UNIX addresses.

#[cfg(unix)]
use tor_general_addr::unix;

/// Helper: construct an unnamed SocketAddr.
#[cfg(unix)]
pub(crate) fn new_unnamed_socketaddr() -> std::io::Result<unix::SocketAddr> {
    // There SHOULD be a better way to do this in legitimate Rust!
    // But sadly, there isn't.
    unix::SocketAddr::from_pathname("")
}

/// Error: Tried to perform an operation on an unsupported kind of AF\_UNIX address.
///
/// (For example, you can't bind or connect to an unnamed address.)
#[derive(Clone, Debug, thiserror::Error)]
#[error("Operation not supported on this kind of AF_UNIX address")]
#[non_exhaustive]
pub struct UnsupportedAfUnixAddressType;

/// Deprecated name for `UnsupportedAfUnixAddressType`
#[deprecated]
pub type UnsupportedUnixAddressType = UnsupportedAfUnixAddressType;

impl From<UnsupportedAfUnixAddressType> for std::io::Error {
    fn from(value: UnsupportedAfUnixAddressType) -> Self {
        std::io::Error::new(std::io::ErrorKind::Unsupported, value)
    }
}

#[cfg(test)]
mod test {
    #[cfg(unix)]
    use super::*;

    #[test]
    #[cfg(unix)]
    fn unnamed() {
        let u = new_unnamed_socketaddr().expect("couldn't construct unnamed AF_UNIX socketaddr");
        assert!(u.is_unnamed());
        assert!(u.as_pathname().is_none());

        let n = unix::SocketAddr::from_pathname("/home/arachnidsGrip/.arti/SOCKET")
            .expect("Couldn't construct named socketaddr");
        assert!(!n.is_unnamed());
    }
}
