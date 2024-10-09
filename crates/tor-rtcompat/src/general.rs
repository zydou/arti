//! Support for generalized addresses.
//!
//! We use the [`SocketAddr`] type in this module,
//! and its associated [`Stream`] and [`Listener`] types,
//! when we want write code
//! that can treat AF_UNIX addresses and internet addresses as a single type.
//!
//! As an alternative, you could also write your code to be generic
//! over address, listener, provider, and stream types.
//! That would give you the performance benefits of monomorphization
//! over some corresponding costs in complexity and code size.
//! Generally, it's better to use these types unless you know
//! that the minor performance overhead here will matter in practice.

use async_trait::async_trait;
use futures::{stream, AsyncRead, AsyncWrite, StreamExt as _};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::{unix, NetStreamListener, NetStreamProvider};
use std::{
    io::{Error as IoError, Result as IoResult},
    net,
};

/// Any address that Arti can listen on or connect to.
///
/// We use this type when we want to make streams
/// without being concerned whether they are AF_UNIX streams, TCP streams, or so forth.
///
/// To avoid confusion, you might want to avoid importing this type directly.
/// Instead, import [`rtcompat::general`](crate::general)
/// and refer to this type as `general::SocketAddr`.
///
/// ## String representation
///
/// Any `general::SocketAddr` has up to two string representations:
///
/// 1. A _qualified_ representation, consisting of a schema
///    (either "unix" or "tcp"),
///    followed by a single colon,
///    followed by the address itself represented as a string.
///
///    Examples: `unix:/path/to/socket`, `tcp:127.0.0.1:9999`,
///    `tcp:[::1]:9999`.
///
/// 2. A _unqualified_ representation,
///    consisting of a TCP address represented as a string.
///
///    Examples: `127.0.0.1:9999`,  `[::1]:9999`.
///
/// Note that not every `general::SocketAddr` has a string representation!
/// Currently, the ones that might not be representable are:
///
///  - AF_UNIX addresses without a path name.
///  - AF_UNIX addresses whose path name is not UTF-8.
///
/// Note also that string representations may contain whitespace
/// or other unusual characters.
/// `/var/run/arti socket` is a valid filename,
/// so `unix:/var/run/arti socket` is a valid representation.
///
/// We may add new schemas in the future.
/// If we do, any new schema will begin with an ascii alphabetical character,
/// and will consist only of ascii alphanumeric characters,
/// the character `-`, and the character `_`.
#[derive(Clone, Debug, derive_more::From, derive_more::TryInto)]
#[non_exhaustive]
pub enum SocketAddr {
    /// An IPv4 or IPv6 address on the internet.
    Inet(net::SocketAddr),
    /// A local AF_UNIX address.
    ///
    /// (Note that [`unix::SocketAddr`] is unconstructable on platforms where it is not supported.)
    Unix(unix::SocketAddr),
}

impl SocketAddr {
    /// Return a wrapper object that can be used to display this address.
    ///
    /// The resulting display might be lossy, depending on whether this address can be represented
    /// as a string.
    ///
    /// The displayed format here is intentionally undocumented;
    /// it may change in the future.
    pub fn display_lossy(&self) -> DisplayLossy<'_> {
        DisplayLossy(self)
    }

    /// If possible, return a qualified string representation for this address.
    ///
    /// Otherwise return None.
    pub fn try_to_string(&self) -> Option<String> {
        use SocketAddr::*;
        match self {
            Inet(sa) => Some(format!("tcp:{}", sa)),
            Unix(sa) => sa
                .as_pathname()
                .and_then(Path::to_str)
                .map(|p| format!("unix:{}", p)),
        }
    }
}

/// Lossy display for a [`SocketAddr`].
pub struct DisplayLossy<'a>(&'a SocketAddr);

impl<'a> std::fmt::Display for DisplayLossy<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use SocketAddr::*;
        match self.0 {
            Inet(sa) => write!(f, "tcp:{}", sa),
            Unix(sa) => {
                if let Some(path) = sa.as_pathname() {
                    if let Some(path_str) = path.to_str() {
                        write!(f, "unix:{}", path_str)
                    } else {
                        write!(f, "unix:{} [lossy]", path.to_string_lossy())
                    }
                } else if sa.is_unnamed() {
                    write!(f, "unix:")
                } else {
                    write!(f, "unix:{:?} [lossy]", sa)
                }
            }
        }
    }
}

impl std::str::FromStr for SocketAddr {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with(|c: char| (c.is_ascii_digit() || c == '[')) {
            // This looks like a tcp address, and cannot be a qualified address.
            Ok(s.parse::<net::SocketAddr>()?.into())
        } else if let Some((schema, remainder)) = s.split_once(':') {
            match schema {
                "unix" => Ok(unix::SocketAddr::from_pathname(remainder)?.into()),
                "tcp" => Ok(s.parse::<net::SocketAddr>()?.into()),
                _ => Err(AddrParseError::UnrecognizedSchema(schema.to_string())),
            }
        } else {
            Err(AddrParseError::NoSchema)
        }
    }
}

/// An error encountered while attempting to parse a [`SocketAddr`]
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AddrParseError {
    /// Tried to parse an address with an unrecognized schema.
    #[error("Address schema {0:?} unrecognized")]
    UnrecognizedSchema(String),
    /// Tried to parse a non TCP-address with no schema.
    #[error("Address did not look like TCP, but had no address schema.")]
    NoSchema,
    /// Tried to parse an address as an AF_UNIX address, but failed.
    #[error("Invalid AF_UNIX address")]
    InvalidUnixAddress(#[source] Arc<IoError>),
    /// Tried to parse an address as a TCP address, but failed.
    #[error("Invalid TCP address")]
    InvalidTcpAddress(#[from] std::net::AddrParseError),
}

impl From<IoError> for AddrParseError {
    fn from(e: IoError) -> Self {
        Self::InvalidUnixAddress(Arc::new(e))
    }
}

/// Helper trait to allow us to create a type-erased stream.
///
/// (Rust doesn't allow "dyn AsyncRead + AsyncWrite")
trait ReadAndWrite: AsyncRead + AsyncWrite + Send + Sync {}
impl<T> ReadAndWrite for T where T: AsyncRead + AsyncWrite + Send + Sync {}

/// A stream returned by a `NetStreamProvider<GeneralizedAddr>`
pub struct Stream(Pin<Box<dyn ReadAndWrite>>);
impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        self.0.as_mut().poll_read(cx, buf)
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        self.0.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.0.as_mut().poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        self.0.as_mut().poll_close(cx)
    }
}

/// The type of the result from an [`IncomingStreams`].
type StreamItem = IoResult<(Stream, SocketAddr)>;

/// A stream of incoming connections on a [`general::Listener`](Listener).
pub struct IncomingStreams(Pin<Box<dyn stream::Stream<Item = StreamItem> + Send + Sync>>);

impl stream::Stream for IncomingStreams {
    type Item = IoResult<(Stream, SocketAddr)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.as_mut().poll_next(cx)
    }
}

/// A listener returned by a `NetStreamProvider<general::SocketAddr>`.
pub struct Listener {
    /// The `futures::Stream` of incoming network streams.
    streams: IncomingStreams,
    /// The local address on which we're listening.
    local_addr: SocketAddr,
}

impl NetStreamListener<SocketAddr> for Listener {
    type Stream = Stream;
    type Incoming = IncomingStreams;

    fn incoming(self) -> IncomingStreams {
        self.streams
    }

    fn local_addr(&self) -> IoResult<SocketAddr> {
        Ok(self.local_addr.clone())
    }
}

/// Use `provider` to launch a `NetStreamListener` at `address`, and wrap that listener
/// as a `Listener`.
async fn abstract_listener_on<ADDR, P>(provider: &P, address: &ADDR) -> IoResult<Listener>
where
    P: NetStreamProvider<ADDR>,
    SocketAddr: From<ADDR>,
{
    let lis = provider.listen(address).await?;
    let local_addr = SocketAddr::from(lis.local_addr()?);
    let streams = lis.incoming().map(|result| {
        result.map(|(socket, addr)| (Stream(Box::pin(socket)), SocketAddr::from(addr)))
    });
    let streams = IncomingStreams(Box::pin(streams));
    Ok(Listener {
        streams,
        local_addr,
    })
}

#[async_trait]
impl<T> NetStreamProvider<SocketAddr> for T
where
    T: NetStreamProvider<net::SocketAddr> + NetStreamProvider<unix::SocketAddr>,
{
    type Stream = Stream;
    type Listener = Listener;

    async fn connect(&self, addr: &SocketAddr) -> IoResult<Stream> {
        use SocketAddr as G;
        match addr {
            G::Inet(a) => Ok(Stream(Box::pin(self.connect(a).await?))),
            G::Unix(a) => Ok(Stream(Box::pin(self.connect(a).await?))),
        }
    }
    async fn listen(&self, addr: &SocketAddr) -> IoResult<Listener> {
        use SocketAddr as G;
        match addr {
            G::Inet(a) => abstract_listener_on(self, a).await,
            G::Unix(a) => abstract_listener_on(self, a).await,
        }
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::AddrParseError;
    use crate::general;
    use assert_matches::assert_matches;
    use std::net;
    #[cfg(unix)]
    use std::os::unix::net as unix;

    #[test]
    fn ok_tcp() {
        let a1: net::SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let a2: net::SocketAddr = "[::1]:9999".parse().unwrap();

        let ga1: general::SocketAddr = a1.into();
        let ga2: general::SocketAddr = a2.into();

        let ga3: general::SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let ga4: general::SocketAddr = "[::1]:9999".parse().unwrap();
        let ga5: general::SocketAddr = "tcp:127.0.0.1:9999".parse().unwrap();
        let ga6: general::SocketAddr = "tcp:[::1]:9999".parse().unwrap();

        assert_eq!(ga1, ga3);
        assert_eq!(ga1, ga5);

        assert_eq!(ga2, ga4);
        assert_eq!(ga2, ga6);

        assert_ne!(ga1, ga2);

        assert_eq!(ga1.display_lossy().to_string(), "tcp:127.0.0.1:9999");
        assert_eq!(ga1.try_to_string().unwrap(), "tcp:127.0.0.1:9999");
        assert_eq!(ga2.display_lossy().to_string(), "tcp:[::1]:9999");
        assert_eq!(ga2.try_to_string().unwrap(), "tcp:[::1]:9999");
    }

    #[test]
    #[cfg(unix)]
    fn ok_unix() {
        let a1 = unix::SocketAddr::from_pathname("/some/path").unwrap();
        let a2 = unix::SocketAddr::from_pathname("/another/path").unwrap();

        let ga1: general::SocketAddr = a1.into();
        let ga2: general::SocketAddr = a2.into();

        let ga3: general::SocketAddr = "unix:/some/path".parse().unwrap();
        let ga4: general::SocketAddr = "unix:/another/path".parse().unwrap();

        assert_eq!(ga1, ga3);
        assert_eq!(ga2, ga4);

        assert_ne!(ga1, ga2);

        assert_eq!(ga1.display_lossy().to_string(), "unix:/some/path");
        assert_eq!(ga1.try_to_string().unwrap(), "unix:/some/path");
        assert_eq!(ga2.display_lossy().to_string(), "unix:/another/path");
        assert_eq!(ga2.try_to_string().unwrap(), "unix:/another/path");
    }

    #[test]
    fn parse_err_tcp() {
        assert_matches!(
            "1234567890:999".parse::<general::SocketAddr>(),
            Err(AddrParseError::InvalidTcpAddress(_))
        );
        assert_matches!(
            "1z".parse::<general::SocketAddr>(),
            Err(AddrParseError::InvalidTcpAddress(_))
        );
        assert_matches!(
            "[[77".parse::<general::SocketAddr>(),
            Err(AddrParseError::InvalidTcpAddress(_))
        );

        assert_matches!(
            "tcp:fred:9999".parse::<general::SocketAddr>(),
            Err(AddrParseError::InvalidTcpAddress(_))
        );

        assert_matches!(
            "tcp:127.0.0.1".parse::<general::SocketAddr>(),
            Err(AddrParseError::InvalidTcpAddress(_))
        );

        assert_matches!(
            "tcp:[::1]".parse::<general::SocketAddr>(),
            Err(AddrParseError::InvalidTcpAddress(_))
        );
    }

    #[test]
    fn parse_err_schemata() {
        assert_matches!(
            "fred".parse::<general::SocketAddr>(),
            Err(AddrParseError::NoSchema)
        );
        assert_matches!(
            "fred:".parse::<general::SocketAddr>(),
            Err(AddrParseError::UnrecognizedSchema(f)) if f == "fred"
        );
        assert_matches!(
            "fred:hello".parse::<general::SocketAddr>(),
            Err(AddrParseError::UnrecognizedSchema(f)) if f == "fred"
        );
    }

    #[test]
    #[cfg(unix)]
    fn display_unix_weird() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt as _;
        let odd_path = &OsStr::from_bytes(&[255, 255, 255, 255]);

        let a1 = general::SocketAddr::from(unix::SocketAddr::from_pathname(odd_path).unwrap());
        let a2 = general::SocketAddr::from(unix::SocketAddr::from_pathname("").unwrap());

        assert!(a1.try_to_string().is_none());
        assert!(a2.try_to_string().is_none());

        assert_eq!(a1.display_lossy().to_string(), "unix:����");
        assert_eq!(a2.display_lossy().to_string(), "unix:----");
    }

    #[test]
    #[cfg(not(unix))]
    fn parse_err_no_unix() {
        assert_matches!(
            "unix:".parse::<general::SocketAddr>(),
            Err(AddrParseError::InvalidUnixAddress(_))
        );
        assert_matches!(
            "unix:/any/path".parse::<general::SocketAddr>(),
            Err(AddrParseError::InvalidUnixAddress(_))
        );
    }
}
