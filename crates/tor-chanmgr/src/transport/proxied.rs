//! Connect to relays via a proxy.
//!
//! This code is here for two reasons:
//!   1. To connect via external pluggable transports (for which we use SOCKS to
//!      build our connections).
//!   2. To support users who are behind a firewall that requires them to use a
//!      SOCKS proxy to connect.
//!
//! Currently only SOCKS proxies are supported.
//
// TODO: Add support for `HTTP(S) CONNECT` someday?
//
// TODO: Maybe refactor this so that tor-ptmgr can exist in a more freestanding
// way, with fewer arti dependencies.
#![allow(dead_code)]

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use futures::{AsyncReadExt, AsyncWriteExt};
use tor_error::internal;
use tor_linkspec::PtTargetAddr;
use tor_rtcompat::NetStreamProvider;
use tor_socksproto::{
    SocksAddr, SocksAuth, SocksClientHandshake, SocksCmd, SocksRequest, SocksStatus, SocksVersion,
    SOCKS_BUF_LEN,
};
use tracing::trace;

#[cfg(feature = "pt-client")]
use super::TransportImplHelper;
#[cfg(feature = "pt-client")]
use async_trait::async_trait;
#[cfg(feature = "pt-client")]
use tor_error::bad_api_usage;
#[cfg(feature = "pt-client")]
use tor_linkspec::{ChannelMethod, HasChanMethod, OwnedChanTarget};

/// Information about what proxy protocol to use, and how to use it.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Protocol {
    /// Connect via SOCKS 4, SOCKS 4a, or SOCKS 5.
    Socks(SocksVersion, SocksAuth),
}

/// An address to use when told to connect to "no address."
const NO_ADDR: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 1));

/// Open a connection to `target` via the proxy at `proxy`, using the protocol
/// at `protocol`.
///
/// # Limitations
///
/// We will give an error if the proxy sends us any data on the connection along
/// with its final handshake: due to our implementation, any such data will be
/// discarded, and so we give an error rather than fail silently.
///
/// This limitation doesn't matter when the underlying protocol is Tor, or
/// anything else where the initiator is expected to speak before the responder
/// says anything.  To lift it, we would have to make this function's return
/// type become something buffered.
//
// TODO: Perhaps we should refactor this someday so it can be a general-purpose
// proxy function, not only for Arti.
pub(crate) async fn connect_via_proxy<R: NetStreamProvider + Send + Sync>(
    runtime: &R,
    proxy: &SocketAddr,
    protocol: &Protocol,
    target: &PtTargetAddr,
) -> Result<R::Stream, ProxyError> {
    trace!(
        "Launching a proxied connection to {} via proxy at {} using {:?}",
        target,
        proxy,
        protocol
    );
    let mut stream = runtime
        .connect(proxy)
        .await
        .map_err(|e| ProxyError::ProxyConnect(Arc::new(e)))?;

    let Protocol::Socks(version, auth) = protocol;

    let (target_addr, target_port): (tor_socksproto::SocksAddr, u16) = match target {
        PtTargetAddr::IpPort(a) => (SocksAddr::Ip(a.ip()), a.port()),
        #[cfg(feature = "pt-client")]
        PtTargetAddr::HostPort(host, port) => (
            SocksAddr::Hostname(
                host.clone()
                    .try_into()
                    .map_err(ProxyError::InvalidSocksAddr)?,
            ),
            *port,
        ),
        #[cfg(feature = "pt-client")]
        PtTargetAddr::None => (SocksAddr::Ip(NO_ADDR), 1),
        _ => return Err(ProxyError::UnrecognizedAddr),
    };

    let request = SocksRequest::new(
        *version,
        SocksCmd::CONNECT,
        target_addr,
        target_port,
        auth.clone(),
    )
    .map_err(ProxyError::InvalidSocksRequest)?;
    let mut handshake = SocksClientHandshake::new(request);

    // TODO: This code is largely copied from the socks server wrapper code in
    // arti::proxy. Perhaps we should condense them into a single thing, if we
    // don't just revise the SOCKS code completely.
    let mut inbuf = [0_u8; SOCKS_BUF_LEN];
    let mut n_read = 0;
    let reply = loop {
        // try to advance the handshake to the next state.
        let action = match handshake.handshake(&inbuf[..n_read]) {
            Err(_) => {
                // Message truncated.
                if n_read == inbuf.len() {
                    // We won't read any more:
                    return Err(ProxyError::Bug(internal!(
                        "SOCKS parser wanted excessively many bytes! {:?} {:?}",
                        handshake,
                        inbuf
                    )));
                }
                // read more and try again.
                continue;
            }
            Ok(Err(e)) => return Err(ProxyError::SocksProto(e)), // real error.
            Ok(Ok(action)) => action,
        };

        // reply if needed.
        if action.drain > 0 {
            inbuf.copy_within(action.drain..action.drain + n_read, 0);
            n_read -= action.drain;
        }
        if !action.reply.is_empty() {
            stream.write_all(&action.reply[..]).await?;
            stream.flush().await?;
        }
        if action.finished {
            break handshake.into_reply();
        }

        if n_read == inbuf.len() {
            // We would like to read more of this SOCKS request, but there is no
            // more space in the buffer.  If we try to keep reading into an
            // empty buffer, we'll just read nothing, try to parse it, and learn
            // that we still wish we had more to read.
            //
            // In theory we might want to resize the buffer.  Right now, though,
            // we just reject handshakes that don't fit into 1k.
            return Err(ProxyError::SocksProto(
                tor_socksproto::Error::NotImplemented(
                    "Socks handshake did not fit in 1KiB buffer".into(),
                ),
            ));
        }

        // Read some more stuff.
        let n = stream.read(&mut inbuf[n_read..]).await?;
        if n == 0 {
            return Err(ProxyError::SocksClosed);
        }
        n_read += n;
    };

    let status = reply
        .ok_or_else(|| internal!("SOCKS protocol finished, but gave no status!"))?
        .status();
    trace!(
        "SOCKS handshake with {} succeeded, with status {:?}",
        proxy,
        status
    );

    if status != SocksStatus::SUCCEEDED {
        return Err(ProxyError::SocksError(status));
    }

    if n_read != 0 {
        return Err(ProxyError::UnexpectedData);
    }

    Ok(stream)
}

/// An error that occurs while negotiating a connection with a proxy.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProxyError {
    /// We had an IO error while trying to open a connection to the proxy.
    #[error("Problem while connecting to proxy")]
    ProxyConnect(#[source] Arc<std::io::Error>),

    /// We had an IO error while talking to the proxy.
    #[error("Problem while communicating with proxy")]
    ProxyIo(#[source] Arc<std::io::Error>),

    /// We tried to use an address which socks doesn't support.
    #[error("SOCKS proxy does not support target address")]
    InvalidSocksAddr(#[source] tor_socksproto::Error),

    /// We tried to use an address type which _we_ don't recognize.
    #[error("Got an address type we don't recognize")]
    UnrecognizedAddr,

    /// Our SOCKS implementation told us that this request cannot be encoded.
    #[error("Tried to make an invalid SOCKS request")]
    InvalidSocksRequest(#[source] tor_socksproto::Error),

    /// The peer refused our request, or spoke SOCKS incorrectly.
    #[error("Protocol error while communicating with SOCKS proxy")]
    SocksProto(#[source] tor_socksproto::Error),

    /// Unexpected close from SOCKS proxy before handshake was completed.
    #[error("Unexpected close while communicating with SOCKS proxy")]
    SocksClosed,

    /// We encountered an internal programming error.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),

    /// We got extra data immediately after our handshake, before we actually
    /// sent anything.
    ///
    /// This is not a bug in the calling code or in the peer protocol: it just
    /// means that the remote peer sent us data before we actually sent it any
    /// data. Unfortunately, there's a limitation in our code that makes it
    /// discard any such data, and therefore we have to give this error to
    /// prevent bugs.
    ///
    /// We could someday remove this limitation.
    #[error("Received unexpected early data from peer")]
    UnexpectedData,

    /// The proxy told us that our attempt failed.
    #[error("SOCKS proxy reported an error: {0}")]
    SocksError(SocksStatus),
}

impl From<std::io::Error> for ProxyError {
    fn from(e: std::io::Error) -> Self {
        ProxyError::ProxyIo(Arc::new(e))
    }
}

impl tor_error::HasKind for ProxyError {
    fn kind(&self) -> tor_error::ErrorKind {
        use tor_error::ErrorKind as EK;
        use ProxyError as E;
        match self {
            E::ProxyConnect(_) | E::ProxyIo(_) => EK::LocalNetworkError,
            E::InvalidSocksAddr(_) | E::InvalidSocksRequest(_) => EK::BadApiUsage,
            E::UnrecognizedAddr => EK::NotImplemented,
            E::SocksProto(_) => EK::LocalProtocolViolation,
            E::SocksClosed => EK::LocalNetworkError, // Could also be a protocol violation.
            E::Bug(e) => e.kind(),
            E::UnexpectedData => EK::NotImplemented,
            E::SocksError(_) => EK::LocalProtocolViolation,
        }
    }
}

impl tor_error::HasRetryTime for ProxyError {
    fn retry_time(&self) -> tor_error::RetryTime {
        use tor_error::RetryTime as RT;
        use ProxyError as E;
        use SocksStatus as S;
        match self {
            E::ProxyConnect(_) | E::ProxyIo(_) => RT::AfterWaiting,
            E::InvalidSocksAddr(_) => RT::Never,
            E::UnrecognizedAddr => RT::Never,
            E::InvalidSocksRequest(_) => RT::Never,
            E::SocksProto(_) => RT::AfterWaiting,
            E::SocksClosed => RT::AfterWaiting,
            E::Bug(_) => RT::Never,
            E::UnexpectedData => RT::Never,
            E::SocksError(e) => match *e {
                S::CONNECTION_REFUSED
                | S::GENERAL_FAILURE
                | S::HOST_UNREACHABLE
                | S::NETWORK_UNREACHABLE
                | S::TTL_EXPIRED => RT::AfterWaiting,
                _ => RT::Never,
            },
        }
    }
}

#[cfg(feature = "pt-client")]
#[cfg_attr(docsrs, doc(cfg(feature = "pt-client")))]
/// An object that connects to a Tor bridge via an external pluggable transport
/// that provides a proxy.
#[derive(Clone, Debug)]
pub struct ExternalProxyPlugin<R> {
    /// The runtime to use for connections.
    runtime: R,
    /// The location of the proxy.
    proxy_addr: SocketAddr,
    /// The SOCKS protocol version to use.
    proxy_version: SocksVersion,
}

#[cfg(feature = "pt-client")]
#[cfg_attr(docsrs, doc(cfg(feature = "pt-client")))]
impl<R: NetStreamProvider + Send + Sync> ExternalProxyPlugin<R> {
    /// Make a new `ExternalProxyPlugin`.
    pub fn new(rt: R, proxy_addr: SocketAddr, proxy_version: SocksVersion) -> Self {
        Self {
            runtime: rt,
            proxy_addr,
            proxy_version,
        }
    }
}

#[cfg(feature = "pt-client")]
#[async_trait]
impl<R: NetStreamProvider + Send + Sync> TransportImplHelper for ExternalProxyPlugin<R> {
    type Stream = R::Stream;

    async fn connect(
        &self,
        target: &OwnedChanTarget,
    ) -> crate::Result<(OwnedChanTarget, R::Stream)> {
        let pt_target = match target.chan_method() {
            ChannelMethod::Direct(_) => {
                return Err(crate::Error::UnusableTarget(bad_api_usage!(
                    "Used pluggable transport for a TCP connection."
                )))
            }
            ChannelMethod::Pluggable(target) => target,
            other => {
                return Err(crate::Error::UnusableTarget(bad_api_usage!(
                    "Used unknown, unsupported, transport {:?} for a TCP connection.",
                    other,
                )))
            }
        };

        let protocol =
            settings_to_protocol(self.proxy_version, encode_settings(pt_target.settings()))?;

        Ok((
            target.clone(),
            connect_via_proxy(&self.runtime, &self.proxy_addr, &protocol, pt_target.addr()).await?,
        ))
    }
}

/// Encode the PT settings from `IT` in a format that a pluggable transport can use.
#[cfg(feature = "pt-client")]
fn encode_settings<'a, IT>(settings: IT) -> String
where
    IT: Iterator<Item = (&'a str, &'a str)>,
{
    /// Escape a character in the way expected by pluggable transports.
    ///
    /// This escape machinery is a mirror of that in the standard library.
    enum EscChar {
        /// Return a backslash then a character.
        Backslash(char),
        /// Return a character.
        Literal(char),
        /// Return nothing.
        Done,
    }
    impl EscChar {
        /// Create an iterator to escape one character.
        fn new(ch: char, in_key: bool) -> Self {
            match ch {
                '\\' | ';' => EscChar::Backslash(ch),
                '=' if in_key => EscChar::Backslash(ch),
                _ => EscChar::Literal(ch),
            }
        }
    }
    impl Iterator for EscChar {
        type Item = char;

        fn next(&mut self) -> Option<Self::Item> {
            match *self {
                EscChar::Backslash(ch) => {
                    *self = EscChar::Literal(ch);
                    Some('\\')
                }
                EscChar::Literal(ch) => {
                    *self = EscChar::Done;
                    Some(ch)
                }
                EscChar::Done => None,
            }
        }
    }

    /// escape a key or value string.
    fn esc(s: &str, in_key: bool) -> impl Iterator<Item = char> + '_ {
        s.chars().flat_map(move |c| EscChar::new(c, in_key))
    }

    let mut result = String::new();
    for (k, v) in settings {
        result.extend(esc(k, true));
        result.push('=');
        result.extend(esc(v, false));
        result.push(';');
    }
    result.pop(); // remove the final ';' if any. Yes this is ugly.

    result
}

/// Transform a string into a representation that can be sent as SOCKS
/// authentication.
// NOTE(eta): I am very unsure of the logic in here.
#[cfg(feature = "pt-client")]
pub fn settings_to_protocol(vers: SocksVersion, s: String) -> Result<Protocol, ProxyError> {
    let mut bytes: Vec<_> = s.into();
    Ok(if bytes.is_empty() {
        Protocol::Socks(vers, SocksAuth::NoAuth)
    } else if vers == SocksVersion::V4 {
        if bytes.contains(&0) {
            return Err(ProxyError::InvalidSocksRequest(
                tor_socksproto::Error::NotImplemented(
                    "SOCKS 4 doesn't support internal NUL bytes (for PT settings list)".into(),
                ),
            ));
        } else {
            Protocol::Socks(SocksVersion::V4, SocksAuth::Socks4(bytes))
        }
    } else if bytes.len() <= 255 {
        // The [0] here is mandatory according to the pt-spec.
        Protocol::Socks(SocksVersion::V5, SocksAuth::Username(bytes, vec![0]))
    } else if bytes.len() <= (255 * 2) {
        let password = bytes.split_off(255);
        Protocol::Socks(SocksVersion::V5, SocksAuth::Username(bytes, password))
    } else {
        return Err(ProxyError::InvalidSocksRequest(
            tor_socksproto::Error::NotImplemented("PT settings list too long for SOCKS 5".into()),
        ));
    })
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
    #[allow(unused_imports)]
    use super::*;

    #[cfg(feature = "pt-client")]
    #[test]
    fn setting_encoding() {
        fn check(settings: Vec<(&str, &str)>, expected: &str) {
            assert_eq!(encode_settings(settings.into_iter()), expected);
        }

        // Easy cases, no escapes.
        check(vec![], "");
        check(vec![("hello", "world")], "hello=world");
        check(
            vec![("hey", "verden"), ("hello", "world")],
            "hey=verden;hello=world",
        );
        check(
            vec![("hey", "verden"), ("hello", "world"), ("selv", "tak")],
            "hey=verden;hello=world;selv=tak",
        );

        check(
            vec![("semi;colon", "equals=sign")],
            r"semi\;colon=equals=sign",
        );
        check(
            vec![("equals=sign", "semi;colon")],
            r"equals\=sign=semi\;colon",
        );
        check(
            vec![("semi;colon", "equals=sign"), ("also", "back\\slash")],
            r"semi\;colon=equals=sign;also=back\\slash",
        );
    }

    #[cfg(feature = "pt-client")]
    #[test]
    fn split_settings() {
        use SocksVersion::*;
        let long_string = "examplestrg".to_owned().repeat(50);
        assert_eq!(long_string.len(), 550);
        let sv = |v, a, b| settings_to_protocol(v, long_string[a..b].to_owned()).unwrap();
        let s = |a, b| sv(V5, a, b);
        let v = |a, b| long_string.as_bytes()[a..b].to_vec();

        assert_eq!(s(0, 0), Protocol::Socks(V5, SocksAuth::NoAuth));
        assert_eq!(
            s(0, 50),
            Protocol::Socks(V5, SocksAuth::Username(v(0, 50), vec![0]))
        );
        assert_eq!(
            s(0, 255),
            Protocol::Socks(V5, SocksAuth::Username(v(0, 255), vec![0]))
        );
        assert_eq!(
            s(0, 256),
            Protocol::Socks(V5, SocksAuth::Username(v(0, 255), v(255, 256)))
        );
        assert_eq!(
            s(0, 300),
            Protocol::Socks(V5, SocksAuth::Username(v(0, 255), v(255, 300)))
        );
        assert_eq!(
            s(0, 510),
            Protocol::Socks(V5, SocksAuth::Username(v(0, 255), v(255, 510)))
        );

        // This one needs to use socks4, or it won't fit. :P
        assert_eq!(
            sv(V4, 0, 511),
            Protocol::Socks(V4, SocksAuth::Socks4(v(0, 511)))
        );

        // Small requests with "0" bytes work fine...
        assert_eq!(
            settings_to_protocol(V5, "\0".to_owned()).unwrap(),
            Protocol::Socks(V5, SocksAuth::Username(vec![0], vec![0]))
        );
        assert_eq!(
            settings_to_protocol(V5, "\0".to_owned().repeat(510)).unwrap(),
            Protocol::Socks(V5, SocksAuth::Username(vec![0; 255], vec![0; 255]))
        );

        // Huge requests with "0" simply can't be encoded.
        assert!(settings_to_protocol(V5, "\0".to_owned().repeat(511)).is_err());

        // Huge requests without "0" can't be encoded as V5
        assert!(settings_to_protocol(V5, long_string[0..512].to_owned()).is_err());

        // Requests with "0" can't be encoded as V4.
        assert!(settings_to_protocol(V4, "\0".to_owned()).is_err());
    }
}
