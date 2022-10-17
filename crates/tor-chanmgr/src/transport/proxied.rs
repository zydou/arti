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
use tor_rtcompat::TcpProvider;
use tor_socksproto::{
    SocksAddr, SocksAuth, SocksClientHandshake, SocksCmd, SocksRequest, SocksStatus, SocksVersion,
};

/// Information about what proxy protocol to use, and how to use it.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub(crate) enum Protocol {
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
pub(crate) async fn connect_via_proxy<R: TcpProvider + Send + Sync>(
    runtime: &R,
    proxy: &SocketAddr,
    protocol: &Protocol,
    target: &PtTargetAddr,
) -> Result<R::TcpStream, ProxyError> {
    // a different error type would be better TODO pt-client
    let mut stream = runtime.connect(proxy).await?;

    let Protocol::Socks(version, auth) = protocol;

    let (target_addr, target_port): (tor_socksproto::SocksAddr, u16) = match target {
        PtTargetAddr::IpPort(a) => (SocksAddr::Ip(a.ip()), a.port()),
        PtTargetAddr::HostPort(host, port) => (
            SocksAddr::Hostname(
                host.clone()
                    .try_into()
                    .map_err(ProxyError::InvalidSocksAddr)?,
            ),
            *port,
        ),
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
    let mut inbuf = [0_u8; 1024];
    let mut n_read = 0;
    let reply = loop {
        // Read some more stuff.
        n_read += stream.read(&mut inbuf[n_read..]).await?;

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
    };

    let status = reply
        .ok_or_else(|| internal!("SOCKS protocol finished, but gave no status!"))?
        .status();

    if status != SocksStatus::SUCCEEDED {
        return Err(ProxyError::SocksError(status));
    }

    if n_read != 0 {
        return Err(ProxyError::ExtraneousData);
    }

    Ok(stream)
}

/// An error that occurs while negotiating a connection with a proxy.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum ProxyError {
    /// We had an IO error while talking to the proxy
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
    #[error("Received extraneous data from peer")]
    ExtraneousData,

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
            E::ProxyIo(_) => EK::LocalNetworkError,
            E::InvalidSocksAddr(_) | E::InvalidSocksRequest(_) => EK::BadApiUsage,
            E::UnrecognizedAddr => EK::NotImplemented,
            E::SocksProto(_) => EK::LocalProtocolViolation,
            E::Bug(e) => e.kind(),
            E::ExtraneousData => EK::NotImplemented,
            E::SocksError(_) => EK::LocalProtocolFailed,
        }
    }
}
