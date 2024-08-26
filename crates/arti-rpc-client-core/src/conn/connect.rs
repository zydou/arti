//! Support for RPC-visible connections through Arti.

use std::{
    io::{Error as IoError, Read as _, Write as _},
    net::{SocketAddr, TcpStream},
    sync::Arc,
};

use serde::{Deserialize, Serialize};

use super::{ErrorResponse, RpcConn};
use crate::{msgs::request::Request, ObjectId};

/// An error encountered while trying to open a data stream.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StreamError {
    /// One of the RPC methods that we invoked to create the stream failed.
    #[error("An error occurred while invoking RPC methods")]
    RpcMethods(#[from] super::ProtoError),

    /// We weren't able to find a working proxy address.
    #[error("Request for proxy info rejected")]
    ProxyInfoRejected(ErrorResponse),

    /// We weren't able to register a new stream ID.
    #[error("Request for new stream ID rejected")]
    NewStreamRejected(ErrorResponse),

    /// We weren't able to release a new stream ID.
    #[error("Request for new stream ID rejected")]
    StreamReleaseRejected(ErrorResponse),

    /// We encountered an internal error.
    /// (This should be impossible.)
    #[error("Internal error: {0}")]
    Internal(String),

    /// No SOCKS proxies were listed in the server's reply.
    #[error("No SOCKS proxy available")]
    NoProxy,

    /// We encountered an IO error while trying to connect to the
    /// proxy or negotiate SOCKS.
    #[error("IO error")]
    Io(#[source] Arc<IoError>),

    /// The generated SOCKS request was invalid.
    ///
    /// (Most likely, a provided isolation string or hostname was too long for the
    /// authentication system to support.)
    #[error("Invalid SOCKS request")]
    SocksRequest(#[source] tor_socksproto::Error),

    /// The other side did not speak socks, or did not speak socks in the format
    /// we expected.
    #[error("SOCKS protocol violation")]
    SocksProtocol(#[source] tor_socksproto::Error),

    /// The other side gave us a SOCKS error.
    #[error("SOCKS error code {0}")]
    SocksError(tor_socksproto::SocksStatus),
}

impl From<IoError> for StreamError {
    fn from(e: IoError) -> Self {
        Self::Io(Arc::new(e))
    }
}

/// Arguments to a request that takes no parameters.
#[derive(Serialize, Debug)]
struct NoParameters {}

/// Arguments to a request to drop an object.
#[derive(Serialize, Debug)]
struct ReleaseObj {
    /// The object to release.
    obj: ObjectId,
}

/// A response with a single ID.
#[derive(Deserialize, Debug)]
struct SingletonId {
    /// The object ID of the response.
    id: ObjectId,
}

/// Representation of a single proxy, as delivered by the RPC API.
// TODO RPC: This is duplicated from proxyinfo.rs; decide on our strategy for this stuff.
#[derive(Deserialize, Clone, Debug)]
pub(super) struct Proxy {
    /// Where the proxy is listening, and what protocol-specific options it expects.
    pub(super) listener: ProxyListener,
}

/// Representation of a single proxy's listener location, as delivered by the RPC API.
#[derive(Deserialize, Clone, Debug)]
// TODO RPC: This is duplicated from proxyinfo.rs; decide on our strategy for this stuff.
pub(super) enum ProxyListener {
    /// A SOCKS5 proxy.
    Socks5 {
        /// The address at which we're listening for SOCKS connections.
        address: SocketAddr,
    },
}

impl Proxy {
    /// If this is a SOCKS proxy, unwrap its address.
    #[allow(clippy::unnecessary_wraps)]
    fn into_socks_addr(self) -> Option<SocketAddr> {
        match self {
            Proxy {
                listener: ProxyListener::Socks5 { address },
            } => Some(address),
        }
    }
}

/// A representation of the set of proxy addresses available from the RPC API.
// TODO RPC: This is duplicated from proxyinfo.rs; decide on our strategy for this stuff.
#[derive(Deserialize, Clone, Debug)]
pub(super) struct ProxyInfo {
    /// A list of the supported proxies.
    ///
    /// (So far, only SOCKS proxies are listed, but other kinds may be listed in the future.)
    pub(super) proxies: Vec<Proxy>,
}
// XXXX validate that we can handle and discard unrecognized proxy types, or unrecognized Socks5
// formats, in the list above.

impl RpcConn {
    /// Open a new data stream, registering the stream with the RPC system.
    ///
    /// Behaves the same as [`connect()`](RpcConn::connect),
    /// with the following exceptions:
    ///
    /// - Returns a `ObjectId` that can be used to identify the `DataStream`
    ///   for later RPC requests.
    /// - Tells Arti not to wait for the stream to succeed or fail
    ///   over the Tor network.
    ///   (To wait for the stream to succeed or fail, use the appropriate method.)
    ///
    ///  (TODO RPC: Implement such a method!)
    pub fn connect_with_object(
        &self,
        on_object: Option<&ObjectId>,
        target: (&str, u16),
        isolation: Option<&str>,
    ) -> Result<(ObjectId, TcpStream), StreamError> {
        let on_object = self.resolve_on_object(on_object)?;
        let new_stream_request =
            Request::new(on_object.clone(), "arti:new_stream_handle", NoParameters {});
        let stream_id = self
            .execute(&new_stream_request.encode()?)?
            .map_err(StreamError::NewStreamRejected)?
            .deserialize_as::<SingletonId>()?
            .id;

        match self.connect(Some(&stream_id), target, isolation) {
            Ok(tcp_stream) => Ok((stream_id, tcp_stream)),
            Err(e) => {
                if let Err(_inner) = self.release_obj(stream_id) {
                    // TODO RPC: We should log this error or something
                }
                Err(e)
            }
        }
    }

    /// Open a new data stream, using Arti to connect anonymously to a given
    /// address and port.
    ///
    /// If `on_object` is provided, it must be a an ID for a  client-like RPC
    /// object that supports opening data streams.  If it is not provided,
    /// the data stream is opened relative to the current session.
    ///
    /// If `isolation` is provided, we tell Arti that the stream must not share
    /// a circuit with any other stream with a different value for `isolation`.
    pub fn connect(
        &self,
        on_object: Option<&ObjectId>,
        (hostname, port): (&str, u16),
        isolation: Option<&str>,
    ) -> Result<TcpStream, StreamError> {
        let on_object = self.resolve_on_object(on_object)?;
        let socks_proxy_addr = self.lookup_socks_proxy_addr()?;
        let mut stream = TcpStream::connect(socks_proxy_addr)?;

        let username = "<arti-rpc-session>";
        let password = match isolation {
            Some(iso) => format!("{}:{}", on_object.as_ref(), iso),
            None => on_object.into(),
        };
        negotiate_socks(&mut stream, hostname, port, username, &password)?;

        Ok(stream)
    }

    /// Ask Arti for its supported SOCKS addresses; return the first one.
    //
    // TODO: Currently we call this every time we want to open a stream.
    // We could instead cache the value.
    fn lookup_socks_proxy_addr(&self) -> Result<SocketAddr, StreamError> {
        let session_id = self.session_id_required()?.clone();

        let proxy_info_request: Request<NoParameters> =
            Request::new(session_id, "arti:get_rpc_proxy_info", NoParameters {});
        let proxy_info = self
            .execute(&proxy_info_request.encode()?)?
            .map_err(StreamError::ProxyInfoRejected)?
            .deserialize_as::<ProxyInfo>()?;
        let socks_proxy_addr = proxy_info
            .proxies
            .into_iter()
            .find_map(Proxy::into_socks_addr)
            .ok_or(StreamError::NoProxy)?;

        Ok(socks_proxy_addr)
    }

    /// Helper: Return the session ID, or an error.
    fn session_id_required(&self) -> Result<&ObjectId, StreamError> {
        self.session()
            .ok_or_else(|| StreamError::Internal("No RPC session".into()))
    }

    /// Helper: Return on_object if it's present, or the session ID otherwise.
    fn resolve_on_object(&self, on_object: Option<&ObjectId>) -> Result<ObjectId, StreamError> {
        Ok(match on_object {
            Some(obj) => obj.clone(),
            None => self.session_id_required()?.clone(),
        })
    }

    /// Helper: Tell Arti to release `obj`.
    fn release_obj(&self, obj: ObjectId) -> Result<(), StreamError> {
        let session_id = self.session_id_required()?;
        let release_request = Request::new(session_id.clone(), "rpc:release", ReleaseObj { obj });
        let _ignore_success = self
            .execute(&release_request.encode()?)?
            .map_err(StreamError::StreamReleaseRejected)?;

        Ok(())
    }
}

/// Helper: Negotiate SOCKS5 on the provided stream, using the given parameters.
//
// NOTE: We could user `tor-socksproto` instead, but that pulls in a little more
// code unnecessarily, has features we don't need, and has to handle variations
// of SOCKS responses that we'll never see.
fn negotiate_socks(
    stream: &mut TcpStream,
    hostname: &str,
    port: u16,
    username: &str,
    password: &str,
) -> Result<(), StreamError> {
    use tor_socksproto::{
        SocksAddr, SocksAuth, SocksClientHandshake, SocksCmd, SocksHostname, SocksRequest,
        SocksStatus, SocksVersion,
    };
    use StreamError as E;

    let request = SocksRequest::new(
        SocksVersion::V5,
        SocksCmd::CONNECT,
        SocksAddr::Hostname(SocksHostname::try_from(hostname.to_owned()).map_err(E::SocksRequest)?),
        port,
        SocksAuth::Username(
            username.to_owned().into_bytes(),
            password.to_owned().into_bytes(),
        ),
    )
    .map_err(E::SocksRequest)?;

    let mut buf = [0_u8; 1024];
    let mut n_in_buf = 0;
    let mut state = SocksClientHandshake::new(request);
    let reply = loop {
        if buf[n_in_buf..].is_empty() {
            return Err(E::Internal(
                "Buffer not large enough to perform SOCKS request!?".to_owned(),
            ));
        }

        n_in_buf += stream.read(&mut buf[n_in_buf..])?;
        let action = match state.handshake(&buf[..n_in_buf]) {
            Err(_truncated) => continue, // need to read more.
            Ok(Err(e)) => return Err(E::SocksProtocol(e)),
            Ok(Ok(action)) => action,
        };
        if action.drain > 0 {
            buf.copy_within(action.drain..n_in_buf, 0);
            n_in_buf -= action.drain;
        }
        if !action.reply.is_empty() {
            stream.write_all(&action.reply)?;
        }
        if action.finished {
            break state.into_reply();
        }
    };

    let status = reply
        .ok_or_else(|| {
            E::Internal("SOCKS handshake finished, but didn't give a SocksReply!?".to_owned())
        })?
        .status();

    if n_in_buf != 0 {
        return Err(E::Internal(
            "Unconsumed bytes left after SOCKS handshake!".to_owned(),
        ));
    }

    if status == SocksStatus::SUCCEEDED {
        Ok(())
    } else {
        Err(StreamError::SocksError(status))
    }
}
