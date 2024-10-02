//! Support for RPC-visible connections through Arti.

use std::{
    io::{Error as IoError, Read as _, Write as _},
    net::{SocketAddr, TcpStream},
    sync::Arc,
};

use serde::{Deserialize, Serialize};

use super::{ErrorResponse, RpcConn};
use crate::{msgs::request::Request, ObjectId};

use tor_error::ErrorReport as _;

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

    /// Tried to open a stream on an unauthenticated RPC connection.
    ///
    /// (At present (Sep 2024) there is no way to get an unauthenticated connection from
    /// `arti-rpc-client-core`, but that may change in the future.)
    #[error("RPC connection not authenticated")]
    NotAuthenticated,

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
struct SingleIdResponse {
    /// The object ID of the response.
    id: ObjectId,
}

/// A response with no data.
#[derive(Deserialize, Debug)]
struct EmptyResponse {}

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
    #[serde(rename = "socks5")]
    Socks5 {
        /// The address at which we're listening for SOCKS connections.
        tcp_address: Option<SocketAddr>,
    },
    /// Some other (unrecognized) listener type.
    #[serde(untagged)]
    Unrecognized {},
}

impl Proxy {
    /// If this is a SOCKS proxy, return its address.
    fn socks_addr(&self) -> Option<SocketAddr> {
        match self.listener {
            ProxyListener::Socks5 { tcp_address } => tcp_address,
            ProxyListener::Unrecognized {} => None,
        }
    }
}

impl ProxyInfo {
    /// Choose a SOCKS5 address to use from this list of proxies.
    fn find_socks_addr(&self) -> Option<SocketAddr> {
        // We choose the first usable Proxy.
        self.proxies.iter().find_map(Proxy::socks_addr)
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

impl RpcConn {
    /// Open a new data stream, registering the stream with the RPC system.
    ///
    /// Behaves the same as [`open_stream()`](RpcConn::open_stream),
    /// with the following exceptions:
    ///
    /// - Returns a `ObjectId` that can be used to identify the `DataStream`
    ///   for later RPC requests.
    /// - Tells Arti not to wait for the stream to succeed or fail
    ///   over the Tor network.
    ///   (To wait for the stream to succeed or fail, use the appropriate method.)
    ///
    ///  (TODO RPC: Implement such a method!)
    pub fn open_stream_as_object(
        &self,
        on_object: Option<&ObjectId>,
        target: (&str, u16),
        isolation: &str,
    ) -> Result<(ObjectId, TcpStream), StreamError> {
        let on_object = self.resolve_on_object(on_object)?;
        let new_stream_request =
            Request::new(on_object.clone(), "arti:new_stream_handle", NoParameters {});
        let stream_id = self
            .execute_internal::<SingleIdResponse>(&new_stream_request.encode()?)?
            .map_err(StreamError::NewStreamRejected)?
            .id;

        match self.open_stream(Some(&stream_id), target, isolation) {
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
    /// We tell Arti that the stream must not share
    /// a circuit with any other stream with a different value for `isolation`.
    /// (If your application doesn't care about isolating its streams from one another,
    /// it is acceptable to leave `isolation` as an empty string.)
    pub fn open_stream(
        &self,
        on_object: Option<&ObjectId>,
        (hostname, port): (&str, u16),
        isolation: &str,
    ) -> Result<TcpStream, StreamError> {
        let on_object = self.resolve_on_object(on_object)?;
        let socks_proxy_addr = self.lookup_socks_proxy_addr()?;
        let mut stream = TcpStream::connect(socks_proxy_addr)?;

        // For information about this encoding,
        // see https://spec.torproject.org/socks-extensions.html#extended-auth
        let username = format!("<torS0X>1{}", on_object.as_ref());
        let password = isolation;
        negotiate_socks(&mut stream, hostname, port, &username, password)?;

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
        let proxy_info = self.execute_internal_ok::<ProxyInfo>(&proxy_info_request.encode()?)?;
        let socks_proxy_addr = proxy_info.find_socks_addr().ok_or(StreamError::NoProxy)?;

        Ok(socks_proxy_addr)
    }

    /// Helper: Return the session ID, or an error.
    fn session_id_required(&self) -> Result<&ObjectId, StreamError> {
        self.session().ok_or(StreamError::NotAuthenticated)
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
        let _empty_response: EmptyResponse =
            self.execute_internal_ok(&release_request.encode()?)?;
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
        Handshake as _, SocksAddr, SocksAuth, SocksClientHandshake, SocksCmd, SocksHostname,
        SocksRequest, SocksStatus, SocksVersion,
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

    let mut buf = tor_socksproto::Buffer::new_precise();
    let mut state = SocksClientHandshake::new(request);
    let reply = loop {
        use tor_socksproto::NextStep as NS;
        match state.step(&mut buf).map_err(E::SocksProtocol)? {
            NS::Recv(mut recv) => {
                let n = stream.read(recv.buf())?;
                recv.note_received(n).map_err(E::SocksProtocol)?;
            }
            NS::Send(send) => stream.write_all(&send)?,
            NS::Finished(fin) => {
                break fin
                    .into_output()
                    .map_err(|bug| E::Internal(bug.report().to_string()))?
            }
        }
    };

    let status = reply.status();

    if status == SocksStatus::SUCCEEDED {
        Ok(())
    } else {
        Err(StreamError::SocksError(status))
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

    use super::*;

    #[test]
    fn unexpected_proxies() {
        let p: ProxyInfo = serde_json::from_str(
            r#"
               { "proxies" : [ {"listener" : {"socks5" : {"tcp_address" : "127.0.0.1:9090" }}} ] }
            "#,
        )
        .unwrap();
        assert_eq!(p.proxies.len(), 1);
        match p.proxies[0].listener {
            ProxyListener::Socks5 {
                tcp_address: address,
            } => {
                assert_eq!(address.unwrap(), "127.0.0.1:9090".parse().unwrap());
            }
            _ => panic!(),
        };

        let p: ProxyInfo = serde_json::from_str(
            r#"
               { "proxies" : [
                {"listener" : {"hypothetical" : {"tzitzel" : "buttered" }}},
                {"listener" : {"socks5" : {"unix_path" : "/home/username/.local/PROXY"}}},
                {"listener" : {"socks5" : {"tcp_address" : "127.0.0.1:9090" }}},
                {"listener" : {"socks5" : {"tcp_address" : "127.0.0.1:9999" }}}
               ] }
            "#,
        )
        .unwrap();
        assert_eq!(
            p.find_socks_addr().unwrap(),
            "127.0.0.1:9090".parse().unwrap()
        );
    }
}
