//! Client operations for working with connect points.

use std::{net::TcpStream, sync::Arc};

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use fs_mistrust::Mistrust;
use tor_general_addr::general;

use crate::{
    ConnectError, ResolvedConnectPoint,
    auth::{RpcAuth, RpcCookieSource, cookie::CookieLocation},
    connpt::{AddrWithStr, AddressFile},
};

/// Information about an initial connection to a connect point.
#[non_exhaustive]
pub struct Connection {
    /// A successfully connected stream.
    ///
    /// At the time this is returned, authentication has not yet completed.
    pub stream: Stream,

    /// Information about how to authenticate.
    pub auth: crate::auth::RpcAuth,
}

/// A connection to Arti that can be used to transfer data.
#[non_exhaustive]
pub enum Stream {
    /// A connection via TCP.
    Tcp(TcpStream),

    /// A connection via an AF_UNIX stream socket.
    #[cfg(unix)]
    Unix(UnixStream),
}

impl ResolvedConnectPoint {
    /// Open a new connection to the RPC server designated by this connect point.
    ///
    /// On success, return a Connection structure containing a newly open socket,
    /// and instructions about how to authenticate on that socket.
    pub fn connect(&self, mistrust: &Mistrust) -> Result<Connection, ConnectError> {
        use crate::connpt::ConnectPointEnum as CptE;
        match &self.0 {
            CptE::Connect(connect) => connect.do_connect(mistrust),
            CptE::Builtin(builtin) => builtin.do_connect(),
        }
    }
}
impl crate::connpt::Builtin {
    /// Try to connect on a "builtin" connect point.
    fn do_connect(&self) -> Result<Connection, ConnectError> {
        use crate::connpt::BuiltinVariant as BV;
        match self.builtin {
            BV::Abort => Err(ConnectError::ExplicitAbort),
        }
    }
}
impl crate::connpt::Connect<crate::connpt::Resolved> {
    /// Return the address that we should actually try to connect to, with its string representation
    /// set to the canonical address.
    fn find_connect_address(
        &self,
        mistrust: &Mistrust,
    ) -> Result<AddrWithStr<general::SocketAddr>, ConnectError> {
        use crate::connpt::ConnectAddress::*;

        // Find the target address.
        let mut addr = match &self.socket {
            InetAuto(auto_addr) => {
                let socket_address_file = self.socket_address_file.as_ref().ok_or_else(|| {
                    ConnectError::Internal(
                        "Absent socket_address_file should have been rejected earlier".into(),
                    )
                })?;
                let addr_from_disk = mistrust
                    .verifier()
                    .permit_readable()
                    .file_access()
                    .read_to_string(socket_address_file)
                    .map_err(ConnectError::SocketAddressFileAccess)?;
                let addrfile: AddressFile = serde_json::from_str(&addr_from_disk)
                    .map_err(|e| ConnectError::SocketAddressFileJson(Arc::new(e)))?;
                let address: AddrWithStr<general::SocketAddr> = addrfile
                    .address
                    .parse()
                    .map_err(ConnectError::SocketAddressFileContent)?;
                auto_addr.validate_parsed_address(address.as_ref())?;
                address
            }
            Socket(addr) => addr.clone(),
        };
        // Override the string if needed.
        if let Some(canon) = &self.socket_canonical {
            addr.set_string_from(canon);
        }
        Ok(addr)
    }

    /// Try to connect on a "Connect" connect point.
    fn do_connect(&self, mistrust: &Mistrust) -> Result<Connection, ConnectError> {
        use crate::connpt::Auth;
        use tor_general_addr::general::SocketAddr as SA;
        let connect_to_address = self.find_connect_address(mistrust)?;
        let auth = match &self.auth {
            Auth::None => RpcAuth::Inherent,
            Auth::Cookie { path } => RpcAuth::Cookie {
                secret: RpcCookieSource::Unloaded(CookieLocation {
                    path: path.clone(),
                    mistrust: mistrust.clone(),
                }),
                server_address: connect_to_address.as_str().to_string(),
            },
            // This is unreachable, but harmless:
            Auth::Unrecognized(_) => return Err(ConnectError::UnsupportedAuthType),
        };
        if let Some(sock_parent_dir) = crate::socket_parent_path(connect_to_address.as_ref()) {
            mistrust.check_directory(sock_parent_dir)?;
        }
        let stream = match connect_to_address.as_ref() {
            SA::Inet(addr) => {
                let socket = TcpStream::connect(addr)?;
                Stream::Tcp(socket)
            }
            #[cfg(unix)]
            SA::Unix(addr) => {
                let socket = UnixStream::connect_addr(addr)?;
                Stream::Unix(socket)
            }
            _ => return Err(ConnectError::UnsupportedSocketType),
        };

        Ok(Connection { stream, auth })
    }
}
