//! Client operations for working with connect points.

use std::{fmt, io, net::TcpStream};

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use fs_mistrust::Mistrust;

use crate::{
    auth::{Cookie, RpcAuth},
    ConnectError, ResolvedConnectPoint,
};

/// Wrapper type for a socket that might be a `UnixStream` or a TcpSocket.
pub trait AnySocket: io::Read + io::Write + fmt::Debug {}
impl<T> AnySocket for T where T: io::Read + io::Write + fmt::Debug {}

/// Information about an initial connection to a connect point.
#[derive(Debug)]
#[non_exhaustive]
pub struct Connection {
    /// A successfully connected socket.
    pub socket: Box<dyn AnySocket>,
    /// Information about how to authenticate.
    pub auth: crate::auth::RpcAuth,
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
    /// Try to connect on a "Connect" connect point.
    fn do_connect(&self, mistrust: &Mistrust) -> Result<Connection, ConnectError> {
        use crate::connpt::Auth;
        use tor_general_addr::general::SocketAddr as SA;
        let auth = match &self.auth {
            Auth::None => RpcAuth::None,
            Auth::Cookie { path } => {
                let canonical_addr = self.socket_canonical.as_ref().unwrap_or(&self.socket);
                RpcAuth::Cookie {
                    // TODO RPC: We may want to _defer_ this load operations until the RPC connect
                    // has been accepted, to ensure that we can't read a partial cookie.
                    secret: Cookie::load(path.as_path(), mistrust)?,
                    server_address: canonical_addr.as_str().to_string(),
                }
            }
            // This is unreachable, but harmless:
            Auth::Unrecognized => return Err(ConnectError::UnsupportedAuthType),
        };
        if let Some(sock_parent_dir) = crate::socket_parent_path(self.socket.as_ref())? {
            mistrust.check_directory(sock_parent_dir)?;
        }
        let socket: Box<dyn AnySocket> = match self.socket.as_ref() {
            SA::Inet(addr) => Box::new(TcpStream::connect(addr)?),
            #[cfg(unix)]
            SA::Unix(addr) => Box::new(UnixStream::connect_addr(addr)?),
            _ => return Err(ConnectError::UnsupportedSocketType),
        };

        Ok(Connection { socket, auth })
    }
}
