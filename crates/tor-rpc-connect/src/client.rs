//! Client operations for working with connect points.

use std::{io, net::TcpStream};

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use fs_mistrust::Mistrust;

use crate::{
    auth::{cookie::Cookie, RpcAuth},
    ConnectError, ResolvedConnectPoint,
};

/// Information about an initial connection to a connect point.
#[non_exhaustive]
pub struct Connection {
    /// A reading instance successfully connected socket.
    pub reader: Box<dyn io::Read + Send>,
    /// A writing instance successfully connected socket.
    pub writer: Box<dyn io::Write + Send>,

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
            Auth::Unrecognized {} => return Err(ConnectError::UnsupportedAuthType),
        };
        if let Some(sock_parent_dir) = crate::socket_parent_path(self.socket.as_ref()) {
            mistrust.check_directory(sock_parent_dir)?;
        }
        // TODO: we currently use try_clone() to get separate reader and writer instances.
        // conceivably, we could instead create something like the `Split` implementation that
        // exists for `AsyncRead + AsyncWrite` objects in futures::io.
        let (reader, writer): (Box<dyn io::Read + Send>, Box<dyn io::Write + Send>) =
            match self.socket.as_ref() {
                SA::Inet(addr) => {
                    let socket = TcpStream::connect(addr)?;
                    (Box::new(socket.try_clone()?), Box::new(socket))
                }
                #[cfg(unix)]
                SA::Unix(addr) => {
                    let socket = UnixStream::connect_addr(addr)?;
                    (Box::new(socket.try_clone()?), Box::new(socket))
                }
                _ => return Err(ConnectError::UnsupportedSocketType),
            };

        Ok(Connection {
            reader,
            writer,
            auth,
        })
    }
}
