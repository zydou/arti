//! Functionality to connect to an RPC server.

use std::{io::BufReader, path::PathBuf, sync::Arc};

use crate::llconn;

use super::{ConnectError, RpcConn};

/// An error occurred while trying to construct or manipulate an [`RpcConnBuilder`].
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BuilderError {
    /// We couldn't decode a provided connect string.
    #[error("Invalid connect string.")]
    InvalidConnectString,
}

/// Information about how to construct a connection to an Arti instance.
pub struct RpcConnBuilder {
    /// A path to a unix domain socket at which Arti is listening.
    // TODO RPC: Right now this is the only kind of supported way to connect.
    unix_socket: PathBuf,
    // todo RPC: include selector for how to connect.
    //
    // TODO RPC: Possibly kill off the builder entirely.
}

// TODO: For FFI purposes, define a slightly higher level API that
// tries to do this all at once, possibly decoding a "connect string"
// and some optional secret stuff?
impl RpcConnBuilder {
    /// Create a Builder from a connect string.
    ///
    /// (Right now the only supported string type is "unix:" followed by a path.)
    //
    // TODO RPC: Should this take an OsString?
    //
    // TODO RPC: Specify the actual metaformat that we want to use here.
    // Possibly turn this into a K=V sequence ... or possibly, just
    // turn it into a JSON object.
    pub fn from_connect_string(s: &str) -> Result<Self, BuilderError> {
        let (kind, location) = s
            .split_once(':')
            .ok_or(BuilderError::InvalidConnectString)?;
        if kind == "unix" {
            Ok(Self::new_unix_socket(location))
        } else {
            Err(BuilderError::InvalidConnectString)
        }
    }

    /// Create a Builder to connect to a unix socket at a given path.
    ///
    /// Note that this function may succeed even in environments where
    /// unix sockets are not supported.  On these environments,
    /// the `connect` attempt will later fail with `SchemeNotSupported`.
    pub fn new_unix_socket(addr: impl Into<PathBuf>) -> Self {
        Self {
            unix_socket: addr.into(),
        }
    }

    /// Try to connect to an Arti process as specified by this Builder.
    pub fn connect(&self) -> Result<RpcConn, ConnectError> {
        #[cfg(not(unix))]
        {
            return Err(ConnectError::SchemeNotSupported);
        }
        #[cfg(unix)]
        {
            let sock = std::os::unix::net::UnixStream::connect(&self.unix_socket)
                .map_err(|e| ConnectError::CannotConnect(Arc::new(e)))?;
            let sock_dup = sock
                .try_clone()
                .map_err(|e| ConnectError::CannotConnect(Arc::new(e)))?;
            let mut conn = RpcConn::new(
                llconn::Reader::new(Box::new(BufReader::new(sock))),
                llconn::Writer::new(Box::new(sock_dup)),
            );

            let session_id = conn.authenticate_inherent("inherent:unix_path")?;
            conn.session = Some(session_id);

            Ok(conn)
        }
    }
}
