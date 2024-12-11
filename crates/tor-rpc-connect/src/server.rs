//! Server operations for working with connect points.

use crate::{
    auth::{Cookie, RpcAuth},
    ConnectError, ResolvedConnectPoint,
};
use fs_mistrust::Mistrust;
use tor_general_addr::general;
use tor_rtcompat::NetStreamProvider;

/// A listener and associated authentication at which an RPC server can watch for connections.
#[non_exhaustive]
pub struct Listener {
    /// The listener on which connections will arrive.
    pub listener: tor_rtcompat::general::Listener,
    /// The authentication to require from incoming connections.
    pub auth: RpcAuth,
}

impl ResolvedConnectPoint {
    /// Try to bind to a location as specified by this connect point.
    pub async fn bind<R>(&self, runtime: &R, mistrust: &Mistrust) -> Result<Listener, ConnectError>
    where
        R: NetStreamProvider<general::SocketAddr, Listener = tor_rtcompat::general::Listener>,
    {
        use crate::connpt::ConnectPointEnum as CptE;
        match &self.0 {
            CptE::Connect(connect) => connect.bind(runtime, mistrust).await,
            CptE::Builtin(builtin) => builtin.bind(),
        }
    }
}

impl crate::connpt::Builtin {
    /// Try to bind to a "Builtin" connect point.
    fn bind(&self) -> Result<Listener, ConnectError> {
        use crate::connpt::BuiltinVariant as BV;
        match self.builtin {
            BV::Abort => Err(ConnectError::ExplicitAbort),
        }
    }
}

impl crate::connpt::Connect<crate::connpt::Resolved> {
    /// Try to bind to a "Connect" connect point.
    async fn bind<R>(&self, runtime: &R, mistrust: &Mistrust) -> Result<Listener, ConnectError>
    where
        R: NetStreamProvider<general::SocketAddr, Listener = tor_rtcompat::general::Listener>,
    {
        if let Some(sock_parent_dir) = crate::socket_parent_path(self.socket.as_ref())? {
            // TODO RPC: Revisit this and other uses of make_directory; do we really want to do so?
            mistrust.make_directory(sock_parent_dir)?;
        }
        let listener = runtime.listen(self.socket.as_ref()).await?;

        // We try to bind to the listener before we (maybe) create the cookie file,
        // so that if we encounter an `EADDRINUSE` we won't overwrite the old cookie file.
        let auth = match &self.auth {
            crate::connpt::Auth::None => RpcAuth::None,
            crate::connpt::Auth::Cookie { path } => RpcAuth::Cookie {
                secret: Cookie::create(path.as_path(), &mut rand::thread_rng(), mistrust)?,
                server_address: self.socket.as_str().to_owned(),
            },
            crate::connpt::Auth::Unrecognized {} => return Err(ConnectError::UnsupportedAuthType),
        };

        Ok(Listener { listener, auth })
    }
}
