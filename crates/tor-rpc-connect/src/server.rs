//! Server operations for working with connect points.

use std::{io, path::PathBuf, sync::Arc};

use crate::{
    ConnectError, ResolvedConnectPoint,
    auth::{RpcAuth, RpcCookieSource, cookie::Cookie},
    connpt::{AddressFile, ConnectAddress},
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
    /// An object we must hold for as long as we're listening on this socket.
    pub guard: ListenerGuard,
}

/// An object to control shutdown for a listener.  We should drop it only when we're no longer
/// listening on the socket.
//
// TODO It might be neat to combine this with the stream of requests from listener,
// so that we can't accidentally drop one prematurely.
pub struct ListenerGuard {
    /// A handle to a file that should be deleted when this is dropped.
    #[allow(unused)]
    rm_guard: Option<UnlinkOnDrop>,
    /// A handle to a lockfile on disk.
    //
    // (Note that this field is ordered after rm_guard:
    // rust guarantees that fields are dropped in order.)
    #[allow(unused)]
    lock_guard: Option<fslock_guard::LockFileGuard>,
}

/// Object that unlinks a file when it is dropped.
struct UnlinkOnDrop(PathBuf);
impl Drop for UnlinkOnDrop {
    fn drop(&mut self) {
        let _ignore = std::fs::remove_file(&self.0);
    }
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
        // Create parent directory for socket if needed.
        if let ConnectAddress::Socket(bind_to_socket) = &self.socket {
            if let Some(sock_parent_dir) = crate::socket_parent_path(bind_to_socket.as_ref()) {
                mistrust.make_directory(sock_parent_dir)?;
            }
        }

        let af_unix_pathname = if let ConnectAddress::Socket(bind_to_socket) = &self.socket {
            bind_to_socket.as_ref().as_pathname()
        } else {
            None
        };

        let guard = if let Some(socket_path) = af_unix_pathname {
            // This socket has a representation in the filesystem.
            // We need an associated lock to make sure that we don't delete the socket
            // while it is in use.
            //
            // (We can't just rely on getting an EADDRINUSE when we bind the socket,
            // since AF_UNIX sockets give that error unconditionally if the file exists,
            // whether anybody has bound to it or not.
            // We can't just check whether the socket file exists,
            // since it might be a stale socket left over from a process that has crashed.
            // We can't lock the socket file itself,
            // since we need to delete it before we can bind to it.)
            let lock_path = {
                let mut p = socket_path.to_owned();
                p.as_mut_os_string().push(".lock");
                p
            };
            let lock_guard = Some(
                fslock_guard::LockFileGuard::try_lock(lock_path)?
                    .ok_or(ConnectError::AlreadyLocked)?,
            );
            // Now that we have the lock, we know that nobody else is listening on this socket.
            // Now we just remove any stale socket file before we bind.)
            match std::fs::remove_file(socket_path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(other) => return Err(other.into()),
            }

            let rm_guard = Some(UnlinkOnDrop(socket_path.to_owned()));
            ListenerGuard {
                rm_guard,
                lock_guard,
            }
        } else {
            ListenerGuard {
                rm_guard: None,
                lock_guard: None,
            }
        };

        let (listener, chosen_address) = self.socket.bind(runtime).await?;

        if let Some(addr_file) = &self.socket_address_file {
            let file_contents = serde_json::to_string(&AddressFile {
                address: chosen_address.clone(),
            })
            .expect("Unable to serialize address!");

            mistrust
                .verifier()
                .permit_readable()
                .file_access()
                .write_and_replace(addr_file, file_contents)
                .map_err(ConnectError::SocketAddressFileAccess)?;
        };

        // We try to bind to the listener before we (maybe) create the cookie file,
        // so that if we encounter an `EADDRINUSE` we won't overwrite the old cookie file.
        let auth = match &self.auth {
            crate::connpt::Auth::None => RpcAuth::Inherent,
            crate::connpt::Auth::Cookie { path } => RpcAuth::Cookie {
                secret: RpcCookieSource::Loaded(Arc::new(Cookie::create(
                    path.as_path(),
                    &mut rand::rng(),
                    mistrust,
                )?)),
                server_address: chosen_address,
            },
            crate::connpt::Auth::Unrecognized(_) => return Err(ConnectError::UnsupportedAuthType),
        };

        Ok(Listener {
            listener,
            auth,
            guard,
        })
    }
}
