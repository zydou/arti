//! Experimental RPC support.

use anyhow::Result;
use arti_rpcserver::{RpcMgr, RpcSession};
use futures::task::SpawnExt;
use std::{path::Path, sync::Arc};

use arti_client::TorClient;
use tor_rtcompat::Runtime;

cfg_if::cfg_if! {
    if #[cfg(all(feature="tokio", not(target_os="windows")))] {
        use tokio_crate::net::UnixListener ;
        use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
    } else if #[cfg(all(feature="async-std", not(target_os="windows")))] {
        use async_std::os::unix::net::UnixListener;
    } else if #[cfg(target_os="windows")] {
        compile_error!("Sorry, no windows support for RPC yet.");
        // TODO RPC: Tokio has a named pipe API; AsyncStd should let us construct
        // one via FromRawHandle.
    } else {
        compile_error!("You need to have tokio or async-std.");
    }
}

/// Run an RPC listener task to accept incoming connections at the Unix
/// socket address of `path`.
pub(crate) fn launch_rpc_listener<R: Runtime>(
    runtime: &R,
    path: impl AsRef<Path>,
    client: TorClient<R>,
) -> Result<Arc<RpcMgr>> {
    // TODO RPC: there should be an error return instead.

    // TODO RPC: Maybe the UnixListener functionality belongs in tor-rtcompat?
    // But I certainly don't want to make breaking changes there if we can help
    // it.
    let listener = UnixListener::bind(path)?;
    let rpc_mgr =
        RpcMgr::new(move |_auth| RpcSession::new_with_client(Arc::new(client.isolated_client())));
    // Register methods. Needed since TorClient is generic.
    //
    // TODO: If we accumulate a large number of generics like this, we should do this elsewhere.
    rpc_mgr.register_rpc_methods(TorClient::<R>::rpc_methods());

    let rt_clone = runtime.clone();
    let rpc_mgr_clone = rpc_mgr.clone();

    // TODO: Using spawn in this way makes it hard to report whether we
    // succeeded or not. This is something we should fix when we refactor
    // our service-launching code.
    runtime.spawn(async {
        let result = run_rpc_listener(rt_clone, listener, rpc_mgr_clone).await;
        if let Err(e) = result {
            tracing::warn!("RPC manager quit with an error: {}", e);
        }
    })?;
    Ok(rpc_mgr)
}

/// Backend function to implement an RPC listener: runs in a loop.
async fn run_rpc_listener<R: Runtime>(
    runtime: R,
    listener: UnixListener,
    rpc_mgr: Arc<RpcMgr>,
) -> Result<()> {
    loop {
        let (stream, _addr) = listener.accept().await?;
        // TODO RPC: Perhaps we should have rpcmgr hold the client reference?
        let connection = rpc_mgr.new_connection();
        let (input, output) = stream.into_split();

        #[cfg(feature = "tokio")]
        let (input, output) = (input.compat(), output.compat_write());

        runtime.spawn(async {
            let result = connection.run(input, output).await;
            if let Err(e) = result {
                tracing::warn!("RPC session ended with an error: {}", e);
            }
        })?;
    }
}
