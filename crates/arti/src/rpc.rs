//! Experimental RPC support.

use anyhow::Result;
use arti_rpcserver::RpcMgr;
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

/// Launch an RPC listener task to accept incoming connections at the Unix
/// socket address of `path`.
pub(crate) async fn run_rpc_listener<R: Runtime>(
    runtime: R,
    path: impl AsRef<Path>,
    client: TorClient<R>,
) -> Result<()> {
    // TODO RPC: there should be an error return instead.

    // TODO RPC: Maybe the UnixListener functionality belongs in tor-rtcompat?
    // But I certainly don't want to make breaking changes there if we can help it.
    let listener = UnixListener::bind(path)?;
    let mgr = RpcMgr::new();

    loop {
        let (stream, _addr) = listener.accept().await?;
        let session = Arc::new(mgr.new_session(client.isolated_client()));
        let (input, output) = stream.into_split();

        #[cfg(feature = "tokio")]
        let (input, output) = (input.compat(), output.compat_write());

        runtime.spawn(async {
            let result = session.run(input, output).await;
            if let Err(e) = result {
                tracing::warn!("RPC session ended with an error: {}", e);
            }
        })?;
    }
}
