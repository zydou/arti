//! Example code for listening for incoming connections.
//!
//! TODO RPC: This doesn't belong here, I think.  But we want it to be at a
//! lower level than the `arti` crate.

use futures::stream::StreamExt;
use std::io::Result;
use std::path::Path;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio_crate as tokio;

use crate::msgs::{BoxedResponse, Request};

/// Listen for incoming connections at a unix path, and handle them as RPC
/// connections.  Runs forever, or until an error occurs.
///
/// TODO RPC: This API is temporary and should be replaced. It's just here for
/// testing.  For now, it only works on unix, and only with tokio.
pub async fn accept_connections<P: AsRef<Path>>(path: P) -> Result<()> {
    use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
    // TODO RPC: there should be an error return instead.

    // TODO RPC: Maybe the UnixListener functionality belongs in tor-rtcompat?
    // But I certainly don't want to make breaking changes there if we can help it.
    let listener = UnixListener::bind(path)?;

    loop {
        let (stream, _addr) = listener.accept().await?;
        let session = Arc::new(crate::session::Session::new());
        let (input, output) = stream.into_split();
        let input = Box::pin(
            asynchronous_codec::FramedRead::new(
                input.compat(),
                asynchronous_codec::JsonCodec::<(), Request>::new(),
            )
            .fuse(),
        );
        let output = Box::pin(asynchronous_codec::FramedWrite::new(
            output.compat_write(),
            crate::streams::JsonLinesEncoder::<BoxedResponse>::default(),
        ));

        tokio::spawn(async {
            let result = session.run_loop(input, output).await;
            if let Err(e) = result {
                tracing::warn!("session ended with an error: {}", e);
            }
        });
    }
}
