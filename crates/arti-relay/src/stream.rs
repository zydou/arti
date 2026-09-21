//! Stream handling logic

mod directory;
pub(crate) mod dns;
mod exit;

use dns::resolver::DnsResolver;

use tor_error::warn_report;
use tor_proto::circuit::CircHopSyncView;
use tor_proto::relay::CircuitIncomingStreamReceiver;
use tor_proto::stream::{
    IncomingStream, IncomingStreamRequest, IncomingStreamRequestContext,
    IncomingStreamRequestDisposition, IncomingStreamRequestFilter,
};
use tor_rtcompat::{Runtime, SpawnExt as _};

use futures::channel::mpsc;
use futures::{Stream, StreamExt as _};

// TODO(#2570): once we dust settles on the implementation,
// we need to factor this out of the client module.
use tor_proto::client::stream::DataStream;

/// Filter callback used to enforce early requirements on streams,
/// acting as an [`IncomingStreamRequestFilter`].
#[derive(Clone, Debug, Default)]
pub(crate) struct RequestFilter {
    // TODO(relay): implement
}

impl IncomingStreamRequestFilter for RequestFilter {
    fn disposition(
        &mut self,
        _ctx: &IncomingStreamRequestContext<'_>,
        _circ: &CircHopSyncView<'_>,
    ) -> tor_proto::Result<IncomingStreamRequestDisposition> {
        // TODO(relay): enforce the checks mentioned in relay-streams.md
        Ok(IncomingStreamRequestDisposition::Accept)
    }
}

/// Handle all the incoming streams arriving on all the circuits
pub(crate) async fn handle_incoming_streams<R: Runtime>(
    runtime: R,
    begin_dir_tx: mpsc::Sender<tor_proto::Result<DataStream>>,
    mut stream_rx: CircuitIncomingStreamReceiver,
    resolver: DnsResolver,
) -> anyhow::Result<void::Void> {
    while let Some(stream) = stream_rx.next().await {
        // Each circuit gets its own stream-handling task
        let rt = runtime.clone();
        let begin_dir_tx = begin_dir_tx.clone();
        runtime.spawn(handle_circuit_incoming_streams(
            rt,
            stream,
            begin_dir_tx,
            resolver.clone(),
        ))?;
    }

    Err(anyhow::anyhow!("stream handling task exited"))
}

/// Handle all the incoming stream requests (BEGIN, BEGIN_DIR, or RESOLVE)
/// arriving on a particular circuit.
async fn handle_circuit_incoming_streams<R: Runtime>(
    runtime: R,
    mut stream: impl Stream<Item = IncomingStream> + Unpin,
    begin_dir_tx: mpsc::Sender<tor_proto::Result<DataStream>>,
    resolver: DnsResolver,
) {
    while let Some(tor_stream) = stream.next().await {
        let begin_dir_tx = begin_dir_tx.clone();

        let resolver = resolver.clone();
        // Spawn a new task for each individual stream
        if let Err(e) = runtime.spawn(async move {
            let res = match tor_stream.request() {
                IncomingStreamRequest::Begin(_) => exit::handle_begin(tor_stream).await,
                IncomingStreamRequest::BeginDir(_) => {
                    directory::handle_begin_dir(tor_stream, begin_dir_tx).await
                }
                IncomingStreamRequest::Resolve(_) => {
                    dns::handle_resolve(tor_stream, resolver.clone()).await
                }
                s => Err(anyhow::anyhow!("unknown stream request kind {s:?}")),
            };

            if let Err(e) = res {
                warn_report!(e, "Could not handle incoming stream");
            }
        }) {
            warn_report!(e, "Failed to launch incoming stream handler task");
        }
    }
}
