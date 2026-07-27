//! Exit streams

use tor_proto::stream::IncomingStream;

/// Handle an incoming exit stream
pub(super) async fn handle_begin(_incoming: IncomingStream) -> anyhow::Result<()> {
    todo!()
}
