//! DNS streams

use tor_proto::stream::IncomingStream;

/// Handle an incoming DNS stream
pub(crate) async fn handle_resolve(_incoming: IncomingStream) -> anyhow::Result<()> {
    todo!()
}
