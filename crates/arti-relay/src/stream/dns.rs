//! DNS streams

pub(crate) mod resolver;

use resolver::{DnsResolver, LookupAnswers, LookupError};

use tor_proto::stream::IncomingStream;

/// The fake TTL to send back with every RESOLVED response.
///
/// This is a mitigation against the DNS cache oracle problem
/// that the original C Tor implementation suffered from.
///
/// See <https://gitlab.torproject.org/tpo/core/tor/-/issues/40979>
const FAKE_TTL_SECONDS: u32 = 60;

/// Handle an incoming DNS stream
#[allow(clippy::unused_async)] // TODO(relay)
pub(crate) async fn handle_resolve(
    _incoming: IncomingStream,
    resolver: DnsResolver,
) -> anyhow::Result<()> {
    todo!()
}
