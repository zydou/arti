//! DNS streams

pub(crate) mod resolver;

use resolver::{DnsResolver, LookupAnswers, LookupError, RecordData};

use tor_cell::relaycell::msg::Resolved;
use tor_proto::stream::{IncomingStream, IncomingStreamRequest};

use tracing::trace;

/// The fake TTL to send back with every RESOLVED response.
///
/// This is a mitigation against the DNS cache oracle problem
/// that the original C Tor implementation suffered from.
///
/// See <https://gitlab.torproject.org/tpo/core/tor/-/issues/40979>
const FAKE_TTL_SECONDS: u32 = 60;

/// Handle an incoming DNS stream
///
/// Performs the DNS lookup, and closes `incoming` by sending back a RESOLVED message.
///
/// Returns an error if `incoming` is not a RESOLVE stream.
pub(crate) async fn handle_resolve(
    incoming: IncomingStream,
    mut resolver: DnsResolver,
) -> anyhow::Result<()> {
    let resolve = match incoming.request() {
        IncomingStreamRequest::Resolve(r) => r,
        s => return Err(anyhow::anyhow!("expected RESOLVE but got {s:?}")),
    };
    let res = resolver.resolve(resolve.query()).await;

    let resolved = lookup_to_resolved(res);
    trace!(cell=?resolved, "sending RESOLVED");

    incoming.resolve(resolved).await?;

    Ok(())
}

/// Build a [`Resolved`] message out of a lookup response.
///
/// Each of the returned answers will have the TTL set to a fake hard-coded value,
/// to avoid leaking the DNS cache insertion timestamps to the client.
//
// TODO(relay): we might want to return random fake TTLs instead
fn lookup_to_resolved(lookup_res: Result<LookupAnswers<RecordData>, LookupError>) -> Resolved {
    match lookup_res {
        Ok(answers) => {
            let mut resolved = Resolved::new_empty();
            if let Some(ans) = answers.first() {
                resolved.add_answer(ans.clone().into(), FAKE_TTL_SECONDS);
            }

            // TODO(relay): try to fit more answers in the RESOLVED

            resolved
        }
        Err(e) => Resolved::new_err(e.is_transient(), FAKE_TTL_SECONDS),
    }
}
