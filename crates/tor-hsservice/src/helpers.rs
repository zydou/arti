//! Functions to help working with onion services.

use crate::internal_prelude::*;

/// Consume a stream of [`RendRequest`], accepting them all, and produce a
/// stream of [`StreamRequest`].
///
/// If you want to reject certain [`RendRequest`]s, you can use [`StreamExt::filter`] or
/// similar in order to remove them from the incoming stream.
pub fn handle_rend_requests<S>(rend_requests: S) -> impl Stream<Item = StreamRequest>
where
    S: Stream<Item = RendRequest>,
{
    rend_requests.flat_map_unordered(None, |rend_request| {
        Box::pin(rend_request.accept())
            .map(|outcome| match outcome {
                Ok(stream_requests) => Either::Left(stream_requests),
                Err(e) => {
                    warn_report!(e, "Problem while accepting rendezvous request");
                    Either::Right(stream::empty())
                }
            })
            .flatten_stream()
    })
}
