//! Rate limiter objects backed by a shared [`crate::bw_pool::BandwidthPool`] making them
//! global as in sharable accross multiple thread/tasks.
//!
//! Available in this module is:
//!     * A [`sink::GlobalRateLimitedSink`] that implements [`futures::Sink`].
//!
//! Please read carefully each submodule documentation before using. These can be tricky
//! to operate without a license ;).

mod sink;

pub use sink::GlobalRateLimitedSink;

/// Error returned by the rate limiters in this module.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GlobalRateLimitedError<E> {
    /// The bandwidth pool was closed. No more refiller.
    #[error("bandwidth pool closed")]
    Pool(#[from] crate::bw_pool::PoolClosed),
    /// The underlying sink failed.
    #[error("underlying sink error")]
    Sink(#[source] E),
    /// No permit
    #[error("no permit when sending")]
    MissingPermit,
}
