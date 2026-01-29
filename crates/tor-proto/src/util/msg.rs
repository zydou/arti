//! Module exposing channel message-related utilities.

use tor_cell::chancell::msg::Relay;

use either::Either;

/// A trait implemented by subclasses of `ChanMsg`
/// that support [`Relay`] messages.
///
// TODO(relay): this trait is an implementation detail of the new circuit reactor.
// It should not be implemented for other message types, nor exposed
// outside of tor-proto.
//
// We might decide to remove this in a future iteration of the circuit reactor,
// if we find a different way of doing implementation-agnostic RELAY message handling.
pub(crate) trait ToRelayMsg {
    /// Try to return this message type as a [`Relay`].
    ///
    /// Returns `Left` if this is a [`Relay`] message,
    /// or a `Right` containing the unmodified `self` otherwise.
    fn to_relay_msg(self) -> Either<Relay, Self>
    where
        Self: Sized;
}
