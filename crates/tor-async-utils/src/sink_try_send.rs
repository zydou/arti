//! [`SinkTrySend`]

use std::error::Error;
use std::pin::Pin;

use futures::Sink;

//---------- principal API ----------

/// A [`Sink`] with a `try_send` method like [`futures::channel::mpsc::Sender`'s]
pub trait SinkTrySend<T>: Sink<T> {
    /// Errors that is not disconnected, or full
    type Error: SinkTrySendError;

    /// Try to send a message `msg`
    ///
    /// If this returns with an error indicating that the stream is full,
    /// *No* arrangements will have been made for a wakeup when space becomes available.
    ///
    /// If the send fails, `item` is dropped.
    /// If you need it back, use [`try_send_or_return`](SinkTrySend::try_send_or_return),
    ///
    /// (When implementing the trait, implement this method.)
    fn try_send(self: Pin<&mut Self>, item: T) -> Result<(), <Self as SinkTrySend<T>>::Error> {
        self.try_send_or_return(item)
            .map_err(|(error, _item)| error)
    }

    /// Try to send a message `msg`
    ///
    /// Like [`try_send`](SinkTrySend::try_send),
    /// but if the send fails, the item is returned.
    ///
    /// (When implementing the trait, implement this method.)
    fn try_send_or_return(
        self: Pin<&mut Self>,
        item: T,
    ) -> Result<(), (<Self as SinkTrySend<T>>::Error, T)>;
}

/// Error from [`SinkTrySend::try_send`]
pub trait SinkTrySendError: Error + 'static {
    /// The stream was full.
    ///
    /// *No* arrangements will have been made for a wakeup when space becomes available.
    ///
    /// Corresponds to [`futures::channel::mpsc::TrySendError::is_full`]
    fn is_full(&self) -> bool;

    /// The stream has disconnected
    ///
    /// Corresponds to [`futures::channel::mpsc::TrySendError::is_disconnected`]
    fn is_disconnected(&self) -> bool;
}
