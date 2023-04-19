//! Extension trait for `Sink`.

use std::{
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{ready, sink::Sink};
use pin_project::pin_project;

/// Extension trait for `Sink`
pub trait SinkExt<Item>: Sink<Item> {
    /// As `Sink::with`, but takes a function that returns an `Item` rather
    /// than `Future<Output=Item>`.
    fn with_fn<F, T, E>(self, func: F) -> WithFn<Self, F, T, E>
    // or error?
    where
        Self: Sized,
        F: FnMut(T) -> Result<Item, E>,
        E: From<Self::Error>;
}

impl<Item, S> SinkExt<Item> for S
where
    S: Sink<Item>,
{
    fn with_fn<F, T, E>(self, func: F) -> WithFn<Self, F, T, E>
    where
        Self: Sized,
        F: FnMut(T) -> Result<Item, E>,
        E: From<Self::Error>,
    {
        WithFn {
            sink: self,
            func,
            _phantom: PhantomData,
        }
    }
}

/// Sink returned by [`SinkExt::with_fn`].
#[pin_project]
pub struct WithFn<S, F, T, E> {
    /// The underlying sink
    #[pin]
    sink: S,
    /// The user-provided function.
    func: F,
    /// Phantom data to ensure type consistency.
    _phantom: PhantomData<fn() -> Result<T, E>>,
}

impl<S, Item, F, T, E> Sink<T> for WithFn<S, F, T, E>
where
    S: Sink<Item>,
    F: FnMut(T) -> Result<Item, E>,
    E: From<S::Error>,
{
    type Error = E;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.project().sink.poll_ready(cx))?;
        Poll::Ready(Ok(()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.project().sink.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.project().sink.poll_close(cx))?;
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        let this = self.project();
        let item = (this.func)(item)?;
        this.sink.start_send(item).map_err(E::from)
    }
}
