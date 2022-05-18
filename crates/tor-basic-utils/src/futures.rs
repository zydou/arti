//! Futures helpers

use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::future::FusedFuture;
use futures::ready;
use futures::Sink;
use pin_project::pin_project;

/// Switch to the nontrivial version of this, to get debugging output on stderr
macro_rules! dprintln { { $f:literal $($a:tt)* } => { } }
//macro_rules! dprintln { { $f:literal $($a:tt)* } => { eprintln!(concat!("    ",$f) $($a)*) } }

/// Extension trait for [`Sink`]
pub trait SinkExt<'w, OS, OM>
where
    OS: Sink<OM>,
{
    /// For processing an item obtained from a future, avoiding async cancel lossage
    ///
    /// Prepares to send a output message `OM` to an input stream `OS` (`self`),
    /// where the `OM` is made from an input message `IM`,
    /// and the `IM` is obtained from a future, `generator: IF`.
    // This slightly inconsistent terminology, "item" vs "message",
    // avoids having to have the generic parameters named `OI` and `II`
    // where `I` is sometimes "item" and sometimes "input".
    ///
    /// When successfully run, `prepare_send_from` gives `(IM, SinkSendable)`.
    ///
    /// After processing `IM` into `OM`,
    /// use the [`SinkSendable`] to [`send`](SinkSendable::send) the `OM` to `OS`.
    ///
    /// # Why use this
    ///
    /// This avoids the following async cancellation hazaard
    /// which exists with naive use of `select!`
    /// followed by `OS.send().await`:
    ///
    /// If the input is ready, the corresponding `select!` branch
    /// will trigger, yielding the next input item.  Then, if the output is *not* ready, awaiting
    /// will have that arm return `Pending`, disscarding the item.
    ///
    /// # Example
    ///
    /// This comprehensive example demonstrates how to read from possibly multiple sources
    /// and also be able to process other events:
    ///
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    /// use futures::select;
    /// use futures::{SinkExt as _, StreamExt as _};
    /// use tor_basic_utils::futures::SinkExt as _;
    ///
    /// let (mut input_w, mut input_r) = futures::channel::mpsc::unbounded::<usize>();
    /// let (mut output_w, mut output_r) = futures::channel::mpsc::unbounded::<String>();
    /// input_w.send(42).await;
    /// select!{
    ///     ret = output_w.prepare_send_from(async {
    ///         select!{
    ///             got_input = input_r.next() => got_input.expect("input stream ended!"),
    ///             () = futures::future::pending() => panic!(), // other branches are OK here
    ///         }
    ///     }) => {
    ///         let (input_msg, sendable) = ret.unwrap();
    ///         let output_msg = input_msg.to_string();
    ///         let () = sendable.send(output_msg).unwrap();
    ///     },
    ///     () = futures::future::pending() => panic!(), // other branches are OK here
    /// }
    ///
    /// assert_eq!(output_r.next().await.unwrap(), "42");
    /// # }
    /// ```
    ///
    /// # Formally
    ///
    /// [`prepare_send_from`](SinkExt::prepare_send_from)
    ///
    ///  * Waits for `OS` to be ready to receive an item.
    ///  * Runs `message_generator` to obtain a `IM`.
    ///  * Returns the `IM` (for processing), and a [`SinkSendable`].
    ///
    /// The caller should then:
    ///
    ///  * Check the error from `prepare_send_from`
    ///    (which came from the *output* stream).
    ///  * Process the `IM`, making an `OM` out of it.
    ///  * Call [`sendable.send()`](SinkSendable::send) (and check its error).
    ///
    /// # Flushing
    ///
    /// `prepare_send_from` will [`flush`](futures::SinkExt::flush) the output sink
    /// when it finds the input is not ready yet.
    /// Until then items may be buffered
    /// (as if they had been written with [`feed`](futures::SinkExt::feed)).
    ///
    /// # Errors
    ///
    /// ## Output sink errors
    ///
    /// The call site can experience output sink errors in two places,
    /// [`prepare_send_from()`](SinkExt::prepare_send_from) and [`SinkSendable::send()`].
    /// The caller should typically handle them the same way regardless of when they occurred.
    ///
    /// If the error happens at [`SinkSendable::send()`],
    /// the call site will usually be forced to discard the item being processed.
    /// This will only occur if the sink is actually broken.
    ///
    /// ## Errors specific to the call site: faillible input, and fallible processing
    ///
    /// At some call sites, the input future may yield errors
    /// (perhaps it is reading from a `Stream` of [`Result`]s).
    /// in that case the value from the input future will be a [`Result`].
    /// Then `IM` is a `Result`, and is provided in the `.0` element
    /// of the "successful" return from `prepare_send_from`.
    ///
    /// And, at some call sites, the processing of an `IM` into an `OM` is fallible.
    ///
    /// Handling these latter two error caess is up to the caller,
    /// in the code which processes `IM`.
    /// The call site will often want to deal with such an error
    /// without sending anything into the output sink,
    /// and can then just drop the [`SinkSendable`].
    ///
    /// # Implementations
    ///
    /// This is an extension trait and you are not expected to need to implement it.
    ///
    /// There are provided implementations for `Pin<&mut impl Sink>`
    /// and `&mut impl Sink + Unpin`, for your convenience.
    fn prepare_send_from<IF, IM>(
        self,
        message_generator: IF,
    ) -> SinkPrepareSendFuture<'w, IF, OS, OM>
    where
        IF: Future<Output = IM>;
}

impl<'w, OS, OM> SinkExt<'w, OS, OM> for Pin<&'w mut OS>
where
    OS: Sink<OM>,
{
    fn prepare_send_from<'r, IF, IM>(
        self,
        message_generator: IF,
    ) -> SinkPrepareSendFuture<'w, IF, OS, OM>
    where
        IF: Future<Output = IM>,
    {
        SinkPrepareSendFuture {
            output: Some(self),
            generator: message_generator,
            tw: PhantomData,
        }
    }
}

impl<'w, OS, OM> SinkExt<'w, OS, OM> for &'w mut OS
where
    OS: Sink<OM> + Unpin,
{
    fn prepare_send_from<'r, IF, IM>(
        self,
        message_generator: IF,
    ) -> SinkPrepareSendFuture<'w, IF, OS, OM>
    where
        IF: Future<Output = IM>,
    {
        Pin::new(self).prepare_send_from(message_generator)
    }
}

/// Future for `SinkExt::prepare_send_from`
#[pin_project]
#[must_use]
pub struct SinkPrepareSendFuture<'w, IF, OS, OM> {
    #[pin]
    generator: IF,
    // This Option exists because otherwise SinkPrepareSendFuture::poll()
    // can't move `output` out of this struct to put it into the `SinkSendable`.
    // (The poll() impl cannot borrow from SinkPrepareSendFuture.)
    output: Option<Pin<&'w mut OS>>,
    tw: PhantomData<fn(OM)>,
}

/// A [`Sink`] which is ready to receive an item
///
/// Produced by [`SinkExt::prepare_send_from`].  See there for the overview docs.
///
/// This references an output sink `OS`.
/// It offers the ability to write into the sink without blocking,
/// (and constitutes a proof token that the sink has declared itself ready for that).
///
/// The only useful method is [`send`](SinkSendable::send).
#[must_use]
pub struct SinkSendable<'w, OS, OM> {
    output: Pin<&'w mut OS>,
    tw: PhantomData<fn(OM)>,
}

impl<'w, IF, OS, IM, OM> Future for SinkPrepareSendFuture<'w, IF, OS, OM>
where
    IF: Future<Output = IM>,
    OS: Sink<OM>,
{
    type Output = Result<(IM, SinkSendable<'w, OS, OM>), OS::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut self_ = self.project();

        let () = match ready!(self_.output.as_mut().unwrap().as_mut().poll_ready(cx)) {
            Err(e) => {
                dprintln!("poll: output poll = IF.Err    SO  IF.Err");
                // Deliberately don't fuse by taking output
                return Poll::Ready(Err(e));
            }
            Ok(x) => {
                dprintln!("poll: output poll = IF.Ok     calling generator");
                x
            }
        };

        let value = match self_.generator.as_mut().poll(cx) {
            Poll::Pending => {
                // We defer flushing the output until the input stops yielding.
                // Or to put it another way, we do not return `Pending` without flushing.
                dprintln!("poll: generator = Pending     calling output flush");
                let flushed = self_.output.as_mut().unwrap().as_mut().poll_flush(cx);
                return match flushed {
                    Poll::Ready(Err(e)) => {
                        dprintln!("poll: output flush = IF.Err   SO  IF.Err");
                        Poll::Ready(Err(e))
                    }
                    Poll::Ready(Ok(())) => {
                        dprintln!("poll: output flush = IF.Ok    SO  Pending");
                        Poll::Pending
                    }
                    Poll::Pending => {
                        dprintln!("poll: output flush = Pending  SO  Pending");
                        Poll::Pending
                    }
                };
            }
            Poll::Ready(v) => {
                dprintln!("poll: generator = Ready       SO  IF.Ok");
                v
            }
        };

        let sendable = SinkSendable {
            output: self_.output.take().unwrap(),
            tw: PhantomData,
        };

        Poll::Ready(Ok((value, sendable)))
    }
}

impl<'w, IF, OS, IM, OM> FusedFuture for SinkPrepareSendFuture<'w, IF, OS, OM>
where
    IF: Future<Output = IM>,
    OS: Sink<OM>,
{
    fn is_terminated(&self) -> bool {
        let r = self.output.is_none();
        dprintln!("is_terminated = {}", r);
        r
    }
}

impl<'w, OS, OM> SinkSendable<'w, OS, OM>
where
    OS: Sink<OM>,
{
    /// Synchronously send an item into `OS`, which is a [`Sink`]
    ///
    /// Can fail if the sink `OS` reports an error.
    ///
    /// (However, the existence of the `SinkSendable` demonstrates that
    /// the sink reported itself ready for sending,
    /// so this call is synchronous, avoding cancellation hazards.)
    pub fn send(self, item: OM) -> Result<(), OS::Error> {
        dprintln!("send ...");
        let r = self.output.start_send(item);
        dprintln!("send: {:?}", r.as_ref().map_err(|_| (())));
        r
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // why is this not the default in tests
mod test {
    use super::*;
    use futures::channel::mpsc;
    use futures::future::poll_fn;
    use futures::select_biased;
    use futures::SinkExt as _;
    use futures_await_test::async_test;
    use std::convert::Infallible;
    use std::sync::Arc;
    use std::sync::Mutex;

    #[derive(Debug, Eq, PartialEq)]
    struct TestError(char);

    #[async_test]
    async fn prepare_send() {
        // Early versions of this used unfold quite a lot more, but it is not really
        // convenient for testing.  It buffers one item internally, and is also buggy:
        //   https://github.com/rust-lang/futures-rs/issues/2600
        // So we use mpsc channels, which (perhaps with buffering) are quite controllable.

        // The eprintln!("FOR ...") calls correspond go the dprintln1() calls in the impl,
        // and can check that each code path in the impementation is used,
        // by turning on the dbug and using `--nocapture`.
        {
            eprintln!("-- disconnected ---");
            eprintln!("FOR poll: output poll = IF.Err    SO  IF.Err");
            let (mut w, r) = mpsc::unbounded::<usize>();
            drop(r);
            let ret = w.prepare_send_from(async { Ok::<_, Infallible>(12) }).await;
            assert!(ret.map(|_| ()).unwrap_err().is_disconnected());
        }

        {
            eprintln!("-- buffered late disconnect --");
            eprintln!("FOR poll: output poll = IF.Ok     calling generator");
            eprintln!("FOR poll: output flush = IF.Err   SO  IF.Err");
            let (w, r) = mpsc::unbounded::<usize>();
            let mut w = w.buffer(10);
            let mut r = Some(r);
            w.feed(66).await.unwrap();
            let ret = w
                .prepare_send_from(poll_fn(move |_cx| {
                    drop(r.take());
                    Poll::Pending::<usize>
                }))
                .await;
            assert!(ret.map(|_| ()).unwrap_err().is_disconnected());
        }

        {
            eprintln!("-- flushing before wait --");
            eprintln!("FOR poll: output flush = IF.Ok    SO  Pending");
            let (mut w, _r) = mpsc::unbounded::<usize>();
            let () = select_biased! {
                _ = w.prepare_send_from(poll_fn(
                    move |_cx| {
                        Poll::Pending::<usize>
                    }
                )) => panic!(),
                _ = futures::future::ready(()) => { },
            };
        }

        {
            eprintln!("-- flush before wait is pending --");
            eprintln!("FOR poll: output flush = Pending  SO  Pending");
            let (mut w, _r) = mpsc::channel::<usize>(0);
            let () = w.feed(77).await.unwrap();
            let mut w = w.buffer(10);
            let () = select_biased! {
                _ = w.prepare_send_from(poll_fn(
                    move |_cx| {
                        Poll::Pending::<usize>
                    }
                )) => panic!(),
                _ = futures::future::ready(()) => { },
            };
        }

        {
            eprintln!("-- flush before wait is pending --");
            eprintln!("FOR poll: generator = Ready       SO  IF.Ok");
            eprintln!("FOR send ...");
            eprintln!("ALSO check that bufferinrg works as expected");

            let sunk = Arc::new(Mutex::new(vec![]));
            let unfold = futures::sink::unfold((), |(), v| {
                let sunk = sunk.clone();
                async move {
                    dbg!();
                    sunk.lock().unwrap().push(v);
                    Ok::<_, Infallible>(())
                }
            });
            let mut unfold = Box::pin(unfold.buffer(10));
            for v in [42, 43] {
                // We can only do two here because that's how many we can actually buffer in Buffer
                // and Unfold.  Because our closure is always ready, the buffering isn't actually
                // as copious as all that.  This is fine, because the point of this test is to test
                // *flushing*.
                dbg!(v);
                let ret = unfold
                    .prepare_send_from(async move { Ok::<_, Infallible>(v) })
                    .await;
                let (msg, sendable) = ret.unwrap();
                let msg = msg.unwrap();
                assert_eq!(msg, v);
                let () = sendable.send(msg).unwrap();
                assert_eq!(*sunk.lock().unwrap(), &[]); // It's still buffered
            }
            select_biased! {
                _ = unfold.prepare_send_from(futures::future::pending::<()>()) => panic!(),
                _ = futures::future::ready(()) => { },
            };
            assert_eq!(*sunk.lock().unwrap(), &[42, 43]);
        }
    }
}
