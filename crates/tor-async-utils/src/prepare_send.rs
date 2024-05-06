//! Extension trait for using [`Sink`] more safely.

use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::future::FusedFuture;
use futures::ready;
use futures::Sink;
use pin_project::pin_project;

/// Switch to the nontrivial version of this, to get debugging output on stderr
macro_rules! dprintln { { $f:literal $($a:tt)* } => { () } }
//macro_rules! dprintln { { $f:literal $($a:tt)* } => { eprintln!(concat!("    ",$f) $($a)*) } }

/// Extension trait for [`Sink`] to add a method for cancel-safe usage.
pub trait SinkPrepareExt<'w, OS, OM>
where
    OS: Sink<OM>,
{
    /// For processing an item obtained from a future, avoiding async cancel lossage
    ///
    /// ```
    /// # use futures::channel::mpsc;
    /// # use tor_async_utils::SinkPrepareExt as _;
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<(),mpsc::SendError> {
    /// #   let (mut sink, sink_r) = mpsc::unbounded::<usize>();
    /// #   let message_generator_future = futures::future::ready(42);
    /// #   let process_message = |m| Ok::<_,mpsc::SendError>(m);
    ///     let (message, sendable) = sink.prepare_send_from(
    ///         message_generator_future
    ///     ).await?;
    ///     let message = process_message(message)?;
    ///     sendable.send(message);
    /// #   Ok(())
    /// # }
    /// ```
    ///
    /// Prepares to send a output message[^terminology] `OM` to an output sink `OS` (`self`),
    /// where the `OM` is made from an input message `IM`,
    /// and the `IM` is obtained from a future, `generator: IF`.
    ///
    /// [^terminology]: We sometimes use slightly inconsistent terminology,
    /// "item" vs "message".
    /// This avoids having to have the generic parameters by named `OI` and `II`
    /// where `I` is sometimes "item" and sometimes "input".
    ///
    /// When successfully run, `prepare_send_from` gives `(IM, SinkSendable)`.
    ///
    /// After processing `IM` into `OM`,
    /// use the [`SinkSendable`] to [`send`](SinkSendable::send) the `OM` to `OS`.
    ///
    /// # Why use this
    ///
    /// This avoids the an async cancellation hazard
    /// which exists with naive use of `select!`
    /// followed by `OS.send().await`.  You might write this:
    ///
    /// ```rust,ignore
    /// select!{
    ///     message = input_stream.next() => {
    ///         if let Some(message) = message {
    ///             let message = do_our_processing(message);
    ///             output_sink(message).await; // <---**BUG**
    ///         }
    ///     }
    ///     control = something_else() => { .. }
    /// }
    /// ```
    ///
    /// If, when we reach `BUG`, the output sink is not ready to receive the message,
    /// the future for that particular `select!` branch will be suspended.
    /// But when `select!` finds that *any one* of the branches is ready,
    /// it *drops* the futures for the other branches.
    /// That drops all the local variables, including possibly `message`, losing it.
    ///
    /// For more about cancellation safety, see
    /// [Rust for the Polyglot Programmer](https://www.chiark.greenend.org.uk/~ianmdlvl/rust-polyglot/async.html#cancellation-safety)
    /// which has a general summary, and
    /// Matthias Einwag's
    /// [extensive discussion in his gist](https://gist.github.com/Matthias247/ffc0f189742abf6aa41a226fe07398a8#cancellation-in-async-rust)
    /// with comparisons to other languages.
    ///
    /// ## Alternatives
    ///
    /// Unbounded mpsc channels, and certain other primitives,
    /// do not suffer from this problem because they do not block.
    /// `UnboundedSender` offers
    /// [`unbounded_send`](futures::channel::mpsc::UnboundedSender::unbounded_send)
    /// but only as an inherent method, so this does not compose with `Sink` combinators.
    /// And of course unbounded channels do not implement any backpressure.
    ///
    /// The problem can otherwise be avoided by completely eschewing use of `select!`
    /// and writing manual implementations of `Future`, `Sink`, and so on,
    /// However, such code is typically considerably more complex and involves
    /// entangling the primary logic with future machinery.
    /// It is normally better to write primary functionality in `async { }`
    /// using utilities (often "futures combinators") such as this one.
    ///
    // Personal note from @Diziet:
    // IMO it is generally accepted in the Rust community that
    // it is not good practice to write principal code at the manual futues level.
    // However, I have not been able to find very clear support for this proposition.
    // There are endless articles explaining how futures work internally,
    // often by describing how to reimplement standard combinators such as `map`.
    // ISTM that these exist to help understanding,
    // but it seems to be only rarely stated that doing this is not generally a good idea.
    //
    // I did find the following:
    //
    //  https://dev.to/mindflavor/rust-futures-an-uneducated-short-and-hopefully-not-boring-tutorial---part-4---a-real-future-from-scratch-734#conclusion
    //
    //    Of course you generally do not write a future manually. You use the ones provided by
    //    libraries and compose them as needed. It's important to understand how they work
    //    nevertheless.
    //
    // And of curse the existence of the `futures` crate is indicative:
    // it consists almost entirely of combinators and utilities
    // whose purpose is to allow you to write many structures in async code
    // without needing to resort to manual future impls.
    //
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
    /// use tor_async_utils::SinkPrepareExt as _;
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
    /// [`prepare_send_from`](SinkPrepareExt::prepare_send_from)
    /// returns a [`SinkPrepareSendFuture`] which, when awaited:
    ///
    ///  * Waits for `OS` to be ready to receive an item.
    ///  * Runs `message_generator` to obtain a `IM`.
    ///  * Returns the `IM` (for processing), and a [`SinkSendable`].
    ///
    /// The caller should then:
    ///
    ///  * Check the error from `prepare_send_from`
    ///    (which came from the *output* sink).
    ///  * Process the `IM`, making an `OM` out of it.
    ///  * Call [`sendable.send()`](SinkSendable::send) (and check its error).
    ///
    /// # Flushing
    ///
    /// `prepare_send_from` will (when awaited)
    /// [`flush`](futures::SinkExt::flush) the output sink
    /// when it finds the input is not ready yet.
    /// Until then items may be buffered
    /// (as if they had been written with [`feed`](futures::SinkExt::feed)).
    ///
    /// # Errors
    ///
    /// ## Output sink errors
    ///
    /// The call site can experience output sink errors in two places,
    /// [`prepare_send_from()`](SinkPrepareExt::prepare_send_from) and [`SinkSendable::send()`].
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

impl<'w, OS, OM> SinkPrepareExt<'w, OS, OM> for Pin<&'w mut OS>
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

impl<'w, OS, OM> SinkPrepareExt<'w, OS, OM> for &'w mut OS
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

/// Future for `SinkPrepareExt::prepare_send_from`
#[pin_project]
#[must_use]
pub struct SinkPrepareSendFuture<'w, IF, OS, OM> {
    /// Underlying future that will yield a message.
    #[pin]
    generator: IF,

    /// This Option exists because otherwise SinkPrepareSendFuture::poll()
    /// can't move `output` out of this struct to put it into the `SinkSendable`.
    /// (The poll() impl cannot borrow from SinkPrepareSendFuture.)
    output: Option<Pin<&'w mut OS>>,

    /// `fn(OM)` gives contravariance in OM.
    ///
    /// Variance is confusing.
    /// Loosely, a SinkPrepareSendFuture<..OM> consumes an OM.
    /// Actually, we don't really need to add any variance restricions wrt OM,
    /// because the &mut OS already implies the correct variance,
    /// so we could have used the PhantomData<fn(*const OM)> trick.
    /// Happily there is no unsafe anywhere nearby, so it is not possible for us to write
    /// a bug due to getting the variance wrong - only to erroneously prevent some use
    /// case.
    tw: PhantomData<fn(OM)>,
}

/// A [`Sink`] which is ready to receive an item
///
/// Produced by [`SinkPrepareExt::prepare_send_from`].  See there for the overview docs.
///
/// This references an output sink `OS`.
/// It offers the ability to write into the sink without blocking,
/// (and constitutes a proof token that the sink has declared itself ready for that).
///
/// The only useful method is [`send`](SinkSendable::send).
///
/// `SinkSendable` has no drop glue and can be freely dropped,
/// for example if you prepare to send a message and then
/// encounter an error when producing the output message.
#[must_use]
pub struct SinkSendable<'w, OS, OM> {
    /// Reference to underlying output sink.
    output: Pin<&'w mut OS>,
    /// Marker to ensure that `OM` is used.
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

        /// returns `&mut Pin<&'w mut OS>` from self_.output
        //
        // macro because the closure's type parameters would be unnameable.
        macro_rules! get_output {
            ($self_:expr) => {
                $self_.output.as_mut().expect(BAD_POLL_MSG).as_mut()
            };
        }
        /// Message to give when panicking because of improper extra poll.
        const BAD_POLL_MSG: &str =
            "future from SinkPrepareExt::prepare_send_from (SinkPrepareSendFuture) \
                 polled after returning Ready(Ok)";

        let () = match ready!(get_output!(self_).poll_ready(cx)) {
            Err(e) => {
                dprintln!("poll: output poll = IF.Err    SO  IF.Err");
                // Deliberately don't fuse by `take`ing output.  If we did that, we would expose
                // our caller to an additional panic risk.  There is no harm in polling the output
                // sink again: although `Sink` documents that a sink that returns errors will
                // probably continue to do so, it is not forbidden to try it and see.  This is in
                // any case better than definitely crashing if the `SinkPrepareSendFuture` is
                // polled after it gave Ready.
                return Poll::Ready(Err(e));
            }
            Ok(()) => {
                dprintln!("poll: output poll = IF.Ok     calling generator");
            }
        };

        let value = match self_.generator.as_mut().poll(cx) {
            Poll::Pending => {
                // We defer flushing the output until the input stops yielding.
                // This allows our caller (which is typically a loop) to transfer multiple
                // items from their input to their output between flushes.
                //
                // But we must not return `Pending` without flushing, or the caller could block
                // without flushing output, leading to untimely delivery of buffered data.
                dprintln!("poll: generator = Pending     calling output flush");
                let flushed = get_output!(self_).poll_flush(cx);
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
            output: self_.output.take().expect(BAD_POLL_MSG),
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
    /// so this call is synchronous, avoiding cancellation hazards.)
    pub fn send(self, item: OM) -> Result<(), OS::Error> {
        dprintln!("send ...");
        let r = self.output.start_send(item);
        dprintln!("send: {:?}", r.as_ref().map_err(|_| (())));
        r
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use futures::channel::mpsc;
    use futures::future::poll_fn;
    use futures::select_biased;
    use futures::SinkExt as _;
    use futures_await_test::async_test;
    use std::convert::Infallible;
    use std::sync::Arc;
    use std::sync::Mutex;

    #[async_test]
    async fn prepare_send() {
        // Early versions of this used unfold quite a lot more, but it is not really
        // convenient for testing.  It buffers one item internally, and is also buggy:
        //   https://github.com/rust-lang/futures-rs/issues/2600
        // So we use mpsc channels, which (perhaps with buffering) are quite controllable.

        // The eprintln!("FOR ...") calls correspond go the dprintln1() calls in the impl,
        // and can check that each code path in the implementation is used,
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
