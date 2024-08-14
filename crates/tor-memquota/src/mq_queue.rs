//! Queues that participate in the memory quota system
//!
//! Wraps a communication channel, such as [`futures::channel::mpsc`],
//! tracks the memory use of the queue,
//! and participates in the memory quota system.
//!
//! Each item in the queue must know its memory cost,
//! and provide it via [`HasMemoryCost`].
//!
//! New queues are created by calling the [`new_mq`](ChannelSpec::new_mq) method
//! on a [`ChannelSpec`],
//! for example [`Mpsc`] or [`MpscUnbounded`].
//!
//! The ends implement [`Stream`] and [`Sink`].
//! If the underlying channel's sender is `Clone`,
//! for example with an MPSC queue, the returned sender is also `Clone`.
//!
//! # Example
//!
//! ```
//! use tor_memquota::{MemoryQuotaTracker, HasMemoryCost};
//! use tor_rtcompat::PreferredRuntime;
//! use tor_memquota::mq_queue::{Mpsc, ChannelSpec as _};
//! # fn m() -> tor_memquota::Result<()> {
//!
//! #[derive(Debug)]
//! struct Message(String);
//! impl HasMemoryCost for Message {
//!     fn memory_cost(&self) -> usize { self.0.len() }
//! }
//!
//! let runtime = PreferredRuntime::create().unwrap();
//! let config  = tor_memquota::Config::builder().max(1024*1024*1024).build().unwrap();
//! let trk = MemoryQuotaTracker::new(&runtime, config).unwrap();
//! let account = trk.new_account(None).unwrap();
//!
//! let (tx, rx) = Mpsc { buffer: 10 }.new_mq::<Message, _>(&runtime, account)?;
//! #
//! # Ok(())
//! # }
//! # m().unwrap();
//! ```

use crate::internal_prelude::*;

use std::task::{Context, Poll, Poll::*, Waker};

//---------- Sender ----------

/// Sender for a channel that participates in the memory quota system
///
/// Returned by [`ChannelSpec::new_mq`], a method on `C`.
/// See the [module-level docs](crate::mq_queue).
#[derive(Educe)]
#[educe(Debug, Clone(bound = "C::Sender<Entry<T>>: Clone"))]
pub struct Sender<T: Debug + Send + 'static, C: ChannelSpec, R: CoarseTimeProvider + Unpin> {
    /// The inner sink
    tx: C::Sender<Entry<T>>,

    /// Our clone of the `Participation`, for memory accounting
    mq: TypedParticipation<Entry<T>>,

    /// Time provider for getting the data age
    #[educe(Debug(ignore))] // CoarseTimeProvider isn't Debug
    runtime: R,
}

//---------- Receiver ----------

/// Receiver for a channel that participates in the memory quota system
///
/// Returned by [`ChannelSpec::new_mq`], a method on `C`.
/// See the [module-level docs](crate::mq_queue).
#[derive(Educe)] // not Clone, see below
#[educe(Debug)]
pub struct Receiver<T: Debug + Send + 'static, C: ChannelSpec> {
    /// Payload
    //
    // We don't make this an "exposed" `Arc`,
    // because that would allow the caller to clone it -
    // but we don't promise we're a multi-consumer queue even if `C::Receiver` is.
    //
    // Despite the in-principle Clone-ability of our `Receiver`,
    // we're not a working multi-consumer queue, even if the underlying channel is,
    // because StreamUnobtrusivePeeker isn't multi-consumer.
    //
    // Providing the multi-consumer feature would perhaps involve StreamUnobtrusivePeeker
    // handling multiple wakers, and then `impl Clone for Receiver where C::Receiver: Clone`.
    // (and writing a bunch of tests).
    //
    // This would all be useless without also `impl ChannelSpec`
    // for a multi-consumer queue.
    inner: Arc<ReceiverInner<T, C>>,
}

/// Payload of `Receiver`, that's within the `Arc`, but contains the `Mutex`.
///
/// This is a separate type because
/// it's what we need to implement [`IsParticipant`] for.
#[derive(Educe)]
#[educe(Debug)]
struct ReceiverInner<T: Debug + Send + 'static, C: ChannelSpec> {
    /// Mutable state
    ///
    /// If we have collapsed due to memory reclaim, state is replaced by an `Err`.
    /// In that case the caller mostly can't send on the Sender either,
    /// because we'll have torn down the Participant,
    /// so claims (beyond the cache in the `Sender`'s `Participation`) will fail.
    state: Mutex<Result<ReceiverState<T, C>, CollapsedDueToReclaim>>,
}

/// Mutable state of a `Receiver`
///
/// Normally the mutex is only locked by the receiving task.
/// On memory pressure, mutex is acquired by the memory system,
/// which has a clone of the `Arc<ReceiverInner>`.
///
/// Within `Arc<Mutex<Result<, >>>`.
#[derive(Educe)]
#[educe(Debug)]
struct ReceiverState<T: Debug + Send + 'static, C: ChannelSpec> {
    /// The inner stream, but with an unobtrusive peek for getting the oldest data age
    rx: StreamUnobtrusivePeeker<C::Receiver<Entry<T>>>,

    /// The `Participation`, which we use for memory accounting
    ///
    /// ### Performance and locality
    ///
    /// We have separate [`Participation`]s for rx and tx.
    /// The tx is constantly claiming and the rx releasing;
    /// at least each MAX_CACHE, they must balance out
    /// via the (fairly globally shared) `MemoryQuotaTracker`.
    ///
    /// If this turns out to be a problem,
    /// we could arrange to share a `Participation`.
    mq: TypedParticipation<Entry<T>>,

    /// Hooks passed to [`Receiver::register_collapse_hook`]
    ///
    /// When receiver dropped, or memory reclaimed, we call all of these.
    #[educe(Debug(method = "receiver_state_debug_collapse_notify"))]
    collapse_callbacks: Vec<CollapseCallback>,
}

//---------- other types ----------

/// Entry in in the inner queue
#[derive(Debug)]
struct Entry<T> {
    /// The actual entry
    t: T,
    /// The data age - when it was inserted into the queue
    when: CoarseInstant,
}

/// Error returned when trying to write to a [`Sender`]
#[derive(Error, Clone, Debug)]
#[non_exhaustive]
pub enum SendError<CE> {
    /// The underlying channel rejected the message
    // Can't be `#[from]` because rustc can't see that C::SendError isn't SendError<C>
    #[error("channel send failed")]
    Channel(#[source] CE),

    /// The memory quota system prevented the send
    ///
    /// NB: when the channel is torn down due to memory pressure,
    /// the inner receiver is also torn down.
    /// This means that this variant is not always reported:
    /// sending on the sender in this situation
    /// may give [`SendError::Channel`] instead.
    #[error("memory quota exhausted, queue reclaimed")]
    Memquota(#[from] Error),
}

/// Callback passed to `Receiver::register_collapse_hook`
pub type CollapseCallback = Box<dyn FnOnce(CollapseReason) + Send + Sync + 'static>;

/// Argument to `CollapseCallback`: why are we collapsing?
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum CollapseReason {
    /// The `Receiver` was dropped
    ReceiverDropped,

    /// The memory quota system asked us to reclaim memory
    MemoryReclaimed,
}

/// Marker, appears in state as `Err` to mean "we have collapsed"
#[derive(Debug, Clone, Copy)]
struct CollapsedDueToReclaim;

//==================== Channel ====================

/// Specification for a communication channel
///
/// Implemented for [`Mpsc`] and [`MpscUnbounded`].
//
// # Correctness (uncomment this if this trait is made unsealed)
//
// It is a requirement that this object really is some kind of channel.
// Specifically:
//
//  * Things that get put into the `Sender` must eventually emerge from the `Receiver`.
//  * Nothing may emerge from the `Receiver` that wasn't put into the `Sender`.
//  * If the `Sender` and `Receiver` are dropped, the items must also get dropped.
//
// If these requirements are violated, it could result in corruption of the memory accounts
//
// Ideally, if the `Receiver` is dropped, most of the items are dropped soon.
//
pub trait ChannelSpec: Sealed /* see Correctness, above */ + Sized + 'static {
    /// The sending [`Sink`] for items of type `T`.
    //
    // Right now we insist that everything is Unpin.
    // futures::channel::mpsc's types all are.
    // If we wanted to support !Unpin channels, that would be possible,
    // but we would have some work to do.
    //
    // We also insist that everything is Debug.  That means `T: Debug`,
    // as well as the channels.  We could avoid that, but it would involve
    // skipping debug of important fields, or pervasive complex trait bounds
    // (Eg `#[educe(Debug(bound = "C::Receiver<Entry<T>>: Debug"))]` or worse.)
    //
    // This is a GAT because we need to instantiate it with T=Entry<_>.
    type Sender<T: Debug + Send + 'static>: Sink<T, Error = Self::SendError>
        + Debug + Unpin + Sized;

    /// The receiving [`Stream`] for items of type `T`.
    type Receiver<T: Debug + Send + 'static>: Stream<Item = T> + Debug + Unpin + Send + Sized;

    /// The error type `<Receiver<_> as Stream>::Error`.
    ///
    /// (For this trait to be implemented, it is not allowed to depend on `T`.)
    type SendError: std::error::Error;

    /// Create a new channel, based on the spec `self`, that participates in the memory quota
    ///
    /// See the [module-level docs](crate::mq_queue) for an example.
    //
    // This method is supposed to be called by the user, not overridden.
    #[allow(clippy::type_complexity)] // the Result; not sensibly reducible or aliasable
    fn new_mq<T, R>(self, runtime: &R, account: Account) -> crate::Result<(
        Sender<T, Self, R>,
        Receiver<T, Self>,
    )>
    where
        T: HasMemoryCost + Debug + Send + 'static,
        R: CoarseTimeProvider + Unpin
    {
        let (rx, (tx, mq)) = account.register_participant_with(
            runtime.now_coarse(),
            move |mq| {
                let mq = TypedParticipation::new(mq);
                let collapse_callbacks = vec![];
                let (tx, rx) = self.raw_channel::<Entry<T>>();
                let rx = StreamUnobtrusivePeeker::new(rx);
                let state = ReceiverState { rx, mq: mq.clone(), collapse_callbacks };
                let state = Mutex::new(Ok(state));
                let inner = ReceiverInner { state };
                Ok::<_, crate::Error>((inner.into(), (tx, mq)))
            },
        )??;

        let runtime = runtime.clone();

        let tx = Sender { runtime, tx, mq };
        let rx = Receiver { inner: rx };

        Ok((tx, rx))
    }

    /// Create a new raw channel as specified by `self`
    //
    // This is called by `mq_queue`.
    fn raw_channel<T: Debug + Send + 'static>(self) -> (Self::Sender<T>, Self::Receiver<T>);

    /// Close the receiver, preventing further sends
    ///
    /// This should ensure that only a smallish bounded number of further items
    /// can be sent, before errors start being returned.
    fn close_receiver<T: Debug + Send + 'static>(rx: &mut Self::Receiver<T>);
}

//---------- impls of Channel ----------

/// Specification for a (bounded) MPSC channel
///
/// Corresponds to the constructor [`futures::channel::mpsc::channel`].
///
/// Call [`new_mq`](ChannelSpec::new_mq) on this unit type:
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[allow(clippy::exhaustive_structs)] // This is precisely the arguments to mpsc::channel
pub struct Mpsc {
    /// Buffer size; see [`futures::channel::mpsc::channel`].
    pub buffer: usize,
}

/// Specification for an unbounded MPSC channel
///
/// Corresponds to the constructor [`futures::channel::mpsc::unbounded`].
///
/// Call [`new_mq`](ChannelSpec::new_mq) on a value of this type.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[allow(clippy::exhaustive_structs)] // This is precisely the arguments to mpsc::unbounded
pub struct MpscUnbounded;

impl Sealed for Mpsc {}
impl Sealed for MpscUnbounded {}

impl ChannelSpec for Mpsc {
    type Sender<T: Debug + Send + 'static> = mpsc::Sender<T>;
    type Receiver<T: Debug + Send + 'static> = mpsc::Receiver<T>;
    type SendError = mpsc::SendError;

    fn raw_channel<T: Debug + Send + 'static>(self) -> (mpsc::Sender<T>, mpsc::Receiver<T>) {
        mpsc::channel(self.buffer)
    }

    fn close_receiver<T: Debug + Send + 'static>(rx: &mut Self::Receiver<T>) {
        rx.close();
    }
}

impl ChannelSpec for MpscUnbounded {
    type Sender<T: Debug + Send + 'static> = mpsc::UnboundedSender<T>;
    type Receiver<T: Debug + Send + 'static> = mpsc::UnboundedReceiver<T>;
    type SendError = mpsc::SendError;

    fn raw_channel<T: Debug + Send + 'static>(self) -> (Self::Sender<T>, Self::Receiver<T>) {
        mpsc::unbounded()
    }

    fn close_receiver<T: Debug + Send + 'static>(rx: &mut Self::Receiver<T>) {
        rx.close();
    }
}

//==================== implementations ====================

//---------- Sender ----------

impl<T, C, R> Sink<T> for Sender<T, C, R>
where
    T: HasMemoryCost + Debug + Send + 'static,
    C: ChannelSpec,
    R: CoarseTimeProvider + Unpin,
{
    type Error = SendError<C::SendError>;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut()
            .tx
            .poll_ready_unpin(cx)
            .map_err(SendError::Channel)
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        let self_ = self.get_mut();
        let item = Entry {
            t: item,
            when: self_.runtime.now_coarse(),
        };
        self_.mq.try_claim(item, |item| {
            self_.tx.start_send_unpin(item).map_err(SendError::Channel)
        })?
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.tx
            .poll_flush_unpin(cx)
            .map(|r| r.map_err(SendError::Channel))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.tx
            .poll_close_unpin(cx)
            .map(|r| r.map_err(SendError::Channel))
    }
}

//---------- Receiver ----------

impl<T: HasMemoryCost + Debug + Send + 'static, C: ChannelSpec> Stream for Receiver<T, C> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut state = self.inner.lock();
        let state = match &mut *state {
            Ok(y) => y,
            Err(CollapsedDueToReclaim) => return Ready(None),
        };
        let ret = state.rx.poll_next_unpin(cx);
        if let Ready(Some(item)) = &ret {
            let cost = item.typed_memory_cost();
            state.mq.release(&cost);
        }
        ret.map(|r| r.map(|e| e.t))
    }
}

// TODO: When we have a trait for peekable streams, Receiver should implement it

impl<T: HasMemoryCost + Debug + Send + 'static, C: ChannelSpec> Receiver<T, C> {
    /// Register a callback, called when we tear the channel down
    ///
    /// This will be called when the `Receiver` is dropped,
    /// or if we tear down because the memory system asks us to reclaim.
    ///
    /// `call` might be called at any time, from any thread, but
    /// it won't be holding any locks relating to memory quota or the queue.
    ///
    /// If `self` is *already* in the process of being torn down,
    /// `call` might be called immediately, reentrantly!
    //
    // This callback is nicer than us handing out an mpsc rx
    // which user must read and convert items from.
    //
    // This method is on Receiver because that has the State,
    // but could be called during setup to hook both sender's and
    // receiver's shutdown mechanisms.
    pub fn register_collapse_hook(&self, call: CollapseCallback) {
        let mut state = self.inner.lock();
        let state = match &mut *state {
            Ok(y) => y,
            Err(reason) => {
                let reason = (*reason).into();
                drop::<MutexGuard<_>>(state);
                call(reason);
                return;
            }
        };
        state.collapse_callbacks.push(call);
    }
}

impl<T: Debug + Send + 'static, C: ChannelSpec> ReceiverInner<T, C> {
    /// Convenience function to take the lock
    fn lock(&self) -> MutexGuard<Result<ReceiverState<T, C>, CollapsedDueToReclaim>> {
        self.state.lock().expect("mq_mpsc lock poisoned")
    }
}

impl<T: HasMemoryCost + Debug + Send + 'static, C: ChannelSpec> IsParticipant
    for ReceiverInner<T, C>
{
    fn get_oldest(&self) -> Option<CoarseInstant> {
        let mut state = self.lock();
        let state = match &mut *state {
            Ok(y) => y,
            Err(CollapsedDueToReclaim) => return None,
        };
        let peeked = Pin::new(&mut state.rx)
            .unobtrusive_peek()
            .map(|peeked| peeked.when);
        peeked
    }

    fn reclaim(self: Arc<Self>) -> mtracker::ReclaimFuture {
        Box::pin(async move {
            let reason = CollapsedDueToReclaim;
            let mut state_guard = self.lock();
            let state = mem::replace(&mut *state_guard, Err(reason));
            drop::<MutexGuard<_>>(state_guard);
            match state {
                Ok(mut state) => {
                    for call in state.collapse_callbacks.drain(..) {
                        call(reason.into());
                    }
                    drop::<ReceiverState<_, _>>(state); // will drain queue, too
                }
                Err(CollapsedDueToReclaim) => {}
            };
            mtracker::Reclaimed::Collapsing
        })
    }
}

impl<T: Debug + Send + 'static, C: ChannelSpec> Drop for ReceiverState<T, C> {
    fn drop(&mut self) {
        // If there's a mutex, we're in its drop

        // `destroy_participant` prevents the sender from making further non-cached claims
        mem::replace(&mut self.mq, Participation::new_dangling().into())
            .into_raw()
            .destroy_participant();

        for call in self.collapse_callbacks.drain(..) {
            call(CollapseReason::ReceiverDropped);
        }

        // try to free whatever is in the queue, in case the stream doesn't do that itself
        // No-one can poll us any more, so we are no longer interested in wakeups
        let noop_waker = Waker::from(Arc::new(NoopWaker));
        let mut noop_cx = Context::from_waker(&noop_waker);

        // prevent further sends, so that our drain doesn't race indefinitely with the sender
        if let Some(mut rx_inner) =
            StreamUnobtrusivePeeker::as_raw_inner_pin_mut(Pin::new(&mut self.rx))
        {
            C::close_receiver(&mut rx_inner);
        }

        while let Ready(Some(item)) = self.rx.poll_next_unpin(&mut noop_cx) {
            drop::<Entry<T>>(item);
        }
    }
}

/// Method for educe's Debug impl for `ReceiverState.collapse_callbacks`
fn receiver_state_debug_collapse_notify(
    v: &[CollapseCallback],
    f: &mut fmt::Formatter,
) -> fmt::Result {
    Debug::fmt(&v.len(), f)
}

//---------- misc ----------

impl<T: HasMemoryCost> HasMemoryCost for Entry<T> {
    fn memory_cost(&self) -> usize {
        let time_size = std::alloc::Layout::new::<CoarseInstant>().size();
        self.t.memory_cost().saturating_add(time_size)
    }
}

impl From<CollapsedDueToReclaim> for CollapseReason {
    fn from(CollapsedDueToReclaim: CollapsedDueToReclaim) -> CollapseReason {
        CollapseReason::MemoryReclaimed
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
    use crate::mtracker::test::*;
    use tor_rtmock::MockRuntime;
    use tracing::debug;
    use tracing_test::traced_test;

    #[derive(Default, Debug)]
    struct ItemTracker {
        state: Mutex<ItemTrackerState>,
    }
    #[derive(Default, Debug)]
    struct ItemTrackerState {
        existing: usize,
        next_id: usize,
    }

    #[derive(Debug)]
    struct Item {
        id: usize,
        tracker: Arc<ItemTracker>,
    }

    impl ItemTracker {
        fn new_item(self: &Arc<Self>) -> Item {
            let mut state = self.lock();
            let id = state.next_id;
            state.existing += 1;
            state.next_id += 1;
            debug!("new {id}");
            Item {
                tracker: self.clone(),
                id,
            }
        }

        fn new_tracker() -> Arc<Self> {
            Arc::default()
        }

        fn lock(&self) -> MutexGuard<ItemTrackerState> {
            self.state.lock().unwrap()
        }
    }

    impl Drop for Item {
        fn drop(&mut self) {
            debug!("old {}", self.id);
            self.tracker.state.lock().unwrap().existing -= 1;
        }
    }

    impl HasMemoryCost for Item {
        fn memory_cost(&self) -> usize {
            mbytes(1)
        }
    }

    struct Setup {
        trk: Arc<mtracker::MemoryQuotaTracker>,
        acct: Account,
        itrk: Arc<ItemTracker>,
    }

    fn setup(rt: &MockRuntime) -> Setup {
        let trk = mk_tracker(rt);
        let acct = trk.new_account(None).unwrap();
        let itrk = ItemTracker::new_tracker();
        Setup { trk, acct, itrk }
    }

    #[traced_test]
    #[test]
    fn lifecycle() {
        MockRuntime::test_with_various(|rt| async move {
            let s = setup(&rt);
            let (mut tx, mut rx) = MpscUnbounded.new_mq(&rt, s.acct.clone()).unwrap();

            tx.send(s.itrk.new_item()).await.unwrap();
            let _: Item = rx.next().await.unwrap();

            for _ in 0..20 {
                tx.send(s.itrk.new_item()).await.unwrap();
            }

            // reclaim task hasn't had a chance to run
            eprintln!("still existing items {}", s.itrk.lock().existing);

            rt.advance_until_stalled().await;

            // reclaim task should have torn everything down
            assert!(s.itrk.lock().existing == 0);

            assert!(rx.next().await.is_none());

            // Empirically, this is a "disconnected" error from the inner mpsc,
            // but let's not assert that.
            let _: SendError<_> = tx.send(s.itrk.new_item()).await.unwrap_err();
        });
    }

    #[traced_test]
    #[test]
    fn fill_and_empty() {
        MockRuntime::test_with_various(|rt| async move {
            let s = setup(&rt);
            let (mut tx, mut rx) = MpscUnbounded.new_mq(&rt, s.acct.clone()).unwrap();

            const COUNT: usize = 19;

            for _ in 0..COUNT {
                tx.send(s.itrk.new_item()).await.unwrap();
            }

            rt.advance_until_stalled().await;

            for _ in 0..COUNT {
                let _: Item = rx.next().await.unwrap();
            }

            rt.advance_until_stalled().await;
        });
    }

    #[traced_test]
    #[test]
    fn sink_error() {
        #[derive(Default, Debug)]
        struct BustedSink;

        impl<T> Sink<T> for BustedSink {
            type Error = BustedError;

            fn poll_ready(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<Result<(), Self::Error>> {
                Ready(Err(BustedError))
            }
            fn start_send(self: Pin<&mut Self>, _item: T) -> Result<(), Self::Error> {
                panic!("poll_ready always gives error, start_send should not be called");
            }
            fn poll_flush(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<Result<(), Self::Error>> {
                Ready(Ok(()))
            }
            fn poll_close(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<Result<(), Self::Error>> {
                Ready(Ok(()))
            }
        }

        #[derive(Error, Debug)]
        #[error("busted, for testing")]
        struct BustedError;

        struct BustedQueueSpec;
        impl Sealed for BustedQueueSpec {}
        impl ChannelSpec for BustedQueueSpec {
            type Sender<T: Debug + Send + 'static> = BustedSink;
            type Receiver<T: Debug + Send + 'static> = futures::stream::Pending<T>;
            type SendError = BustedError;
            fn raw_channel<T: Debug + Send + 'static>(self) -> (BustedSink, Self::Receiver<T>) {
                (BustedSink, futures::stream::pending())
            }
            fn close_receiver<T: Debug + Send + 'static>(_rx: &mut Self::Receiver<T>) {}
        }

        MockRuntime::test_with_various(|rt| async move {
            let s = setup(&rt);
            let (mut tx, _rx) = BustedQueueSpec.new_mq(&rt, s.acct.clone()).unwrap();

            let e = tx.send(s.itrk.new_item()).await.unwrap_err();
            assert!(matches!(e, SendError::Channel(BustedError)));

            // item should have been destroyed
            assert_eq!(s.itrk.lock().existing, 0);

            // no memory should be claimed
            assert!(s.trk.used_current_approx().unwrap() <= *mtracker::MAX_CACHE);
        });
    }
}
