//! [`SinkTrySend`]

use std::error::Error;
use std::pin::Pin;
use std::sync::Arc;

use futures::channel::mpsc;
use futures::Sink;

use derive_deftly::{define_derive_deftly, Deftly};
use thiserror::Error;

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
///
/// See also [`ErasedSinkTrySendError`] which can often
/// be usefully used when an implementation of `SinkTrySendError` is needed.
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

//---------- macrology - this has to come here, ideally all in one go ----------

#[rustfmt::skip] // rustfmt makes a complete hash of this
define_derive_deftly! {
    /// Implements various things which handle `full` and `disconnected`
    ///
    /// # Generates
    ///
    ///  * `SinkTrySendError for`ErasedSinkTrySendError`
    ///  * `From<E: SinkTrySendError> for`ErasedSinkTrySendError`
    ///  * [`handle_mpsc_error`]
    ///
    /// Use of macros avoids copypaste errors like
    /// `fn is_full(..) { self.is_disconnected() }`.
    ErasedSinkTrySendError expect items:

    ${defcond PREDICATE vmeta(predicate)}
    ${define PREDICATE { $<is_ ${snake_case $vname}> }}

    impl SinkTrySendError for ErasedSinkTrySendError {
        $(
            ${when PREDICATE}

            fn $PREDICATE(&self) -> bool {
                matches!(self, $vtype)
            }
        )
    }

    impl ErasedSinkTrySendError {
        /// Obtain an `ErasedSinkTrySendError` from a concrete `SinkTrySendError`
        //
        // (Can't be a `From` impl because it conflicts with the identity `From<T> for T`.)
        pub fn from<E>(e: E) -> ErasedSinkTrySendError
        where E: SinkTrySendError + Send + Sync
        {
            $(
                ${when PREDICATE}
                if e.$PREDICATE() {
                    $vtype
                } else
            )
                /* else */ {
                    $ttype::Other(Arc::new(e))
                }
        }
    }

    fn handle_mpsc_error<T>(me: mpsc::TrySendError<T>) -> (ErasedSinkTrySendError, T) {
        let error = $(
            ${when PREDICATE}

            if me.$PREDICATE() {
                $vtype
            } else
        )
            /* else */ {
                $ttype::Other(Arc::new(MpscOtherSinkTrySendError {}))
            };
        (error, me.into_inner())
    }
}

//---------- helper - erased error ----------

/// Type-erased error for [`SinkTrySend::try_send`]
///
/// Provided for situations where providing a concrete error type is awkward.
///
/// `futures::channel::mpsc::Sender` wants this because when its `try_send` method fails,
/// it is not possible to extract both the sent item, and the error!
///
/// `tor_memquota::mq_queue::Sender` wants this because the types of the error return
/// from `its `try_send` would otherwise be tainted by complex generics,
/// including its private `Entry` type.
#[derive(Debug, Error, Clone, Deftly)]
#[derive_deftly(ErasedSinkTrySendError)]
#[allow(clippy::exhaustive_enums)] // Adding other variants would be a breaking change anyway
pub enum ErasedSinkTrySendError {
    /// The stream was full.
    ///
    /// *No* arrangements will have been made for a wakeup when space becomes available.
    ///
    /// Corresponds to [`SinkTrySendError::is_full`]
    #[error("stream full (backpressure)")]
    #[deftly(predicate)]
    Full,

    /// The stream has disconnected
    ///
    /// Corresponds to [`SinkTrySendError::is_disconnected`]
    #[error("stream disconnected")]
    #[deftly(predicate)]
    Disconnected,

    /// Something else went wrong
    #[error("failed to convey data")]
    Other(#[source] Arc<dyn Error + Send + Sync + 'static>),
}

//---------- impl for futures::channel::mpsc ----------

/// [`mpsc::Sender::try_send`] returned an uncategorisable error
///
/// Both `.full()` and `.disconnected()` returned `false`.
/// We could call [`mpsc::TrySendError::into_send_error`] but then we don't get the payload.
/// In the future, we might replace this type with a type alias for [`mpsc::SendError`].
///
/// When returned from `<mpsc::Sender::SinkTrySend::try_send`,
/// this is wrapped in [`ErasedSinkTrySendError::Other`].
#[derive(Debug, Error)]
#[error("mpsc::Sender::try_send returned an error which is neither .full() nor .disconnected()")]
#[non_exhaustive]
pub struct MpscOtherSinkTrySendError {}

impl<T> SinkTrySend<T> for mpsc::Sender<T> {
    // Ideally we would just use [`mpsc::SendError`].
    // But `mpsc::TrySendError` lacks an `into_parts` method that gives both `SendError` and `T`.
    type Error = ErasedSinkTrySendError;

    fn try_send_or_return(
        self: Pin<&mut Self>,
        item: T,
    ) -> Result<(), (ErasedSinkTrySendError, T)> {
        let self_: &mut Self = Pin::into_inner(self);
        mpsc::Sender::try_send(self_, item).map_err(handle_mpsc_error)
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
    #![allow(clippy::arithmetic_side_effects)] // don't mind potential panicking ops in tests
    #![allow(clippy::useless_format)] // srsly

    use super::*;
    use derive_deftly::derive_deftly_adhoc;
    use tor_error::ErrorReport as _;

    #[test]
    fn chk_erased_sink() {
        #[derive(Error, Clone, Debug, Deftly)]
        #[error("concrete {is_full} {is_disconnected}")]
        #[derive_deftly_adhoc]
        struct Concrete {
            is_full: bool,
            is_disconnected: bool,
        }

        derive_deftly_adhoc! {
            Concrete:

            impl SinkTrySendError for Concrete { $(
                fn $fname(&self) -> bool { self.$fname }
            ) }
        }

        for is_full in [false, true] {
            for is_disconnected in [false, true] {
                let c = Concrete {
                    is_full,
                    is_disconnected,
                };
                let e = ErasedSinkTrySendError::from(c.clone());
                let e2 = ErasedSinkTrySendError::from(e.clone());

                let cs = format!("concrete {is_full} {is_disconnected}");

                let es = if is_full {
                    format!("stream full (backpressure)")
                } else if is_disconnected {
                    format!("stream disconnected")
                } else {
                    format!("failed to convey data: {cs}")
                };

                assert_eq!(c.report().to_string(), format!("error: {cs}"));
                assert_eq!(e.report().to_string(), format!("error: {es}"));
                assert_eq!(e2.report().to_string(), format!("error: {es}"));
            }
        }
    }
}
