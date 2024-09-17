//! Framework for helping implement a `handshake` function
//!
//! Each kind of handshake should:
//!
//!  * `impl HandshakeImpl`, supplying a `handshake_impl` which does the actual work.
//!
//!  * Provide the public `fn handshake` function,
//!    in terms of the provided method `HandshakeImpl::run_handshake`.
//!
//!  * Derive [`Handshake`](derive_deftly_template_Handshake).
//
// The contents of this module is not in handshake.rs,
// because putting it there would give the protocol implementations
// access to fields of our private types etc.
//
// TODO arguably, the handshake module is a redundant level of nesting.
// We could consider moving its sub-modules into the toplevel,
// and its handful of items elsewhere.

use derive_deftly::define_derive_deftly;

use tor_bytes::Reader;
use tor_error::internal;

use crate::{Action, Error, Truncated};

define_derive_deftly! {
    /// Macro-generated components for a handshake outer state structure
    ///
    /// # Requirements
    ///
    ///  * Must be a struct containing `state: State`
    ///  * `State` must be in scope as a binding at the derivation site
    ///  * `State` must have a unit variant `Failed`
    ///  * One `Option` field must be decorated `#[deftly(handshake(output))]`
    ///
    /// # Generates
    ///
    ///  * Implementation of `HasHandshake`
    ///  * Implementation of `HasHandshakeState`
    ///  * Implementation of `HasHandshakeOutput`
    //
    // An alternative would be to have a each handwhake contain an enum
    // which we handle here ourselves, moving `Done` and `failed` here.
    // But currently each handshake stores state outside `state`;
    // some more intermediate structs would be needed.
    Handshake for struct, expect items:

    impl $crate::handshake::framework::HasHandshakeState for $ttype {
        fn set_failed(&mut self) {
            self.state = State::Failed {};
        }
    }

  $(
    // This is supposed to happen precisely once
    ${when fmeta(handshake(output))}

    // This trick extracts the T from Option<T>
    ${define OUTPUT { <$ftype as IntoIterator>::Item }}

    impl $crate::handshake::framework::Handshake for $ttype {
        type Output = $OUTPUT;
    }

    impl $crate::handshake::framework::HasHandshakeOutput<$OUTPUT> for $ttype {
        fn take_output(&mut self) -> Option<$OUTPUT> {
            // using UFCS arranges that we check that $ftype really is Option
            Option::take(&mut self.$fname)
        }
    }
  )
}
#[allow(unused_imports)] // false positives, rust#130570, see also derive-deftly #117
#[allow(clippy::single_component_path_imports)] // false positive, see rust-clippy#13419
use derive_deftly_template_Handshake; // for rustdoc's benefit

/// The internal (implementation-side) representation of the next step to take
///
/// `handwhake_impl` may not consume nothing from the `Reader`
/// and return `Reply { reply: vec![] }`,
/// since that would imply an infinite loop.
pub(crate) enum ImplNextStep {
    /// Send some data to the peer
    Reply {
        /// The message to send
        reply: Vec<u8>,
    },

    /// We're done.  The output is available.
    Finished,
}

/// `Handshake` structs that have a state that can be `Failed`
///
/// Derive this with
/// [`#[derive_deftly(Handshake)]`](derive_deftly_template_Handshake).
pub(super) trait HasHandshakeState {
    /// Set the state to `Failed`
    fn set_failed(&mut self);
}

/// `Handshake` structs whose output can be obtained
///
/// Derive this with
/// [`#[derive_deftly(Handshake)]`](derive_deftly_template_Handshake).
#[allow(unused)] // XXXX
pub(super) trait HasHandshakeOutput<O> {
    /// Obtain the output from a handshake completed with [`.handshake`](Handshake::handshake)
    ///
    /// Call only if `Action` said `finished`, and then only once.
    /// Otherwise, will return `None`.
    fn take_output(&mut self) -> Option<O>;
}

/// `Handshake`s: `SocksClientHandshake` or `SocksProxyHandshake`
pub(super) trait HandshakeImpl: HasHandshakeState {
    /// Actual implementation, to be provided
    ///
    /// Does not need to handle setting the state to `Failed` on error.
    /// But *does* need to handle setting the state to `Done` if applicable.
    ///
    /// May return the error from the `Reader`, in `Error::Decode`.
    /// (For example,. `Error::Decode(tor_bytes::Error::Incomplete)`
    /// if the message was incomplete and reading more data would help.)
    fn handshake_impl(&mut self, r: &mut tor_bytes::Reader<'_>) -> crate::Result<ImplNextStep>;

    /// Helper, used by public API implementations to call `handshake_impl`.
    ///
    /// Deals with:
    ///  * Setting up the `Reader`
    ///  * Determining the amount drained.
    ///  * Avoiding infinite loops (detect nothing drained, nothing replied)
    ///
    /// Return value is `(drain, Result<ImplNextStep>)`.
    fn call_handshake_impl(&mut self, input: &[u8]) -> (usize, crate::Result<ImplNextStep>) {
        let mut b = Reader::from_possibly_incomplete_slice(input);
        let rv = self.handshake_impl(&mut b);
        let drain = b.consumed();

        // avoid infinite loop
        match &rv {
            Ok(ImplNextStep::Reply { reply }) if reply.is_empty() && drain == 0 => {
                return (
                    0,
                    Err(
                        internal!("protocol implementation drained nothing, replied nothing")
                            .into(),
                    ),
                )
            }
            _ => {}
        };

        (drain, rv)
    }
}

/// Handshake
#[allow(private_bounds)] // This is a sealed trait, that's expected
pub trait Handshake: HandshakeImpl + HasHandshakeOutput<Self::Output> {
    /// Output from the handshake: the meaning, as we understand it
    type Output;

    /// Try to advance the handshake, given some peer input in
    /// `input`.
    ///
    /// If there isn't enough input, gives a [`Truncated`].
    /// In this case, *the caller must retain the input*, and pass it to a later
    /// invocation of `handshake`.  Input should only be regarded as consumed when
    /// the `Action::drain` field is nonzero.
    ///
    /// Other errors (besides `Truncated`) indicate a failure.
    ///
    /// On success, return an Action describing what to tell the peer,
    /// and how much of its input to consume.
    fn handshake(&mut self, input: &[u8]) -> crate::TResult<Action> {
        let (drain, rv) = self.call_handshake_impl(input);
        match rv {
            #[allow(deprecated)]
            Err(Error::Decode(
                tor_bytes::Error::Incomplete { .. } | tor_bytes::Error::Truncated,
            )) => Err(Truncated::new()),
            Err(e) => {
                self.set_failed();
                Ok(Err(e))
            }
            Ok(ImplNextStep::Reply { reply }) => Ok(Ok(Action {
                drain,
                reply,
                finished: false,
            })),
            Ok(ImplNextStep::Finished {}) => Ok(Ok(Action {
                drain,
                reply: vec![],
                finished: true,
            })),
        }
    }
}
