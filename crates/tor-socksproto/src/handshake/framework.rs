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

use std::fmt::Debug;
use std::mem;
use std::num::{NonZeroUsize, TryFromIntError};

use derive_deftly::define_derive_deftly;
use educe::Educe;

use tor_bytes::Reader;
use tor_error::{internal, Bug};

use crate::SOCKS_BUF_LEN;
use crate::{Action, Error, Truncated};

/// Markers indicating whether we're allowing read-ahead,
///
/// The `P` type parameter on `[Buffer]` et al indicates
/// whether we are doing (only) precise reads:
/// `()` for normal operation, with readahead;
/// `PreciseReads` for reading small amounts as needed.
///
/// ## Normal operation, `P = ()`
///
/// When the SOCKS protocol implementation wants to see more data,
/// [`RecvStep::<()>::buf`] is all of the free space in the buffer.
///
/// The caller will typically read whatever data is available,
/// including possibly data sent by the peer *after* the end of the SOCKS handshake.
/// If so, that data will eventually be returned, after the handshake is complete,
/// by [`Finished::into_output_and_slice`] or [`Finished::into_output_and_vec`].
///
/// ## Avoiding read-ahead, `P = PreciseReads`
///
/// [`RecvStep::<PreciseReads>::buf()`] is only as long as the SOCKS protocol implementation
/// *knows* that it needs.
///
/// Typically this is a very small buffer, often only one byte.
/// This means that a single protocol exchange will involve many iterations
/// each returning a `RecvStep`,
/// and (depending on the caller) each implying one `recv(2)` call or similar.
/// This is not very performant.
/// But it does allow the implementation to avoid reading ahead.
///
/// In this mode, `Finished::into_output` is available,
/// which returns only the output.
pub trait ReadPrecision: ReadPrecisionSealed + Default + Copy + Debug {}
impl ReadPrecision for PreciseReads {}
impl ReadPrecision for () {}

/// Sealed, and adjustment of `RecvStep::buf`
pub trait ReadPrecisionSealed {
    /// Adjust `buf` to `deficit`, iff we're doing precise reads
    fn recv_step_buf(buf: &mut [u8], deficit: NonZeroUsize) -> &mut [u8];
}
impl ReadPrecisionSealed for () {
    fn recv_step_buf(buf: &mut [u8], _deficit: NonZeroUsize) -> &mut [u8] {
        buf
    }
}
impl ReadPrecisionSealed for PreciseReads {
    fn recv_step_buf<'b>(buf: &mut [u8], deficit: NonZeroUsize) -> &mut [u8] {
        &mut buf[0..deficit.into()]
    }
}

/// Marker indicating precise reads
///
/// See [`ReadPrecision`].
#[derive(Default, Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[allow(clippy::exhaustive_structs)]
pub struct PreciseReads;

/// An input buffer containing maybe some socks data
///
/// `Buffer` has a capacity set at creation time,
/// and records how much data it contains.
///
/// Data is consumed by [`step()`](Handshake::step), and
/// received data is appended using a [`RecvStep`] returned from `step`.
///
/// The `P` type parameter indicates whether we're allowing read-ahead,
/// or doing only precise reads.
/// See [`ReadPrecision`] for details.
//
// `P` prevents accidentally mixing `Finished.into_output`
// with reads into the whole buffer, not limited by the deficit.
#[derive(Educe)]
#[educe(Debug)]
pub struct Buffer<P: ReadPrecision = ()> {
    /// The actual buffer
    #[educe(Debug(ignore))]
    buf: Box<[u8]>,

    /// `[0..filled]` has data that's been read but not yet drained
    filled: usize,

    /// Marker for the precision
    //
    // We don't need PhantomData, since P is always a Copy unit.
    #[allow(dead_code)]
    precision: P,
}

/// Next step to take in the handshake
///
/// Returned by [`Handshake::step`].
///
/// Instructions from the handshake implementation.
/// Caller should match on this and perform the requested action.
//
// This is an enum, rather than a struct with fields representing different components
// of an instruction, because an enum demands of the caller that they do precise one thing.
// With a compound instruction struct, it would be quite easy for a caller to
// (sometimes) fail to execute some part(s).
#[derive(Debug)]
#[allow(clippy::exhaustive_enums)] // callers have no good response to unknown variants anyway
pub enum NextStep<'b, O, P: ReadPrecision> {
    /// Caller should send this data to the peer
    Send(Vec<u8>),

    /// Caller should read from the peer and call one of the `received` functions.
    Recv(RecvStep<'b, P>),

    /// The handshake is complete
    ///
    /// The returned [`Finished`] can be used to obtain the handshake output.
    ///
    /// The `Handshake` should not be used any more after this.
    Finished(Finished<'b, O, P>),
}

/// A completed handshake
///
/// Represents:
///  * [`Handshake::Output`],
///    a value representing the meaning of the completed protocol exchange.
///  * Possibly, some data which was received, but didn't form part of the protocol.
//
// Returning this in `NextStep::finished` means that the caller can access the output
// iff the handshake as finished.  Also, this type's API helps prevent accidental
// discard of any readahead that there might be.
#[derive(Debug)]
#[must_use]
pub struct Finished<'b, O, P: ReadPrecision> {
    /// The buffer
    buffer: &'b mut Buffer<P>,

    /// Details of the completed handshake:
    output: O,
}

impl<'b, O> Finished<'b, O, PreciseReads> {
    /// Return (just) the output of the completed handshake
    ///
    /// Available only if the `Buffer` was constructed with [`Buffer::new_precise()`]
    /// (or equivalent).
    pub fn into_output(self) -> Result<O, Bug> {
        if let Ok(nonzero) = NonZeroUsize::try_from(self.buffer.filled_slice().len()) {
            Err(internal!(
 "handshake complete, but we read too much earlier, and are now misframed by {nonzero} bytes!"
            ))
        } else {
            Ok(self.output)
        }
    }
}

impl<'b, O, P: ReadPrecision> Finished<'b, O, P> {
    /// Return the output, and the following already-read data as a slice
    ///
    /// (After callin gthis, the following already-read data
    /// will no longer be in the `Buffer`.)
    pub fn into_output_and_slice(self) -> (O, &'b [u8]) {
        let filled = mem::take(&mut self.buffer.filled);
        let data = &self.buffer.buf[0..filled];
        (self.output, data)
    }

    /// Return the output, and the following already-read data as a `Vec`
    ///
    /// The `Vec` is quite likely to have a considerably larger capacity than contents.
    /// (Its capacity is usually the original buffer size, when the `Buffer` was created.)
    ///
    /// The `Buffer` should not be discarded after calling this;
    /// it will not be usable.
    //
    // Ideally, this would *consume* the Buffer.  But that would mean that
    // `step` would have to take and return the buffer,
    // which would be quite inconvenient at call sites.
    pub fn into_output_and_vec(self) -> (O, Vec<u8>) {
        let mut data = mem::take(&mut self.buffer.buf).into_vec();
        data.truncate(self.buffer.filled);
        (self.output, data)
    }

    /// Return the output of the completed handshake, declaring any readahead a protocol error
    ///
    /// This function is appropriate when the peer is not supposed to send data
    /// until the handshake is complete.
    /// If data *did* arrive before then, and was read, we call it a protocol error,
    /// [`Error::ForbiddenPipelining`].
    pub fn into_output_forbid_pipelining(self) -> Result<O, Error> {
        if !self.buffer.filled_slice().is_empty() {
            Err(Error::ForbiddenPipelining)
        } else {
            Ok(self.output)
        }
    }
}

/// Next step - details for reading from the peer
///
/// Value in [`NextStep::Recv`].
///
/// Caller should read from the peer and call one of the `received` functions.
/// Specifically, caller should do one of the following:
///
///  1. Read some data into the slice returned by [`.buf()`](RecvStep::buf),
///     and then call [`.note_received()`](RecvStep::note_received).
///
///  2. Determine the available buffer space with [`.buf()`](RecvStep::buf)`.len()`,
///     write some data into the buffer's [`unfilled_slice()`](Buffer::unfilled_slice),
///     and call [`Buffer::note_received`].
///     This allows the caller to
///     dispose of the [`RecvStep`] (which mutably borrows the `Buffer`)
///     while reading,
///     at the cost of slightly less correctness checking by the compiler.
///
/// The caller should *not* wait for enough data to fill the whole `buf`.
#[derive(Debug)]
pub struct RecvStep<'b, P: ReadPrecision> {
    /// The buffer
    buffer: &'b mut Buffer<P>,

    /// Lower bound on the number of bytes that the handshake needs to read to complete.
    ///
    /// Useful only for callers that want to avoid reading beyond the end of the handshake.
    /// Always `<= .buf().len()`.
    ///
    /// The returned value has the same semantics as
    /// [`tor_bytes::IncompleteMessage.deficit`.
    deficit: NonZeroUsize,
}

impl<'b, P: ReadPrecision> RecvStep<'b, P> {
    /// Returns the buffer slice the caller should write data into.
    ///
    /// For precise reads, returns the slice of the buffer of length `deficit`.
    /// sol as to avoid reading ahead beyond the end of the handshake.
    pub fn buf(&mut self) -> &mut [u8] {
        P::recv_step_buf(self.buffer.unfilled_slice(), self.deficit)
    }

    /// Notes that `len` bytes have been received.
    ///
    /// The actual data must already have been written to the slice from `.buf()`.
    ///
    /// If `len == 0`, treats this as having received EOF (which is an error).
    ///
    /// # Panics
    ///
    /// `len` must be no more than `.buf().len()`.
    pub fn note_received(self, len: usize) -> Result<(), Error> {
        let len = len
            .try_into()
            .map_err(|_: TryFromIntError| Error::UnexpectedEof)?;
        self.buffer.note_received(len);
        Ok(())
    }
}

impl<P: ReadPrecision> Default for Buffer<P> {
    fn default() -> Self {
        Buffer::with_size(SOCKS_BUF_LEN)
    }
}

impl Buffer<()> {
    /// Creates a new default `Buffer`
    pub fn new() -> Self {
        Self::default()
    }
}

impl Buffer<PreciseReads> {
    /// Creates a new `Buffer` for reeading precisely
    ///
    /// ```
    /// use tor_socksproto::{Handshake as _, SocksProxyHandshake, SocksRequest};
    ///
    /// let mut hs = SocksProxyHandshake::new();
    /// let mut buf = tor_socksproto::Buffer::new_precise();
    /// ```
    pub fn new_precise() -> Self {
        Self::default()
    }
}

impl<P: ReadPrecision> Buffer<P> {
    /// Creates a new `Buffer` with a specified size
    ///
    /// Specify the `P` type parameter according to whether you wanted
    /// a `Buffer` like from [`Buffer::new()`], which will read eagerly,
    /// or one like from [`Buffer::new_precise()`], which will read eagerly,
    /// See [`ReadPrecision`].
    ///
    /// ```
    /// let mut buf = tor_socksproto::Buffer::<tor_socksproto::PreciseReads>::with_size(2048);
    /// ```
    pub fn with_size(size: usize) -> Self {
        Buffer {
            buf: vec![0xaa; size].into(),
            filled: 0,
            precision: P::default(),
        }
    }

    /// Creates a new `Buffer` from a partially-filed buffer
    ///
    ///  * `buf[..filled]` should contain data already read from the peer
    ///  * `buf[filled..]` should be zero (or other innocuous data),
    ///                    and will not be used (except if there are bugs)
    ///
    /// Using this and `into_parts` to obtain a `Buffer`
    /// with a differetn the read precision (different `P` type parameter)
    /// can result in malfunctions.
    pub fn from_parts(buf: Box<[u8]>, filled: usize) -> Self {
        Buffer {
            buf,
            filled,
            precision: P::default(),
        }
    }

    /// Disassembles a `Buffer`, returning the pieces
    pub fn into_parts(self) -> (Box<[u8]>, usize) {
        let Buffer {
            buf,
            filled,
            precision: _,
        } = self;
        (buf, filled)
    }

    /// The portion of the buffer that is available for writing new data.
    ///
    /// The caller may fill this (from the beginning) with more data,
    /// and then call [`Buffer::note_received`].
    /// Normally, the caller will do this after receiving a [`NextStep::Recv`] instruction.
    ///
    /// Where possible, prefer [`RecvStep::buf`] and [`RecvStep::note_received`].
    pub fn unfilled_slice(&mut self) -> &mut [u8] {
        &mut self.buf[self.filled..]
    }

    /// The portion of the buffer that contains already-read, but unprocessed, data.
    ///
    /// Callers will not normally want this.
    pub fn filled_slice(&mut self) -> &[u8] {
        &self.buf[..self.filled]
    }

    /// Notes that `len` bytes have been received.
    ///
    /// The actual data must already have been written to the slice from `.unfilled_slice()`.
    /// Where possible, prefer [`RecvStep::buf`] and [`RecvStep::note_received`].
    ///
    /// (It doesn't make sense to call this with `len == 0`.
    /// If the `0` came from a read call, this indicates EOF -
    /// but that might not be an error if the protocol implemnetation doesn't need more data.
    /// [`RecvStep::note_received`] handles this properly.)
    ///
    /// # Panics
    ///
    /// `len` must be no more than `.unfilled_slice().len()`.
    pub fn note_received(&mut self, len: NonZeroUsize) {
        let len = usize::from(len);
        assert!(len <= self.unfilled_slice().len());
        self.filled += len;
    }
}

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
    type Output: Debug;

    /// Drive a handshake forward, determining what the next step is
    ///
    /// ```no_run
    /// # fn main() -> Result<(), anyhow::Error> {
    /// use std::io::{Read as _, Write as _};
    /// use tor_socksproto::{Handshake as _, SocksProxyHandshake, SocksRequest};
    ///
    /// let socket: std::net::TcpStream = todo!();
    ///
    /// let mut hs = SocksProxyHandshake::new();
    /// let mut buf = tor_socksproto::Buffer::new();
    /// let (request, data_read_ahead) = loop {
    ///     use tor_socksproto::NextStep;
    ///     match hs.step(&mut buf)? {
    ///         NextStep::Send(data) => socket.write_all(&data)?,
    ///         NextStep::Recv(recv) => {
    ///             let got = socket.read(recv.buf())?;
    ///             recv.note_received(got);
    ///         },
    ///         NextStep::Finished(request) => break request.into_output_and_vec(),
    ///     }
    /// };
    /// let _: SocksRequest = request;
    /// let _: Vec<u8> = data_read_ahead;
    ///
    /// // Or, with precise reading:
    ///
    /// //...
    /// let mut buf = tor_socksproto::Buffer::new_precise();
    /// let request = loop {
    ///     use tor_socksproto::NextStep;
    ///     match hs.step(&mut buf)? {
    ///         //...
    ///         NextStep::Finished(request) => break request.into_output()?,
    /// #       _ => todo!(),
    ///     }
    /// };
    /// let _: SocksRequest = request;
    /// # }
    /// ```
    ///
    /// See `[ReadPrecision]` for information about read precision and the `P` type parameter.
    fn step<'b, P: ReadPrecision>(
        &mut self,
        buffer: &'b mut Buffer<P>,
    ) -> Result<NextStep<'b, <Self as Handshake>::Output, P>, Error> {
        let (drain, rv) = self.call_handshake_impl(buffer.filled_slice());

        if let Err(Error::Decode(tor_bytes::Error::Incomplete { deficit, .. })) = rv {
            let deficit = deficit.into_inner();
            return if usize::from(deficit) > buffer.unfilled_slice().len() {
                Err(Error::MessageTooLong {
                    limit: buffer.buf.len(),
                })
            } else {
                Ok(NextStep::Recv(RecvStep { buffer, deficit }))
            };
        };

        let rv = rv?;

        buffer.buf.copy_within(drain..buffer.filled, 0);
        buffer.filled -= drain;

        Ok(match rv {
            ImplNextStep::Reply { reply } => NextStep::Send(reply),
            ImplNextStep::Finished => {
                let output = self.take_output().ok_or_else(|| internal!("no output!"))?;
                NextStep::Finished(Finished { buffer, output })
            }
        })
    }

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
    //
    // When removing this API, also remove `Action`.
    #[deprecated = "use the new Handshake::step API instead"]
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

    /// [`Handshake::handshake`] for tests
    ///
    /// This wrapper function allows us to avoid writing many (or broad) allows in our tests.
    #[cfg(test)]
    #[allow(deprecated)]
    fn handshake_for_tests(&mut self, input: &[u8]) -> crate::TResult<Action> {
        self.handshake(input)
    }
}
