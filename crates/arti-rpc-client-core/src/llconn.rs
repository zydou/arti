//! Lowest-level API interface to an active RPC connection.
//!
//! Treats messages as unrelated strings, and validates outgoing messages for correctness.

use crate::{
    msgs::{
        request::{ParsedRequest, ValidatedRequest},
        response::UnparsedResponse,
    },
    util::define_from_for_arc,
};
use std::{io, sync::Arc};

/// Trait representing the ability to read a single RPC message from
/// an Arti RPC connection.
//
// We make this a trait so that we can put it in a Box<dyn _> inside
// Reader, and not force Reader to be parameterized itself.
pub trait UnvalidatedReader {
    /// Read the next message from `self`.
    ///
    /// Return Ok(None) on EOF, possibly discarding any truncated or incomplete message.
    ///
    /// Does not check whether the resulting message is well-formed;
    /// if Arti has bugs, the resulting message may not even be valid JSON.
    fn read_msg_unvalidated(&mut self) -> io::Result<Option<String>>;
}

/// Trait representing the ability to write a single RPC message onto
/// an Arti RPC connection.
//
// We make this a trait so that we can put it in a Box<dyn _> inside
// Reader, and not force Reader to be parameterized itself.
pub trait UnvalidatedWriter {
    /// Write a message to `self`.
    ///
    /// Does not check whether `msg` is a valid message.
    /// If the caller does not provide a valid RPC request,
    /// the RPC connection may enter an unusable state.
    fn write_msg_unvalidated(&mut self, msg: &[u8]) -> io::Result<()>;

    /// Flush any unwritten bytes on this writer.
    fn flush(&mut self) -> io::Result<()>;
}

// Every BufRead is automatically an UnvalidatedReader.
impl<T> UnvalidatedReader for T
where
    T: io::BufRead + ?Sized,
{
    fn read_msg_unvalidated(&mut self) -> io::Result<Option<String>> {
        let mut s = String::new();
        // We assume that Arti obeys the specification and puts one JSON message per line.
        //
        // We do not enforce a maximum line size; instead we trust Arti not to DOS us.
        match self.read_line(&mut s) {
            Err(e) => Err(e),
            Ok(0) => Ok(None),
            Ok(_) if s.ends_with('\n') => Ok(Some(s)),
            // NOTE: This discards truncated lines on EOF.
            Ok(_) => Ok(None), // TODO: Log?
        }
    }
}

// Every Write is automatically an UnvalidatedWriter.
impl<T> UnvalidatedWriter for T
where
    T: io::Write + ?Sized,
{
    fn write_msg_unvalidated(&mut self, msg: &[u8]) -> io::Result<()> {
        self.write_all(msg)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush()
    }
}

/// A low-level reader type, wrapping an [`UnvalidatedReader`].
///
/// (Currently it performs no additional validation; instead it assumes
/// that Arti is obeying its specification.)
pub struct Reader {
    backend: Box<dyn UnvalidatedReader + Send>,
}

/// A low-level writer type, wrapping an [`UnvalidatdWriter`].
///
/// It enforces the property that outbound requests are syntactically well-formed.
pub struct Writer {
    backend: Box<dyn UnvalidatedWriter + Send>,
}

impl UnvalidatedReader for Reader {
    fn read_msg_unvalidated(&mut self) -> io::Result<Option<String>> {
        self.backend.read_msg_unvalidated()
    }
}

impl UnvalidatedWriter for Writer {
    fn write_msg_unvalidated(&mut self, msg: &[u8]) -> io::Result<()> {
        self.backend.write_msg_unvalidated(msg)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.backend.flush()
    }
}

impl Reader {
    /// Create a new writer, wrapping an [`UnvalidatedReader`].
    pub fn new(backend: Box<dyn UnvalidatedReader + Send>) -> Self {
        Self { backend }
    }

    /// Receive an inbound reply.
    ///
    /// Blocks as needed until the reply is available.
    ///
    /// Returns `Ok(None)` on end-of-stream.
    pub fn read_msg(&mut self) -> io::Result<Option<UnparsedResponse>> {
        // TODO: possibly ensure that the value is legit?
        match self.read_msg_unvalidated() {
            Err(e) => Err(e),
            Ok(None) => Ok(None),
            Ok(Some(m)) => Ok(Some(UnparsedResponse::new(m))),
        }
    }
}

impl Writer {
    /// Create a new writer, wrapping an [`UnvalidatedWriter`].
    pub fn new(backend: Box<dyn UnvalidatedWriter + Send>) -> Self {
        Self { backend }
    }

    /// Send an outbound request.
    ///
    /// Return an error if an IO problems occurred, or if the request was not well-formed.
    pub fn send_request(&mut self, request: &str) -> Result<(), SendRequestError> {
        let _req: ParsedRequest = serde_json::from_str(request)?;
        // TODO: Maybe ensure it is all one line, if some "strict mode" flag is set?
        // (The spec only requires that arti send its responses in jsonlines;
        // clients are allowed to send an arbitrary stream of json.)
        self.write_msg_unvalidated(request.as_bytes())?;
        Ok(())
    }

    /// Crate-internal: Send a request that is known to be valid.
    ///
    /// (This is reliable since we never construct a `ValidRequest` except by encoding a
    /// known-correct object.)
    pub(crate) fn send_valid(&mut self, request: &ValidatedRequest) -> io::Result<()> {
        self.write_msg_unvalidated(request.as_ref().as_bytes())
    }
}

/// An error that has occurred while sending a request.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SendRequestError {
    #[error("Unable to send request: {0}")]
    Io(Arc<io::Error>),
    #[error("Invalid Json request: {0}")]
    InvalidRequest(Arc<serde_json::Error>),
}
define_from_for_arc!( io::Error => SendRequestError [Io] );
define_from_for_arc!( serde_json::Error => SendRequestError [InvalidRequest] );
