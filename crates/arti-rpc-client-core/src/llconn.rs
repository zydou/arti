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

/// A low-level reader type, wrapping an [`UnvalidatedReader`].
///
/// (Currently it performs no additional validation; instead it assumes
/// that Arti is obeying its specification.)
pub struct Reader {
    backend: Box<dyn io::BufRead + Send>,
}

/// A low-level writer type, wrapping an [`UnvalidatdWriter`].
///
/// It enforces the property that outbound requests are syntactically well-formed.
pub struct Writer {
    backend: Box<dyn io::Write + Send>,
}

impl Reader {
    /// Create a new Reader, wrapping a BufRead.
    pub fn new<T>(backend: T) -> Self
    where
        T: io::BufRead + Send + 'static,
    {
        Self {
            backend: Box::new(backend),
        }
    }

    /// Receive an inbound reply.
    ///
    /// Blocks as needed until the reply is available.
    ///
    /// Returns `Ok(None)` on end-of-stream.
    pub fn read_msg(&mut self) -> io::Result<Option<UnparsedResponse>> {
        let mut s = String::new();

        // TODO: possibly ensure that the value is legit?
        match self.backend.read_line(&mut s) {
            Err(e) => Err(e),
            Ok(0) => Ok(None),
            Ok(_) if s.ends_with('\n') => Ok(Some(UnparsedResponse::new(s))),
            // NOTE: This can happen if we hit EOF.
            //
            // We discard any truncated lines in this case.
            Ok(_) => Ok(None),
        }
    }
}

impl Writer {
    /// Create a new writer, wrapping an [`UnvalidatedWriter`].
    pub fn new<T>(backend: T) -> Self
    where
        T: io::Write + Send + 'static,
    {
        Self {
            backend: Box::new(backend),
        }
    }

    /// Send an outbound request.
    ///
    /// Return an error if an IO problems occurred, or if the request was not well-formed.
    pub fn send_request(&mut self, request: &str) -> Result<(), SendRequestError> {
        let _req: ParsedRequest = serde_json::from_str(request)?;
        // TODO: Maybe ensure it is all one line, if some "strict mode" flag is set?
        // (The spec only requires that arti send its responses in jsonlines;
        // clients are allowed to send an arbitrary stream of json.)
        self.backend.write_all(request.as_bytes())?;
        Ok(())
    }

    /// Crate-internal: Send a request that is known to be valid.
    ///
    /// (This is reliable since we never construct a `ValidRequest` except by encoding a
    /// known-correct object.)
    pub(crate) fn send_valid(&mut self, request: &ValidatedRequest) -> io::Result<()> {
        self.backend.write_all(request.as_ref().as_bytes())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.backend.flush()
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
