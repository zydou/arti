//! Define a response type for directory requests.

use tor_proto::circuit::UniqId;

use crate::Error;

/// A successful (or at any rate, well-formed) response to a directory
/// request.
#[derive(Debug)]
pub struct DirResponse {
    /// An HTTP status code.
    status: u16,
    /// The decompressed output that we got from the directory cache.
    output: Vec<u8>,
    /// The error, if any, that caused us to stop getting this response early.
    error: Option<Error>,
    /// Information about the directory cache we used.
    source: Option<SourceInfo>,
}

/// Information about the source of a directory response.
///
/// We use this to remember when a request has failed, so we can
/// abandon the circuit.
///
/// (In the future, we will probably want to use this structure to
/// remember that the cache isn't working.)
#[derive(Debug, Clone)]
pub struct SourceInfo {
    /// Unique identifier for the circuit we're using
    circuit: UniqId,
}

impl DirResponse {
    /// Construct a new DirResponse from its parts
    pub(crate) fn new(
        status: u16,
        error: Option<Error>,
        output: Vec<u8>,
        source: Option<SourceInfo>,
    ) -> Self {
        DirResponse {
            status,
            output,
            error,
            source,
        }
    }

    /// Construct a new successful DirResponse from its body.
    pub fn from_body(body: impl AsRef<[u8]>) -> Self {
        Self::new(200, None, body.as_ref().to_vec(), None)
    }

    /// Return the HTTP status code for this response.
    pub fn status_code(&self) -> u16 {
        self.status
    }

    /// Return true if this is in incomplete response.
    pub fn is_partial(&self) -> bool {
        self.error.is_some()
    }

    /// Return the error from this response, if any.
    pub fn error(&self) -> Option<&Error> {
        self.error.as_ref()
    }

    /// Return the output from this response.
    pub fn output(&self) -> &[u8] {
        &self.output
    }

    /// Consume this DirResponse and return the output in it.
    pub fn into_output(self) -> Vec<u8> {
        self.output
    }

    /// Return the source information about this response.
    pub fn source(&self) -> Option<&SourceInfo> {
        self.source.as_ref()
    }
}

impl SourceInfo {
    /// Construct a new SourceInfo
    pub(crate) fn new(circuit: UniqId) -> Self {
        SourceInfo { circuit }
    }
    /// Return the unique circuit identifier for the circuit on which
    /// we received this info.
    pub fn unique_circ_id(&self) -> &UniqId {
        &self.circuit
    }
}
