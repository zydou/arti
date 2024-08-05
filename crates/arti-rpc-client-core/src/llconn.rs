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

/// A low-level reader type, wrapping a boxed [`Read`](io::Read).
///
/// (Currently it performs no additional validation; instead it assumes
/// that Arti is obeying its specification.)
pub struct Reader {
    /// The underlying reader.
    backend: Box<dyn io::BufRead + Send>,
}

/// A low-level writer type, wrapping a boxed [`Write`](io::Write).
///
/// It enforces the property that outbound requests are syntactically well-formed.
pub struct Writer {
    /// The underlying writer.
    backend: Box<dyn io::Write + Send>,
}

impl Reader {
    /// Create a new Reader, wrapping an [`io::BufRead`].
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
    /// Create a new writer, wrapping an [`io::Write`].
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
        let req: ParsedRequest = serde_json::from_str(request)?;
        // TODO: Perhaps someday we'd like a way to send without re-encoding.
        let validated = req
            .format()
            .map_err(|e| SendRequestError::ReEncode(Arc::new(e)))?;
        self.send_valid(&validated)?;
        Ok(())
    }

    /// Crate-internal: Send a request that is known to be valid.
    ///
    /// (This is reliable since we never construct a `ValidRequest` except by encoding a
    /// known-correct object.)
    pub(crate) fn send_valid(&mut self, request: &ValidatedRequest) -> io::Result<()> {
        self.backend.write_all(request.as_ref().as_bytes())
    }

    /// Flush any queued data in this writer.
    pub fn flush(&mut self) -> io::Result<()> {
        self.backend.flush()
    }
}

/// An error that has occurred while sending a request.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SendRequestError {
    /// An IO error occurred while sending a request.
    #[error("Unable to send request: {0}")]
    Io(Arc<io::Error>),
    /// We found a problem in the JSON while sending a request.
    #[error("Invalid Json request: {0}")]
    InvalidRequest(Arc<serde_json::Error>),
    /// Internal error while re-encoding request.  Should be impossible.
    #[error("Unable to re-encode request after parsing it‽")]
    ReEncode(Arc<serde_json::Error>),
}
define_from_for_arc!( io::Error => SendRequestError [Io] );
define_from_for_arc!( serde_json::Error => SendRequestError [InvalidRequest] );

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

    use std::thread;

    use io::{BufRead, BufReader, Cursor};

    use super::*;

    struct NeverConnected;
    impl io::Read for NeverConnected {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::NotConnected.into())
        }
    }
    impl io::Write for NeverConnected {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::NotConnected.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::NotConnected.into())
        }
    }

    #[test]
    fn reading() {
        // basic case: valid reply.
        let mut v = r#"{"id":7,"result":{}}"#.as_bytes().to_vec();
        v.push(b'\n');
        let mut r = Reader::new(Cursor::new(v));
        let m = r.read_msg();
        let msg = m.unwrap().unwrap();
        assert_eq!(
            msg.as_ref().strip_suffix('\n').unwrap(),
            r#"{"id":7,"result":{}}"#
        );

        // case 2: incomplete reply (gets treated as EOF)
        let mut r = Reader::new(Cursor::new(r#"{"id":7"#));
        let m = r.read_msg();
        assert!(m.unwrap().is_none());

        // Case 3: empty buffer (gets treated as EOF since there is no more to read.
        let mut r = Reader::new(Cursor::new(""));
        let m = r.read_msg();
        assert!(m.unwrap().is_none());

        // Case 4: reader gives an error
        let mut r = Reader::new(BufReader::new(NeverConnected));
        let m = r.read_msg();
        assert_eq!(m.unwrap_err().kind(), io::ErrorKind::NotConnected);
    }

    #[test]
    fn write_success() {
        let (r, w) = socketpair::socketpair_stream().unwrap();
        let mut w = Writer::new(w);
        let mut r = io::BufReader::new(r);

        let wt: thread::JoinHandle<Result<(), SendRequestError>> = thread::spawn(move || {
            let res = w.send_request(
                r#"{"id":7,
                 "obj":"foo",
                 "method":"arti:x-frob", "params":{},
                 "extra": "preserved"
            }"#,
            );
            w.flush().unwrap();
            drop(w);
            res
        });
        let rt = thread::spawn(move || -> io::Result<String> {
            let mut s = String::new();
            r.read_line(&mut s)?;
            Ok(s)
        });
        let write_result = wt.join().unwrap();
        assert!(write_result.is_ok());
        let read_result = rt.join().unwrap().unwrap();
        assert_eq!(
            read_result.strip_suffix('\n').unwrap(),
            r#"{"id":7,"obj":"foo","method":"arti:x-frob","params":{},"extra":"preserved"}"#
        );
    }

    #[test]
    fn write_failure() {
        let mut w = Writer::new(NeverConnected);

        // Write an incomplete request.
        assert!(matches!(
            w.send_request("{"),
            Err(SendRequestError::InvalidRequest(_))
        ));

        // Write an invalid request.
        assert!(matches!(
            w.send_request("{}"),
            Err(SendRequestError::InvalidRequest(_))
        ));

        // Valid request, but get an IO error.
        let r = w.send_request(r#"{"id":7,"obj":"foo","method":"arti:x-frob","params":{}}"#);
        assert!(
            matches!(r, Err(SendRequestError::Io(e)) if e.kind() == io::ErrorKind::NotConnected)
        );
    }
}
