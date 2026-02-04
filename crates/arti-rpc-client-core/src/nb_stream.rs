//! Low-level nonblocking stream implementation.
//!
//! This module defines two main types: [`NonblockingStream`].
//! (a low-level type for use by external tools
//! that want to implement their own nonblocking IO),
//! and [`PollingStream`] (a slightly higher-level type
//! that we use internally when we are asked to provide
//! our own nonblocking IO loop(s)).
//!
//! This module also defines several traits for use by these types.
//!
//! Treats messages as unrelated strings, and validates outgoing messages for correctness.
//!
//! TODO nb: For now, nothing in this module is actually public; we'll want to expose some of these types.

use mio::Interest;

use crate::{
    msgs::{request::ValidatedRequest, response::UnparsedResponse},
    util::define_from_for_arc,
};
use std::{
    io::{self, Read as _, Write as _},
    mem,
    sync::{Arc, Mutex},
};

/// An IO stream to Arti, along with any supporting logic necessary to check it for readiness.
///
/// Internally, this uses `mio` along with a [`NonblockingStream`] to check for events.
///
/// To use this type, mark the stream as nonblocking
/// with e.g. [TcpStream::set_nonblocking](std::net::TcpStream::set_nonblocking),
/// convert it into a [`mio::event::Source`],
/// and pass it to [`PollingStream::new()`]
///
/// At this point, you can read and write messages via nonblocking IO.
///
/// The [`PollingStream::writer()`] method will return a handle that you can use from any thread
/// that you can use to queue an outbound message.
///
/// No messages are actually sent or received unless some thread is calling [`PollingStream::interact()`].
#[derive(Debug)]
pub(crate) struct PollingStream {
    /// The poll object.
    ///
    /// (This typically corresponds to a kqueue or epoll handle.)
    poll: mio::Poll,

    /// A small buffer to receive IO readiness events.
    events: mio::Events,

    /// The underlying stream.
    ///
    /// Invariant: `stream.stream` is a [`MioStream`].
    stream: NonblockingStream,
}

/// A `mio` token corresponding to the Waker we use to tell the interactor about new writes.
const WAKE_TOKEN: mio::Token = mio::Token(0);

/// A `mio` token corresponding to the Stream connecting to the RPC
const STREAM_TOKEN: mio::Token = mio::Token(1);

impl PollingStream {
    /// Create a new PollingStream.
    ///
    /// The `stream` argument must support [`MioStream`], and must be set for nonblocking IO.
    pub(crate) fn new(stream: Box<dyn MioStream>) -> io::Result<Self> {
        let poll = mio::Poll::new()?;
        let waker = mio::Waker::new(poll.registry(), WAKE_TOKEN)?;

        let stream = NonblockingStream::new(Box::new(waker), stream);

        let mut cio = Self {
            poll,
            events: mio::Events::with_capacity(4),
            stream,
        };

        // We register the stream here, since we want to use it exclusively with `reregister`
        // later on.
        cio.poll.registry().register(
            cio.stream
                .stream
                .as_mio_stream()
                .expect("logic error: not a mio stream."),
            STREAM_TOKEN,
            Interest::READABLE,
        )?;

        Ok(cio)
    }

    /// Return a new [`WriteHandle`] that can be used to queue messages to be sent via this stream.
    pub(crate) fn writer(&self) -> WriteHandle {
        self.stream.writer()
    }

    /// Interact with the underlying stream.
    ///
    /// Returns an error if an IO condition has failed.
    /// Returns None if the other side has closed the stream.
    /// Otherwise, returns an unparsed message from the RPC server.
    ///
    /// Unless some thread is calling this method, nobody will actually be reading or writing from
    /// the [`PollingStream`], and so nobody's requests will be sent or answered.
    pub(crate) fn interact(&mut self) -> io::Result<Option<UnparsedResponse>> {
        // Should we try to read and write? Start out by assuming "yes".
        let mut try_writing = true;
        let mut try_reading = true;

        loop {
            // Try interacting with the underlying stream.
            let want_io = match self.stream.interact_once(try_writing, try_reading)? {
                PollStatus::Closed => return Ok(None),
                PollStatus::Msg(msg) => return Ok(Some(msg)),
                PollStatus::WouldBlock(w) => w,
            };

            // We're blocking on reading and possibly writing.  Register our interest,
            // so that we get woken as appropriate.
            self.poll.registry().reregister(
                self.stream
                    .stream
                    .as_mio_stream()
                    .expect("logic error: not a mio stream!"),
                STREAM_TOKEN,
                want_io.into(),
            )?;

            // Poll until the socket is ready to read or write,
            // _or_ until somebody invokes the Waker because they have queued more to write.
            'inner: loop {
                match self.poll.poll(&mut self.events, None) {
                    Ok(()) => break 'inner,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                        continue 'inner;
                    }
                    Err(e) => return Err(e),
                }
            }

            // Now that we've been woken, see which events we've been woken with,
            // and adjust our plans accordingly on the next time through the loop.
            try_reading = false;
            try_writing = false;
            for event in self.events.iter() {
                if event.token() == STREAM_TOKEN {
                    if event.is_readable() {
                        try_reading = true;
                    }
                    if event.is_writable() {
                        try_writing = true;
                    }
                } else if event.token() == WAKE_TOKEN {
                    try_writing = true;
                }
            }
        }
    }
}

/// A handle that can be used to queue outgoing messages for a nonblocking stream.
///
/// Note that queueing a message has no effect unless some party is polling the stream,
/// either with [`PollingStream::interact()`], or [`NonblockingStream::interact_once()`].
#[derive(Clone, Debug)]
pub(crate) struct WriteHandle {
    /// The actual implementation type for this writer.
    inner: Arc<Mutex<WriteHandleImpl>>,
}

impl WriteHandle {
    /// Queue an outgoing message for a nonblocking stream.
    pub(crate) fn send_valid(&self, msg: &ValidatedRequest) -> io::Result<()> {
        let mut w = self.inner.lock().expect("Poisoned lock");
        w.write_buf.extend_from_slice(msg.as_ref().as_bytes());

        // See TOCTOU note on `WriteHandleImpl`: we need to wake() while we are holding the
        // above mutex.
        w.waker.wake()
    }
}

/// An error that has occurred while sending a request.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SendRequestError {
    /// An IO error occurred while sending a request.
    #[error("Unable to wake poling loop")]
    Io(#[source] Arc<io::Error>),
    /// We found a problem in the JSON while sending a request.
    #[error("Invalid Json request")]
    InvalidRequest(#[from] crate::InvalidRequestError),
    /// Internal error while re-encoding request.  Should be impossible.
    #[error("Unable to re-encode request after parsing it‽")]
    ReEncode(#[source] Arc<serde_json::Error>),
}
define_from_for_arc!( io::Error => SendRequestError [Io] );

/// The inner implementation for [`WriteHandle`].
///
/// NOTE: We need to be careful to avoid TOCTOU problems with this type:
/// It would be bad if a writing thread called `waker.wake()`, and then the interactor checked the
/// buffer and found it empty, and only then did the writing thread add to the buffer.
///
/// To solve this, we put the write_buf and the waker behind the same lock:
/// While the interactor is checking the buffer, nobody is able to add to the buffer _or_ wake the
/// interactor.
#[derive(derive_more::Debug)]
struct WriteHandleImpl {
    /// An underlying buffer holding messages to be sent to the RPC server.
    //
    // TODO: Consider using a VecDeque or BytesMut or such.
    write_buf: Vec<u8>,

    /// The waker to use to wake the polling loop.
    #[debug(ignore)]
    waker: Box<dyn Waker>,
}

/// A lower-level implementation of nonblocking IO for an open stream to the RPC server.
///
/// Unlike [`PollingStream`], this type _does not_ handle the IO event polling loops:
/// the caller is required to provide their own.
#[derive(derive_more::Debug)]
pub(crate) struct NonblockingStream {
    /// A write handle used to write onto this stream.
    #[debug(ignore)]
    write_handle: WriteHandle,

    /// A buffer of incoming messages (possibly partial) from the RPC server.
    //
    // TODO: Consider using a VecDeque or BytesMut or such.
    read_buf: Vec<u8>,

    /// The underlying nonblocking stream.
    #[debug(ignore)]
    stream: Box<dyn Stream>,
}

/// Helper to return which events a [`NonblockingStream`] is interested in.
#[derive(Clone, Debug, Default, Copy)]
pub(crate) struct WantIo {
    /// True if the stream is interested in writing.
    ///
    /// (It is always interested in reading.)
    write: bool,
}

#[allow(dead_code)] // TODO nb: remove or expose.
impl WantIo {
    /// Return true if the stream is interested in reading.
    fn want_read(&self) -> bool {
        true
    }

    /// Return true if the stream is interested in writing.
    fn want_write(&self) -> bool {
        self.write
    }
}

impl From<WantIo> for mio::Interest {
    fn from(value: WantIo) -> Self {
        if value.write {
            mio::Interest::WRITABLE | mio::Interest::READABLE
        } else {
            mio::Interest::READABLE
        }
    }
}

/// A return value from [`NonblockingStream::interact_once`].
#[derive(Debug, Clone)]
pub(crate) enum PollStatus {
    /// The stream is closed.
    Closed,

    /// No progress can be made until the stream is available for further IO.
    WouldBlock(WantIo),

    /// We have received a message.
    Msg(UnparsedResponse),
}

impl NonblockingStream {
    /// Create a new `NonblockingStream` from a provided [`Waker`] and [`Stream`].
    pub(crate) fn new(waker: Box<dyn Waker>, stream: Box<dyn Stream>) -> Self {
        Self {
            write_handle: WriteHandle {
                inner: Arc::new(Mutex::new(WriteHandleImpl {
                    write_buf: Default::default(),
                    waker,
                })),
            },
            read_buf: Default::default(),
            stream,
        }
    }

    /// Return a new [`WriteHandle`] that can be used to queue messages to be sent via this stream.
    pub(crate) fn writer(&self) -> WriteHandle {
        self.write_handle.clone()
    }

    /// Try to exchange messages with the RPC server.
    ///
    /// If `try_reading` is true, then we should try reading from the RPC server.
    /// If `try_writing` is true, then we should try flushing messages to the RPC server
    /// (if we have any).
    ///
    /// If the stream proves to be closed, returns [`PollStatus::Closed`].
    ///
    /// If a message is available, returns [`PollStatus::Msg`].
    /// (Note that a message may be available in the internal buffer here even if try_reading is false.)
    ///
    /// If no message is available, return [`PollStatus::WouldBlock`] with a [`WantIo`]
    /// describing which IO operations we would like to perform.
    pub(crate) fn interact_once(
        &mut self,
        try_writing: bool,
        try_reading: bool,
    ) -> io::Result<PollStatus> {
        use io::ErrorKind::WouldBlock;

        if let Some(msg) = self.extract_msg()? {
            return Ok(PollStatus::Msg(msg));
        }

        let mut want_io = WantIo::default();

        if try_writing {
            match self.flush_queue() {
                Ok(()) => {}
                Err(e) if e.kind() == WouldBlock => want_io.write = true,
                Err(e) => return Err(e),
            }
        }
        if try_reading {
            match self.read_msg() {
                Ok(Some(msg)) => return Ok(PollStatus::Msg(msg)),
                Ok(None) => return Ok(PollStatus::Closed),
                Err(e) if e.kind() == WouldBlock => {}
                Err(e) => return Err(e),
            }
        }

        if !want_io.write && self.has_data_to_write() {
            want_io.write = true;
        }

        Ok(PollStatus::WouldBlock(want_io))
    }

    /// Internal helper: Try to get a buffered message out of our `read_buf`.
    ///
    /// Returns Ok(None) if there are no complete lines in the buffer.
    ///
    /// If there is a line, but it is not valid UTF-8, returns an error and discards the line.
    fn extract_msg(&mut self) -> io::Result<Option<UnparsedResponse>> {
        // Look for an eol within the buffer.
        let Some(eol_pos) = memchr::memchr(b'\n', &self.read_buf[..]) else {
            return Ok(None);
        };
        // Split off the part of the buffer ending with the EOF from the remainder.
        let mut line = self.read_buf.split_off(eol_pos + 1);
        // Put the message in "line" and the remainder of the buffer in read_buf.
        mem::swap(&mut line, &mut self.read_buf);
        // Try to convert the line to an UnparsedResponse.
        match String::from_utf8(line) {
            Ok(s) => Ok(Some(UnparsedResponse::new(s))),
            Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
        }
    }

    /// Internal helper: Return true if there is any outgoing data queued to be written.
    fn has_data_to_write(&self) -> bool {
        let w = self.write_handle.inner.lock().expect("Lock poisoned");
        // See TOCTOU note on WriteHandleImpl: We need to check whether we have data to write
        // with the same lock used to hold the waker, so that we can't lose any data.
        !w.write_buf.is_empty()
    }

    /// Helper: Try to get a message, reading into our read_buf as needed.
    ///
    /// (We don't use a BufReader here because its behavior with nonblocking IO is kind of underspecified.)
    fn read_msg(&mut self) -> io::Result<Option<UnparsedResponse>> {
        const READLEN: usize = 4096;
        loop {
            if let Some(msg) = self.extract_msg()? {
                return Ok(Some(msg));
            }

            let len_orig = self.read_buf.len();
            // TODO: Impose a maximum length?
            self.read_buf.resize(len_orig + READLEN, 0);
            // TODO: Do I need to check for eintr?
            let result = self.stream.read(&mut self.read_buf[len_orig..]);
            match result {
                Ok(0) => return Ok(None),
                Ok(n) => {
                    self.read_buf.truncate(len_orig + n);
                }
                Err(e) => {
                    self.read_buf.truncate(len_orig);
                    return Err(e);
                }
            }
        }
    }

    /// Try to flush data from the underlying write buffer.
    ///
    /// Returns Ok() only if all of the data is flushed, and the write buffer has become empty.
    fn flush_queue(&mut self) -> io::Result<()> {
        let mut w = self.write_handle.inner.lock().expect("Poisoned lock.");
        loop {
            if w.write_buf.is_empty() {
                return Ok(());
            }
            // TODO: Do I need to check for eintr?
            let n = self.stream.write(&w.write_buf[..])?;
            vec_pop_from_front(&mut w.write_buf, n);
            // TODO: DO I need to flush?
        }
    }
}

/// Any type we can use as a target for [`NonblockingStream`].
pub(crate) trait Stream: io::Read + io::Write + Send {
    /// If this Stream object is a [`MioStream`], upcast it to one.
    ///
    /// Otherwise return None.
    fn as_mio_stream(&mut self) -> Option<&mut dyn MioStream>;
}

/// A [`Stream`] that we can use inside a [`PollingStream`].
pub(crate) trait MioStream: Stream + mio::event::Source {}

/// An object that can wake a pending IO poller.
///
/// When the underlying IO loop is `mio`, this is a [`mio::Waker`];
/// otherwise, it is some user-provided type.
pub(crate) trait Waker: Send + Sync {
    /// Alert the polling thread.
    fn wake(&mut self) -> io::Result<()>;
}

impl Waker for mio::Waker {
    fn wake(&mut self) -> io::Result<()> {
        mio::Waker::wake(self)
    }
}

/// Implement Stream and MioStream for a related pair of traits.
macro_rules! impl_traits {
    { $stream:ty => $mio_stream:ty } => {
        impl Stream for $stream {
            fn as_mio_stream(&mut self) -> Option<&mut dyn MioStream> {
                None
            }
        }
        impl Stream for $mio_stream {
            fn as_mio_stream(&mut self) -> Option<&mut dyn MioStream> {
                Some(self as _)
            }
        }
        impl MioStream for $mio_stream {}
    }
}

impl_traits! { std::net::TcpStream => mio::net::TcpStream }
#[cfg(unix)]
impl_traits! { std::os::unix::net::UnixStream => mio::net::UnixStream }

/// Remove n elements from the front of v.
///
/// # Panics
///
/// Panics if `n > v.len()`.
fn vec_pop_from_front(v: &mut Vec<u8>, n: usize) {
    v.copy_within(n.., 0);
    let new_len = v.len() - n;
    v.truncate(new_len);
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use std::cmp::min;

    use super::*;

    impl super::PollStatus {
        fn unwrap_wantio(self) -> WantIo {
            match self {
                PollStatus::WouldBlock(want_io) => want_io,
                other => panic!("Wanted WantIo; found {other:?}"),
            }
        }

        fn unwrap_msg(self) -> UnparsedResponse {
            match self {
                PollStatus::Msg(msg) => msg,
                other => panic!("Wanted Msg; found {other:?}"),
            }
        }
    }

    #[derive(Default, Debug)]
    struct TestWaker {
        n_wakes: usize,
    }
    impl Waker for TestWaker {
        fn wake(&mut self) -> io::Result<()> {
            self.n_wakes += 1;
            Ok(())
        }
    }

    // Helper: Simulates nonblocking IO.
    //
    // Has interior mutability so we can inspect it.
    #[derive(Default, Debug, Clone)]
    struct TestStream {
        inner: Arc<Mutex<TestStreamInner>>,
    }
    #[derive(Default, Debug, Clone)]
    struct TestStreamInner {
        // Bytes that we have _received_ from the client.
        received: Vec<u8>,
        // Bytes that we are _sending_ to the client.
        sending: Vec<u8>,
        receive_capacity: Option<usize>,
    }
    impl TestStream {
        fn push(&self, b: &[u8]) {
            self.inner.lock().unwrap().sending.extend_from_slice(b);
        }
        fn drain(&self, n: usize) -> Vec<u8> {
            let mut s = self.inner.lock().unwrap();
            let n = min(n, s.received.len());
            let mut v = vec![0_u8; n];
            v[..].copy_from_slice(&s.received[..n]);
            vec_pop_from_front(&mut s.received, n);
            v
        }
    }

    impl io::Read for TestStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut s = self.inner.lock().unwrap();
            if s.sending.is_empty() {
                return Err(io::ErrorKind::WouldBlock.into());
            }

            let n_to_copy = min(s.sending.len(), buf.len());
            buf[..n_to_copy].copy_from_slice(&s.sending[..n_to_copy]);
            vec_pop_from_front(&mut s.sending, n_to_copy);
            Ok(n_to_copy)
        }
    }

    impl io::Write for TestStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }

            let mut s = self.inner.lock().unwrap();

            let n_to_copy = match s.receive_capacity {
                Some(0) => return Err(io::ErrorKind::WouldBlock.into()),
                Some(n) => min(n, buf.len()),
                None => buf.len(),
            };

            s.received.extend_from_slice(&buf[..n_to_copy]);
            if let Some(ref mut n) = s.receive_capacity {
                *n -= n_to_copy;
            }

            Ok(n_to_copy)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Stream for TestStream {
        fn as_mio_stream(&mut self) -> Option<&mut dyn MioStream> {
            None
        }
    }

    #[test]
    fn read_msg() {
        let test_stream = TestStream::default();
        let mut stream = NonblockingStream::new(
            Box::new(TestWaker::default()),
            Box::new(test_stream.clone()),
        );

        // Try interacting with nothing to do.
        let r = stream.interact_once(true, true);
        assert_eq!(r.unwrap().unwrap_wantio().want_write(), false);

        // Give it a partial message.
        test_stream.push(b"Hello world");
        let r = stream.interact_once(true, true);
        assert_eq!(r.unwrap().unwrap_wantio().want_write(), false);

        // Finish the message.
        test_stream.push(b"\nAnd many happy");
        let r = stream.interact_once(true, true);
        assert_eq!(r.unwrap().unwrap_msg().as_str(), "Hello world\n");

        // Then it should block...
        let r = stream.interact_once(true, true);
        assert_eq!(r.unwrap().unwrap_wantio().want_write(), false);

        // Finish two more messages, and leave a partial message.
        test_stream.push(b" returns\nof the day\nto you!");
        let r = stream.interact_once(true, true);
        assert_eq!(r.unwrap().unwrap_msg().as_str(), "And many happy returns\n");
        let r = stream.interact_once(true, true);
        assert_eq!(r.unwrap().unwrap_msg().as_str(), "of the day\n");
    }

    #[test]
    fn write_msg() {
        let test_stream = TestStream::default();
        let mut stream = NonblockingStream::new(
            Box::new(TestWaker::default()),
            Box::new(test_stream.clone()),
        );
        let writer = stream.writer();

        // Make sure we can write in a nonblocking way...
        let req1 = r#"{"id":7,
                 "obj":"foo",
                 "method":"arti:x-frob", "params":{},
                 "extra": "preserved"
            }"#;
        let v = ValidatedRequest::from_string_strict(req1).unwrap();
        writer.send_valid(&v).unwrap();

        // At this point the above request is queued, but won't be sent until we interact.
        {
            assert!(test_stream.inner.lock().unwrap().received.is_empty());
        }

        // Now interact. This will cause the whole request to get flushed.
        let r = stream.interact_once(true, true);
        assert_eq!(r.unwrap().unwrap_wantio().want_write(), false);

        let m = test_stream.drain(v.as_ref().len());
        assert_eq!(m, v.as_ref().as_bytes());

        // Now try again, but with a blocked stream.
        {
            test_stream.inner.lock().unwrap().receive_capacity = Some(32);
        }
        writer.send_valid(&v).unwrap();

        let r: Result<PollStatus, io::Error> = stream.interact_once(true, true);
        assert_eq!(r.unwrap().unwrap_wantio().want_write(), true);
        {
            assert_eq!(test_stream.inner.lock().unwrap().received.len(), 32);
            // Make the capacity unlimited.
            test_stream.inner.lock().unwrap().receive_capacity = None;
        }
        let r: Result<PollStatus, io::Error> = stream.interact_once(true, true);
        assert_eq!(r.unwrap().unwrap_wantio().want_write(), false);
        let m = test_stream.drain(v.as_ref().len());
        assert_eq!(m, v.as_ref().as_bytes());
    }

    // TODO nb: It would be good to have additional tests for the MIO code as well.
}
