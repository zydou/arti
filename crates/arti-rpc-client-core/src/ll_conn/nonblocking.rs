//! Lower level connection type based on nonblocking IO.
//!
//! This module defines [`NonblockingConnection`], which provides a nonblocking
//! wrapper around an underlying nonblocking stream,
//! [`WriteHandle`], which queues messages for a `NonblockingConnection`,
//! and [`EventLoop`], a trait wrapping access to an event loop
//! based on poll, select, kqueue, epoll, etc.
//!
//! `NonblockingConnection` is used directly in `RpcPoll` if the user wants to provide their own
//! event loop, or wrapped in a [`BlockingConnection`](super::BlockingConnection)
//! if this RPC library is providing its own event loop.

use crate::{
    msgs::{request::ValidatedRequest, response::UnparsedResponse},
    util::define_from_for_arc,
};
use std::{
    io::{self, Read as _, Write as _},
    mem::{self},
    sync::{Arc, Mutex},
};

#[cfg(unix)]
use std::os::fd::BorrowedFd as BorrowedOsHandle;
#[cfg(windows)]
use std::os::windows::io::BorrowedSocket as BorrowedOsHandle;

use super::{Stream, retry_eintr};

/// A lower-level implementation of nonblocking IO for an open stream to the RPC server.
///
/// Unlike [`BlockingConnection`], this type _does not_ handle the IO event polling loops:
/// the caller is required to provide their own.
#[derive(derive_more::Debug)]
pub(crate) struct NonblockingConnection {
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

/// A return value from [`NonblockingConnection::interact_once`].
#[derive(Debug, Clone)]
pub(crate) enum PollStatus {
    /// The stream is closed.
    Closed,

    /// No progress can be made until the stream is available for further IO.
    WouldBlock,

    /// We have received a message.
    Msg(UnparsedResponse),
}

/// A handle that can be used to queue outgoing messages for a nonblocking stream.
///
/// Note that queueing a message has no effect unless some party is polling the stream,
/// either with [`BlockingConnection::interact()`], or [`NonblockingConnection::interact_once()`].
#[derive(Clone, Debug)]
pub(crate) struct WriteHandle {
    /// The actual implementation type for this writer.
    inner: Arc<Mutex<WriteHandleImpl>>,
}

impl WriteHandle {
    /// Queue an outgoing message for a nonblocking stream.
    pub(crate) fn send_valid(&self, msg: &ValidatedRequest) -> io::Result<()> {
        let mut w = self.inner.lock().expect("Poisoned lock");
        let was_empty = w.write_buf.is_empty();
        w.write_buf.extend_from_slice(msg.as_ref().as_bytes());

        // See TOCTOU note on `WriteHandleImpl`:
        // we need to change our interest while we are holding the
        // above mutex.
        if was_empty {
            w.event_loop.start_writing()?;
        }
        Ok(())
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
/// It would be bad if a writing thread said "now I care about write events",
/// and then the interactor checked the
/// buffer and found it empty, and only then did the writing thread add to the buffer.
///
/// To solve this, we put the `write_buf` and the `event_loop` behind the same lock:
/// While the interactor is checking the buffer, nobody is able to add to the buffer _or_ wake the
/// interactor.
#[derive(derive_more::Debug)]
struct WriteHandleImpl {
    /// An underlying buffer holding messages to be sent to the RPC server.
    //
    // TODO: Consider using a VecDeque or BytesMut or such.
    write_buf: Vec<u8>,

    /// The handle to use to wake the polling loop.
    #[debug(ignore)]
    event_loop: Box<dyn EventLoop>,
}

impl NonblockingConnection {
    /// Create a new `NonblockingConnection` from a provided [`EventLoop`] and [`Stream`].
    pub(crate) fn new(event_loop: Box<dyn EventLoop>, stream: Box<dyn Stream>) -> Self {
        Self {
            write_handle: WriteHandle {
                inner: Arc::new(Mutex::new(WriteHandleImpl {
                    write_buf: Default::default(),
                    event_loop,
                })),
            },
            read_buf: Default::default(),
            stream,
        }
    }

    /// Return a reference to this connection as a mio source.
    ///
    /// Returns None if this is was not constructed with a mio stream,
    /// or if `downgrade_source` has been called.
    pub(super) fn as_mio_source(&mut self) -> Option<&mut dyn mio::event::Source> {
        self.stream.as_mut().as_mio_source()
    }

    /// Remove any mio wrappers from this connection.
    pub(super) fn downgrade_source(&mut self) {
        // We need this rigamarole because `self.stream = self.stream.remove_mio()`
        // gives a "can't move out of self.stream, which is behind a mutable reference"
        // error.
        let mut s: Box<dyn Stream> = Box::new(std::io::empty());
        mem::swap(&mut s, &mut self.stream);
        self.stream = s.remove_mio();
    }

    /// Return a new [`WriteHandle`] that can be used to queue messages to be sent via this connection.
    pub(crate) fn writer(&self) -> WriteHandle {
        self.write_handle.clone()
    }

    /// Try to return an OS-level handle for use with this connection.
    ///
    /// This is an fd on unix and a SOCKET on windows.
    pub(crate) fn try_as_handle(&self) -> io::Result<BorrowedOsHandle<'_>> {
        self.stream.try_as_handle()
    }

    /// Replace the current `EventLoop` this [`NonblockingConnection`].
    ///
    /// This should only be done while nothing else is interacting with the stream or the waker.
    pub(crate) fn replace_event_loop_handle(&mut self, new_event_loop_handle: Box<dyn EventLoop>) {
        let mut h = self.write_handle.inner.lock().expect("Poisoned lock");
        h.event_loop = new_event_loop_handle;
    }

    /// Return true iff this [`NonblockingConnection`] currently wants to write
    ///
    /// See [`RpcPoll::wants_to_write`] and [`EventLoop`]
    /// for the semantics.
    ///
    /// [`RpcPoll::wants_to_write`]: crate::RpcPoll::wants_to_write
    /// [`EventLoop`]: crate::EventLoop
    pub(crate) fn wants_to_write(&self) -> bool {
        self.has_data_to_write()
    }

    /// Try to exchange messages with the RPC server.
    ///
    /// If the stream proves to be closed, returns [`PollStatus::Closed`].
    ///
    /// If a message is available, returns [`PollStatus::Msg`].
    /// (Note that a message may be available in the internal buffer here
    /// even if try_reading is false.)
    ///
    /// If no message is available, return [`PollStatus::WouldBlock`].
    pub(crate) fn interact_once(&mut self) -> io::Result<PollStatus> {
        use io::ErrorKind::WouldBlock;

        if let Some(msg) = self.extract_msg()? {
            return Ok(PollStatus::Msg(msg));
        }

        match self.flush_queue() {
            Ok(()) => {}
            Err(e) if e.kind() == WouldBlock => {}
            Err(e) => return Err(e),
        }

        match self.read_msg() {
            Ok(Some(msg)) => return Ok(PollStatus::Msg(msg)),
            Ok(None) => return Ok(PollStatus::Closed),
            Err(e) if e.kind() == WouldBlock => {}
            Err(e) => return Err(e),
        }

        Ok(PollStatus::WouldBlock)
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
        // See TOCTOU note on WriteHandleImpl: Our rule is to check whether we have data to write
        // within the same lock used to hold the waker, so that we can't lose any data.
        !w.write_buf.is_empty()
    }

    /// Helper: Try to get a message, reading into our read_buf as needed.
    ///
    /// (We don't use a BufReader here because
    /// its behavior with nonblocking IO is kind of underspecified.)
    fn read_msg(&mut self) -> io::Result<Option<UnparsedResponse>> {
        const READLEN: usize = 4096;
        loop {
            if let Some(msg) = self.extract_msg()? {
                return Ok(Some(msg));
            }

            let len_orig = self.read_buf.len();
            // TODO: Impose a maximum length?
            self.read_buf.resize(len_orig + READLEN, 0);
            let result = retry_eintr(|| self.stream.read(&mut self.read_buf[len_orig..]));
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

            let n = retry_eintr(|| self.stream.write(&w.write_buf[..]))?;
            vec_pop_from_front(&mut w.write_buf, n);

            if w.write_buf.is_empty() {
                w.event_loop.stop_writing()?;
            }

            // This is a no-op for the streams we support so far, but it could be necessary if
            // we support more kinds in the future.
            let () = retry_eintr(|| self.stream.flush())?;
        }
    }
}

/// Representation of an event loop that can watch a handle and arrange to call `poll`
///
/// Provided to the event-driven nonblocking RPC connection API,
/// by the user, via [`connect_polling`].
///
/// This is only used along with [`RpcPoll`]; if you aren't using that type,
/// you don't need to worry about this trait.
///
/// # Operating principles
///
/// The user code must implement an event loop,
/// which can monitor for handle readability/writeability.
///
/// The RPC library provides the user code with
/// the OS handle for the transport connection.
///
/// The RPC library always wants to read from the handle.
/// It informs the user code whether the RPC library wants to write to the handle.
///
/// When the handle is readable, or (if applicable) writeable,
/// the user code must call into the RPC library via [`RpcPoll::poll`]
/// so that the library can perform IO.
///
/// # Implementation strategies
///
/// The RPC library's API is designed to be easy to interface
/// to existing event loops.
///
/// ## Plumbing to using an existing event loop
///
/// With an existing event loop which is suitably reentrant across multiple threads,
/// or in single-threaded programs with an existing event loop:
///
///  * Call `connect_polling`; use `try_as_fd` or `try_as_socket`
///    on the returned `RpcPoll` to obtain the OS handle.
///  * Register the OS handle with the event loop,
///    and ask to be notified when the handle is readable.
///  * Implement `EventLoop::start_writing` and `EventLoop::stop_writing`:
///    `start_writing` should reregister the handle with the event loop
///    to request writeability notifications too;
///    `stop_writing` should stop writeability notifications.
///  * When notified that the handle is readable or writeable,
///    call [`RpcPoll::poll`].
///
/// Depending on the event loop's API, the type implementing `EventLoop`
/// might be a unit struct (if the event loop is global);
/// or it might be a handle onto the event loop,
/// or some kind of "event source" object if the event loop has those.
///
/// ## "Main thread only" event loops in multithreaded programs
///
/// Many real event loops have a "main thread",
/// and require all changes to OS handle interests to happen on that thread.
///
/// If you can't guarantee that all calls to `submit` will be made on the main thread,
/// you need to arrange that `start_writing` can add the writeability interest
/// even if another thread is currently blocked in the event loop waiting for IO events.
///
/// To achieve this:
///
///  * Use an inter-thread communication facility, such as an event loop "waker",
///    a self-pipe, or similar technique.  (We'll call this the "waker".)
///  * Entrol the receiving end of the waker in the event loop during setup.
///  * `EventLoop` contains just the sending handle of the waker,
///    not a reference to the real event loop.
///    `start_writing` notifies the waker.  `stop_writing` is a no-op.
///
/// When the event loop notifies your glue code (necessarily, on the main thread)
/// that the waker, or the RPC connection OS handle, is ready for IO:
///
///  * Repeatedly call `RpcPoll::poll` and dispatch any returned `Response`,
///    until it returns `WouldBlock`.
///  * Call `RpcPoll::wants_to_write` and adjust the RPC connection OS handle interest,
///    in the event loop.
///
/// (You can respond to all such wakeups with this identical, idempotent, response.)
///
/// # Single-threaded open-coded event loops
///
/// In a single-threaded program, with an open-coded event loop,
/// it is permissible to simply call `wants_to_write`
/// to determine the correct value for `pollfd.events`
/// (`POLLIN`, plus `POLLOUT` iff `wants_to_write`),
/// then `poll(2)`,
/// and `RpcPoll::poll` and/or `submit` after `poll(2)`.
///
/// You can pass an `EventLoop` which implements
/// `start_writing` and `stop_writing` as no-ops.
///
/// (This is because only `submit` can cause `wants_to_write` to change to `true`,
/// and if there is only one thread, you can know that you're not calling `submit`
/// between `wants_to_write` and `poll(2)`.)
///
/// # Detailed requirements and guarantees
///
/// Progress will only be made during calls to `poll`.
/// In particular, `submit` does not actually send the data.
///
/// The program should not sleep, without arranging that readability
/// and (as applicable) writeability of the RPC connection handle
/// will result in a wakeup.
///
/// `start_writing` must be effective right away,
/// without waiting for any other events:
/// if `submit` can be called while another thread
/// is in the program's event loop waiting for OS events,
/// user code implementing `start_writing` must
/// arrange to wake up the event loop if necessary,
/// so that writeability will result in a call to `poll`.
///
/// `start_writing` is only ever called from `submit`,
/// on the same thread.
///
/// `stop_writing` is only ever called from `RpcPoll::poll`,
/// on the same thread.
///
/// All changes to the value which would be returned from `wants_to_write`
/// are reflected in `start_writing` and `stop_writing`,
/// and vice versa.
///
/// It is OK to call `RpcPoll::poll` when the handle is not known to be ready;
/// `RpcPoll::poll` never blocks, and instead immediately returns `WouldBlock`.
/// (A loop which calls `RpcPoll::poll` should involve waiting for
/// appropriate readiness on the underling OS handle,
/// as the program would otherwise spin rather than wait.)
///
/// Immediately after creation, a connection made with `connect_polling`
/// is not interested in writing.
///
/// # Relationship to the synchronous API
///
/// It is also permissible to call the [`.execute()`](crate::RpcConn::execute)
/// family of methods on the `RpcConn` returned from `connect_polling`.
///
/// In this case, `start_writing` might be called
/// from `execute`, not just from `submit`.
///
/// [`RpcPoll`]: crate::RpcPoll
/// [`RpcPoll::poll`]: crate::RpcPoll::poll
/// [`connect_polling`]: crate::conn::RpcConnBuilder::connect_polling
//
// When the underlying IO loop is `mio`, this is a [`MioWaker`];
// otherwise, it is some user-provided type.
pub trait EventLoop: Send + Sync {
    /// Alert the polling thread that we are no longer interested in write events.
    ///
    /// In a user-provided `EventLoop`,
    /// this method will only be invoked from within [`RpcPoll::poll`](crate::RpcPoll::poll).
    fn stop_writing(&mut self) -> io::Result<()>;

    /// Alert the polling thread that we have become interested in write events.
    ///
    /// In a user-provided `EventLoop`,
    /// this method will only be invoked from within one of the `submit` or `execute` methods
    /// on [`RpcConn`](crate::RpcConn).
    fn start_writing(&mut self) -> io::Result<()>;
}

/// Remove n elements from the front of v.
///
/// # Panics
///
/// Panics if `n > v.len()`.
fn vec_pop_from_front(v: &mut Vec<u8>, n: usize) {
    // This returns an iterator, but we don't need to actually iterate over the elements.
    // The compiler appears to be smart enough to optimize it away.
    // (Cargo asm indicates that this optimizes down to a memmove.)
    v.drain(0..n);
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

    use assert_matches::assert_matches;
    use std::cmp::min;

    use super::*;

    impl super::PollStatus {
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
    impl EventLoop for TestWaker {
        fn start_writing(&mut self) -> io::Result<()> {
            self.n_wakes += 1;
            Ok(())
        }
        fn stop_writing(&mut self) -> io::Result<()> {
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
        fn as_mio_source(&mut self) -> Option<&mut dyn mio::event::Source> {
            None
        }
        fn remove_mio(self: Box<Self>) -> Box<dyn Stream> {
            self
        }
        fn try_as_handle(&self) -> io::Result<BorrowedOsHandle<'_>> {
            Err(io::Error::from(io::ErrorKind::Other))
        }
    }

    fn assert_wants_rw(nb: &NonblockingConnection, r: &io::Result<PollStatus>) {
        assert_matches!(r, Ok(PollStatus::WouldBlock));
        assert_eq!(nb.wants_to_write(), true);
    }

    fn assert_wants_r_only(nb: &NonblockingConnection, r: &io::Result<PollStatus>) {
        assert_matches!(r, Ok(PollStatus::WouldBlock));
        assert_eq!(nb.wants_to_write(), false);
    }

    #[test]
    fn read_msg() {
        let test_stream = TestStream::default();
        let mut nbconn = NonblockingConnection::new(
            Box::new(TestWaker::default()),
            Box::new(test_stream.clone()),
        );

        // Try interacting with nothing to do.
        let r = nbconn.interact_once();
        assert_wants_r_only(&nbconn, &r);

        // Give it a partial message.
        test_stream.push(b"Hello world");
        let r = nbconn.interact_once();
        assert_wants_r_only(&nbconn, &r);

        // Finish the message.
        test_stream.push(b"\nAnd many happy");
        let r = nbconn.interact_once();
        assert_eq!(r.unwrap().unwrap_msg().as_str(), "Hello world\n");

        // Then it should block...
        let r = nbconn.interact_once();
        assert_wants_r_only(&nbconn, &r);

        // Finish two more messages, and leave a partial message.
        test_stream.push(b" returns\nof the day\nto you!");
        let r = nbconn.interact_once();
        assert_eq!(r.unwrap().unwrap_msg().as_str(), "And many happy returns\n");
        let r = nbconn.interact_once();
        assert_eq!(r.unwrap().unwrap_msg().as_str(), "of the day\n");
    }

    #[test]
    fn write_msg() {
        let test_stream = TestStream::default();
        let mut nbconn = NonblockingConnection::new(
            Box::new(TestWaker::default()),
            Box::new(test_stream.clone()),
        );
        let writer = nbconn.writer();

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
        let r = nbconn.interact_once();
        assert_wants_r_only(&nbconn, &r);

        let m = test_stream.drain(v.as_ref().len());
        assert_eq!(m, v.as_ref().as_bytes());

        // Now try again, but with a blocked stream.
        {
            test_stream.inner.lock().unwrap().receive_capacity = Some(32);
        }
        writer.send_valid(&v).unwrap();

        let r: Result<PollStatus, io::Error> = nbconn.interact_once();
        assert_wants_rw(&nbconn, &r);
        {
            assert_eq!(test_stream.inner.lock().unwrap().received.len(), 32);
            // Make the capacity unlimited.
            test_stream.inner.lock().unwrap().receive_capacity = None;
        }
        let r: Result<PollStatus, io::Error> = nbconn.interact_once();
        assert_wants_r_only(&nbconn, &r);
        let m = test_stream.drain(v.as_ref().len());
        assert_eq!(m, v.as_ref().as_bytes());
    }
}
