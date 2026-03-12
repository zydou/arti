//! Define a wrapper around [`NonblockingConnection`] providing blocking io,
//! based on the [`mio`] library.
//!
//! We use this wrapper when the user is not providing their own event loop.

use mio::Interest;

use crate::msgs::response::UnparsedResponse;
use std::io;

use super::nonblocking::{EventLoop, NonblockingConnection, PollStatus, WriteHandle};
use super::{MioStream, retry_eintr};

/// An IO stream to Arti, along with any supporting logic necessary to check it for readiness.
///
/// Internally, this uses `mio` along with a [`NonblockingConnection`] to check for events.
///
/// To use this type, mark the stream as nonblocking
/// with e.g. [TcpStream::set_nonblocking](std::net::TcpStream::set_nonblocking),
/// convert it into a [`mio::event::Source`],
/// and pass it to [`BlockingConnection::new()`]
///
/// At this point, you can read and write messages via nonblocking IO.
///
/// The [`BlockingConnection::writer()`] method will return a handle that you can use from any thread
/// that you can use to queue an outbound message.
///
/// No messages are actually sent or received unless
/// some thread is calling [`BlockingConnection::interact()`].
///
/// ## Concurrency and interior mutability
///
/// A `BlockingConnection` has (limited) interior mutability.
///
/// Only a single call to `interact` can be made at the same time.
/// So only one thread can be waiting for responses, and
/// the caller of `interact` must demultiplex responses as necessary.
///
/// But, one or more [`WriteHandle`]s can be created,
/// and these are `'static + Send + Sync`.
/// Using `WriteHandle`, multiple threads can enqueue requests,
/// with [`send_valid`](WriteHandle::send_valid), concurrently.
///
/// (All these restrictions imposed on the caller are enforced by the Rust type system.)
#[derive(Debug)]
pub(crate) struct BlockingConnection {
    /// The poll object.
    ///
    /// (This typically corresponds to a kqueue or epoll handle.)
    ///
    /// ## IO Safety
    ///
    /// This object (semantically) contains references to the `fd`s or `SOCKETS`
    /// of any inserted [`mio::event::Source`].  Therefore it must not outlive those sources.
    /// Further, according to `mio`'s documentation, every Source must be deregistered
    /// before it can be dropped.
    ///
    /// We ensure these properties are obeyed as follows:
    ///  - We hold the stream via `stream`, the NonblockingConnection member of this struct.
    ///    We do not let anybody outside this module have the stream or the `Poll`.
    ///  - We declare a Drop implementation that deregisters the stream.
    ///    This method ensures that the stream is dropped before it is closed.
    poll: mio::Poll,

    /// A small buffer to receive IO readiness events.
    events: mio::Events,

    /// The underlying stream.
    ///
    /// Invariant: `stream.stream` is a [`MioStream`], so [`Stream::as_mio_stream`] will return
    /// Some when we call it.
    ///
    /// This is None only if we have called `into_nonblocking()` or `drop()`.
    /// We store this in an Option so that we can move it out of this object.
    stream: Option<NonblockingConnection>,
}

/// A `mio` token corresponding to the Waker we use to tell the interactor about new writes.
const WAKE_TOKEN: mio::Token = mio::Token(0);

/// A `mio` token corresponding to the Stream connecting to the RPC
const STREAM_TOKEN: mio::Token = mio::Token(1);

/// Wrapper around [`mio::Waker`] on which we implement [`EventLoop`].
///
/// We don't do so on `mio::Waker` directly
/// since other implementations of `EventLoop` on `mio::Waker`
/// are possible.
struct MioWaker(mio::Waker);

impl BlockingConnection {
    /// Create a new BlockingConnection.
    ///
    /// The `stream` will be set to use nonblocking IO;
    /// on Unix this will affect the behaviour of other `dup`s of the same fd!
    pub(crate) fn new(stream: Box<dyn MioStream>) -> io::Result<Self> {
        let poll = mio::Poll::new()?;
        let waker = mio::Waker::new(poll.registry(), WAKE_TOKEN)?;

        let stream = NonblockingConnection::new(Box::new(MioWaker(waker)), stream);

        let mut cio = Self {
            poll,
            events: mio::Events::with_capacity(4),
            stream: Some(stream),
        };

        // We register the stream here, since we want to use it exclusively with `reregister`
        // later on.  We do not deregister the stream until `Drop::drop` is called.
        cio.poll.registry().register(
            cio.stream
                .as_mut()
                .expect("Logic error: stream not present")
                .as_mio_source()
                .expect("logic error: not a mio stream."),
            STREAM_TOKEN,
            Interest::READABLE,
        )?;

        Ok(cio)
    }

    /// Return a new [`WriteHandle`] that can be used to queue messages to be sent via this stream.
    pub(crate) fn writer(&self) -> WriteHandle {
        self.stream
            .as_ref()
            .expect("logic error: stream not present")
            .writer()
    }

    /// Interact with the peer until some response is received.
    ///
    /// Sends all requests given to [`WriteHandle::send_valid`]
    /// (including calls to `send_valid` made while `interact` is running)
    /// while looking for a response from the server.
    /// Returns when the first response is received.
    ///
    ///
    /// Returns an error if an IO condition has failed.
    /// Returns None if the other side has closed the stream.
    /// Otherwise, returns an unparsed message from the RPC server.
    ///
    /// Unless some thread is calling this method, nobody will actually be reading or writing from
    /// the [`BlockingConnection`], and so nobody's requests will be sent or answered.
    pub(crate) fn interact(&mut self) -> io::Result<Option<UnparsedResponse>> {
        // Should we try to read and write? Start out by assuming "yes".

        loop {
            let stream = self
                .stream
                .as_mut()
                .expect("logic error: stream not present!");

            // Try interacting with the underlying stream.
            match stream.interact_once()? {
                PollStatus::Closed => return Ok(None),
                PollStatus::Msg(msg) => return Ok(Some(msg)),
                PollStatus::WouldBlock => {}
            };

            // We're blocking on reading and possibly writing.  Register our interest,
            // so that we get woken as appropriate.
            //
            // TOCTOU note: If `want_write` is true, it will not become
            // false until the next time we call stream.interact_once().
            //
            // If `wantio.want_write()` is false, Whenever it becomes true,
            // `MioWaker` will be invoked.  That will cause the
            // self.poll.poll() to return, and the loop to repeat.
            let want_write = stream.wants_to_write();
            let interests = if want_write {
                Interest::READABLE | Interest::WRITABLE
            } else {
                Interest::READABLE
            };
            self.poll.registry().reregister(
                stream
                    .as_mio_source()
                    .expect("logic error: not a mio stream!"),
                STREAM_TOKEN,
                interests,
            )?;

            // Poll until the socket is ready to read or write,
            // _or_ until somebody invokes the EventLoop because they have queued more to write.
            let () = retry_eintr(|| self.poll.poll(&mut self.events, None))?;

            // Now that we've been woken, see which events we've been woken with,
            // and adjust our plans accordingly on the next time through the loop.
            self.events.clear();
        }
    }

    /// Downgrade this stream into a [`NonblockingConnection`]
    /// for use within an [`RpcPoll`](crate::RpcPoll).
    pub(crate) fn into_nonblocking(mut self) -> NonblockingConnection {
        let mut nb_conn = self
            .deregister_and_take_nb_conn()
            .expect("logic error: stream not present!");
        nb_conn.downgrade_source();
        nb_conn
    }

    /// Implementation helper for Drop and into_nonblocking:
    ///
    /// Deregisters the NonblockingConnection with the mio Registry, removes it from this object,
    /// and returns it.
    ///
    /// After this method is called, this object may no longer be used.
    fn deregister_and_take_nb_conn(&mut self) -> Option<NonblockingConnection> {
        // IO SAFETY: See "IO Safety" note in documentation for BlockingConnection.
        let mut stream = self.stream.take()?;
        let s: &mut _ = stream
            .as_mio_source()
            .expect("Logic error: Stream was not a MIO stream.");
        self.poll
            .registry()
            .deregister(s)
            .expect("Deregister operation failed");
        Some(stream)
    }
}

impl Drop for BlockingConnection {
    fn drop(&mut self) {
        // IO SAFETY: See "IO Safety" note in documentation for BlockingConnection.
        let _ = self.deregister_and_take_nb_conn();
    }
}

impl EventLoop for MioWaker {
    fn start_writing(&mut self) -> io::Result<()> {
        mio::Waker::wake(&self.0)
    }
    fn stop_writing(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// TODO: It would be good to have additional tests for this code.
// It's exercised by all tests for `conn` that don't provide their own event loop,
// but there could definitely be more things to look at.
