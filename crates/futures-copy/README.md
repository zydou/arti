# futures-copy

Copy data from an `AsyncRead` to an `AsyncWrite`,
or between a pair of `AsyncRead + AsyncWrite` streams.

(If you're using tokio only, you _probably_ don't need this;
you can probably use one of the `tokio::io::copy` functions instead.)

## Differences from other `copy`s

This crate works with the `AsyncRead` and `AsyncWrite` traits 
from the [`futures`] crate.

Unlike `futures::io::copy` and _some_ of the `copy` methods in `tokio`,
the code in this crate flushes the writer
whenever the reader returns `Pending`,
and so is suitable for use in more cases:
this behavior ensures that data does not wait forever on writers with internal buffering.

`futures-copy` ensures that the writer is flushed
whenever the reader has returned `Pending`.

`futures-copy` doesn't require reader and writer types to be `Unpin`,
and allows readers and writers to be given either by value or by
mutable reference.

`futures-copy` lets you control the way in which an EOF received
on one stream is copied to the other (e.g., via [`AsyncWriteExt::close`],
[`TcpStream::shutdown`], or some other means.)

## Limitations

The [`io::Error`] that's returned by the functions in `futures-copy`
is not _exactly_ the same `io::Error` that caused the copy operation to fail.
Instead, it wraps the source error in an [`Arc`],
We do this because, in Rust,
[`std::io::Error`] doesn't implement [`Clone`].

Although `futures-copy` returns the amount of data transferred on success,
it does not report this information on error.

If an error occurs while reading data,
`futures_copy` tries to ensure that the writer is flushed
before it returns that error.
This may delay receipt of the error message.

## Example

```
# use futures::io::{AsyncRead, AsyncWrite};
# use std::io;
use futures_copy::{copy_bidirectional, eof};
# async fn x(stream_a: impl AsyncRead+AsyncWrite,
#            stream_b: impl AsyncRead+AsyncWrite) -> io::Result<()> {

// Copy data between stream_a and stream_b, in both directions,
// flushing as appropriate.
// As soon as we reach EOF on either stream, close the other.
copy_bidirectional(
   stream_a, stream_b,
   eof::Close, eof::Close
).await?;
# Ok(())
# }
```

## Acknowledgments

The API is loosely based on the API of `tokio`'s `io::copy*` functions,
(`copy_buf`, `copy`, and `copy_bidirectional`),
ported for use outside `tokio`.
The implementation strategy is loosely based on the implementation strategy of `futures`'s
`io::copy` methods (`copy` and `copy_buf`).
It should be mostly usable as a drop-in replacement for those functions.


[`AsyncWriteExt::close`]: futures::io::AsyncWriteExt::close
[`TcpStream::shutdown`]: std::net::TcpStream::shutdown
[`io::Error`]: std::io::Error
[`Arc`]: std::sync::Arc

License: MIT OR Apache-2.0
