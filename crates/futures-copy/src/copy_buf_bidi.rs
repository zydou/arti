//! Functionality to copy bidirectionally between two streams
//! that implement `AsyncBufRead` and`AsyncWrite`.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use futures::{AsyncBufRead, AsyncWrite};
use pin_project::pin_project;

use crate::{
    arc_io_result::{ArcIoResult, wrap_error},
    copy_buf::poll_copy_r_to_w,
    eof::EofStrategy,
    fuse_buf_reader::FuseBufReader,
};

/// Return a future to copies bytes from `stream_a` to `stream_b`,
/// and from `stream_b` to `stream_a`.
///
/// The future makes sure that
/// if a stream pauses (returns Pending),
/// all as-yet-received bytes are still flushed to the other stream.
///
/// If an EOF is read from `stream_a`,
/// the future uses `on_a_eof` to report the EOF to `stream_b`.
/// Similarly, if an EOF is read from  `stream_b`,
/// the future uses `on_b_eof` to report the EOF to `stream_a`.
///
/// The future will continue running until either an error has occurred
/// (in which case it yields an error),
/// or until both streams have returned an EOF as readers
/// and have both been flushed as writers
/// (in which case it yields a tuple of the number of bytes copied from a to b,
/// and the number of bytes copied from b to a.)
///
/// # Limitations
///
/// See the crate-level documentation for
/// [discussion of this function's limitations](crate#Limitations).
pub fn copy_buf_bidirectional<A, B, AE, BE>(
    stream_a: A,
    stream_b: B,
    on_a_eof: AE,
    on_b_eof: BE,
) -> CopyBufBidirectional<A, B, AE, BE>
where
    A: AsyncBufRead + AsyncWrite,
    B: AsyncBufRead + AsyncWrite,
    AE: EofStrategy<B>,
    BE: EofStrategy<A>,
{
    CopyBufBidirectional {
        stream_a: FuseBufReader::new(stream_a),
        stream_b: FuseBufReader::new(stream_b),
        on_a_eof,
        on_b_eof,
        copied_a_to_b: 0,
        copied_b_to_a: 0,
        a_to_b_status: DirectionStatus::Copying,
        b_to_a_status: DirectionStatus::Copying,
    }
}

/// A future returned by [`copy_buf_bidirectional`].
//
// Note to the reader: You might think it's a good idea to have two separate CopyBuf futures here.
// That won't work, though, since each one would need to own both `stream_a` and `stream_b`.
// We could use `split` to share the streams, but that would introduce needless locking overhead.
//
// Instead, we implement the shared functionality via poll_copy_r_to_w.
#[derive(Debug)]
#[pin_project]
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct CopyBufBidirectional<A, B, AE, BE> {
    /// The first stream.
    #[pin]
    stream_a: FuseBufReader<A>,

    /// The second stream.
    #[pin]
    stream_b: FuseBufReader<B>,

    /// An [`EofStrategy`] to use when `stream_a` reaches EOF.
    #[pin]
    on_a_eof: AE,

    /// An [`EofStrategy`] to use when `stream_b` reaches EOF.
    #[pin]
    on_b_eof: BE,

    /// The number of bytes from `a` written onto `b` so far.
    copied_a_to_b: u64,
    /// The number of bytes from `b` written onto `a` so far.
    copied_b_to_a: u64,

    /// The current status of copying from `a` to `b`.
    a_to_b_status: DirectionStatus,

    /// The current status of copying from `b` to `a`.
    b_to_a_status: DirectionStatus,
}

impl<A, B, AE, BE> CopyBufBidirectional<A, B, AE, BE> {
    /// Consume this CopyBufBirectional future, and return the underlying streams.
    pub fn into_inner(self) -> (A, B) {
        (self.stream_a.into_inner(), self.stream_b.into_inner())
    }
}

impl<A, B, AE, BE> Future for CopyBufBidirectional<A, B, AE, BE>
where
    A: AsyncBufRead + AsyncWrite,
    B: AsyncBufRead + AsyncWrite,
    AE: EofStrategy<B>,
    BE: EofStrategy<A>,
{
    type Output = io::Result<(u64, u64)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        use DirectionStatus::*;

        let mut this = self.project();

        if *this.a_to_b_status != DirectionStatus::Done {
            let _ignore_completion = one_direction(
                cx,
                this.stream_a.as_mut(),
                this.stream_b.as_mut(),
                this.on_a_eof,
                this.copied_a_to_b,
                this.a_to_b_status,
            )
            .map_err(|e| wrap_error(&e))?;
        }

        if *this.b_to_a_status != DirectionStatus::Done {
            let _ignore_completion = one_direction(
                cx,
                this.stream_b.as_mut(),
                this.stream_a.as_mut(),
                this.on_b_eof,
                this.copied_b_to_a,
                this.b_to_a_status,
            )
            .map_err(|e| wrap_error(&e))?;
        }

        if (*this.a_to_b_status, *this.b_to_a_status) == (Done, Done) {
            Poll::Ready(Ok((*this.copied_a_to_b, *this.copied_b_to_a)))
        } else {
            Poll::Pending
        }
    }
}

/// A possible status for copying in a single direction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DirectionStatus {
    /// Copying data: we have not yet reached an EOF.
    Copying,

    /// Reached EOF: using an [`EofStrategy`] to propagate the EOF to the writer.
    SendingEof,

    /// EOF sent: Nothing more to do.
    Done,
}

/// Try to make progress copying data in a single data, and propagating the EOF.
fn one_direction<A, B, AE>(
    cx: &mut Context<'_>,
    r: Pin<&mut FuseBufReader<A>>,
    mut w: Pin<&mut FuseBufReader<B>>,
    eof_strategy: Pin<&mut AE>,
    n_copied: &mut u64,
    status: &mut DirectionStatus,
) -> Poll<ArcIoResult<()>>
where
    A: AsyncBufRead,
    B: AsyncWrite,
    AE: EofStrategy<B>,
{
    use DirectionStatus::*;

    if *status == Copying {
        let () = ready!(poll_copy_r_to_w(cx, r, w.as_mut(), n_copied, false))?;
        *status = SendingEof;
    }

    if *status == SendingEof {
        let () = ready!(eof_strategy.poll_send_eof(cx, w.get_pin_mut()))?;
        *status = Done;
    }

    assert_eq!(*status, Done);
    Poll::Ready(Ok(()))
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

    use super::*;
    use crate::{eof, test::RWPair};

    use futures::{
        AsyncBufReadExt,
        io::{BufReader, BufWriter, Cursor},
    };
    use tor_rtcompat::SpawnExt as _;
    use tor_rtmock::{MockRuntime, io::stream_pair};

    /// Return a stream implemented with a pair of Vec-backed cursors.
    #[allow(clippy::type_complexity)]
    fn cursor_stream(init_data: &[u8]) -> BufReader<RWPair<Cursor<Vec<u8>>, Cursor<Vec<u8>>>> {
        BufReader::new(RWPair(
            Cursor::new(init_data.to_vec()),
            Cursor::new(Vec::new()),
        ))
    }

    async fn test_transfer_cursor(data_1: &[u8], data_2: &[u8]) {
        let mut s1 = cursor_stream(data_1);
        let mut s2 = cursor_stream(data_2);

        let (t1, t2) = copy_buf_bidirectional(&mut s1, &mut s2, eof::Close, eof::Close)
            .await
            .unwrap();
        assert_eq!(t1, data_1.len() as u64);
        assert_eq!(t2, data_2.len() as u64);
        let out1 = s1.into_inner().1.into_inner();
        let out2 = s2.into_inner().1.into_inner();
        assert_eq!(&out1[..], data_2);
        assert_eq!(&out2[..], data_1);
    }

    async fn test_transfer_streams(rt: &MockRuntime, data_1: &[u8], data_2: &[u8]) {
        let mut s1 = cursor_stream(data_1);
        let (s2, s3) = stream_pair();
        let mut s4 = cursor_stream(data_2);

        let h1 = rt
            .spawn_with_handle(async move {
                let r = copy_buf_bidirectional(&mut s1, BufReader::new(s2), eof::Close, eof::Close)
                    .await;
                (r, s1.into_inner().1.into_inner())
            })
            .unwrap();
        let h2 = rt
            .spawn_with_handle(async move {
                let r = copy_buf_bidirectional(BufReader::new(s3), &mut s4, eof::Close, eof::Close)
                    .await;
                (r, s4.into_inner().1.into_inner())
            })
            .unwrap();
        let (r1, buf1) = h1.await;
        let (r2, buf2) = h2.await;

        assert_eq!(r1.unwrap(), (data_1.len() as u64, data_2.len() as u64));
        assert_eq!(r2.unwrap(), (data_1.len() as u64, data_2.len() as u64));
        assert_eq!(&buf1, data_2);
        assert_eq!(&buf2, data_1);
    }

    fn test_transfer(data_1: &[u8], data_2: &[u8]) {
        MockRuntime::test_with_various(async |rt| {
            test_transfer_cursor(data_1, data_2).await;
            test_transfer_streams(&rt, data_1, data_2).await;
        });
    }

    fn big(x: u8) -> Vec<u8> {
        (1..=x).cycle().take(1_234_567).collect()
    }

    #[test]
    fn transfer_empty() {
        test_transfer(&[], &[]);
    }

    #[test]
    fn transfer_empty_small() {
        test_transfer(&[], b"hello world");
    }

    #[test]
    fn transfer_small() {
        test_transfer(b"hola mundo", b"hello world");
    }

    #[test]
    fn transfer_huge() {
        let big1 = big(79);
        let big2 = big(81);
        test_transfer(&big1, &big2);
    }

    #[test]
    fn interactive_protocol() {
        use futures::io::AsyncWriteExt as _;
        // Test our flush behavior by relaying traffic between a pair of communicators that
        // don't say anything until they get a message.

        MockRuntime::test_with_various(async |rt| {
            let (s1, s2) = stream_pair();
            let (s3, s4) = stream_pair();

            // Using BufWriter here means that unless we propagate the flush correctly,
            // flushing won't happen soon enough to cause a reply.
            let mut s1 = BufReader::new(s1);
            let s2 = BufReader::new(BufWriter::with_capacity(1024, s2));
            let s3 = BufReader::new(BufWriter::with_capacity(1024, s3));
            let mut s4 = BufReader::new(s4);

            // That's a lot of streams!  Here's how they all connect:
            //
            // Task 1 <--> s1  <-Rt-> s2 <-> Task 2 <--> s3 <-Rt-> s4 <--> Task 3
            //
            // In other words, s1 and s2 are automatically connected under the hood by
            // the MockRuntime, as are s3 and s4.  Task 1 reads and writes from s1.
            // Task 2 tests copy_buf_bidirectional by relaying between s2 and s3.
            // And Task 3 reads and writes to s4.
            //
            // Thus task 1 and task 3 can only communicate with one another if
            // task 2 (and copy_buf_bidirectional) do their job.

            // Task 1:
            // Write a number starting with 1, then read numbers and write back 1 more.
            // Continue until you read a number >= 100.
            let h1 = rt
                .spawn_with_handle(async move {
                    let mut buf = String::new();
                    let mut num: u32 = 1;

                    loop {
                        s1.write_all(format!("{num}\n").as_bytes()).await?;
                        s1.flush().await?;

                        let written = num;

                        let n_bytes_read = s1.read_line(&mut buf).await?;
                        if n_bytes_read == 0 {
                            break;
                        }
                        num = buf.trim_ascii().parse().unwrap();
                        buf.clear();
                        assert_eq!(num, written + 1);

                        if num >= 100 {
                            break;
                        }
                        num += 1;
                    }

                    s1.close().await?;

                    Ok::<u32, io::Error>(num)
                })
                .unwrap();

            // Task 2: Use copy_buf_bidirectional to relay traffic.
            let h2 = rt
                .spawn_with_handle(copy_buf_bidirectional(s2, s3, eof::Close, eof::Close))
                .unwrap();

            // Task 3: Forever: read a number on a line, and write back 1 more.
            let h3 = rt
                .spawn_with_handle(async move {
                    let mut buf = String::new();
                    let mut last_written = None;

                    loop {
                        let n_bytes_read = s4.read_line(&mut buf).await?;
                        if n_bytes_read == 0 {
                            break;
                        }
                        let num: u32 = buf.trim_ascii().parse().unwrap();
                        buf.clear();
                        if let Some(last) = last_written {
                            assert_eq!(num, last + 1);
                        }

                        let num = num + 1;
                        s4.write_all(format!("{num}\n").as_bytes()).await?;
                        s4.flush().await?;
                        last_written = Some(num);
                    }
                    Ok::<_, io::Error>(())
                })
                .unwrap();

            let outcome1 = h1.await;
            let outcome2 = h2.await;
            let outcome3 = h3.await;

            assert_eq!(outcome1.unwrap(), 100);
            let (_, _) = outcome2.unwrap();
            let () = outcome3.unwrap();
        });
    }
}
