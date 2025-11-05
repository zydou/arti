//! An [`AsyncWrite`] rate limiter which receives rate limit changes from a [`FusedStream`].

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::AsyncWrite;
use futures::io::Error;
use futures::stream::FusedStream;
use tor_rtcompat::SleepProvider;

use super::writer::{RateLimitedWriter, RateLimitedWriterConfig};

/// A rate-limited async [writer](AsyncWrite).
///
/// This wraps a [`RateLimitedWriter`] and watches a stream for configuration changes (such as rate
/// limit changes).
#[derive(educe::Educe)]
#[educe(Debug)]
#[pin_project::pin_project]
pub(crate) struct DynamicRateLimitedWriter<W: AsyncWrite, S, P: SleepProvider> {
    /// The rate-limited writer.
    #[pin]
    writer: RateLimitedWriter<W, P>,
    /// A stream that provides configuration updates, including rate limit updates.
    #[educe(Debug(ignore))]
    #[pin]
    updates: S,
}

impl<W, S, P> DynamicRateLimitedWriter<W, S, P>
where
    W: AsyncWrite,
    P: SleepProvider,
{
    /// Create a new [`DynamicRateLimitedWriter`].
    ///
    /// This wraps the `writer` and watches for configuration changes from the `updates` stream.
    pub(crate) fn new(writer: RateLimitedWriter<W, P>, updates: S) -> Self {
        Self { writer, updates }
    }

    /// Access the inner [`AsyncWrite`] writer of the [`RateLimitedWriter`].
    pub(crate) fn inner(&self) -> &W {
        self.writer.inner()
    }
}

impl<W, S, P> AsyncWrite for DynamicRateLimitedWriter<W, S, P>
where
    W: AsyncWrite,
    S: FusedStream<Item = RateLimitedWriterConfig>,
    P: SleepProvider,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let mut self_ = self.as_mut().project();

        // Try getting any update to the rate limit and burst.
        //
        // We loop until we receive `Ready(None)` or `Pending`. The former indicates that we
        // shouldn't receive any more updates. The latter indicates that there aren't currently more
        // to read, and that we've registered the waker with the stream so that we'll wake when the
        // rate limit is later updated.
        //
        // Since `S` is a `FusedStream`, it's fine to call `poll_next()` even if `Ready(None)` was
        // returned in the past.
        let mut iters = 0;
        while let Poll::Ready(Some(config)) = self_.updates.as_mut().poll_next(cx) {
            // update the writer's configuration
            let now = self_.writer.sleep_provider().now();
            self_.writer.adjust(now, &config);

            // It's possible that `DynamicRateLimitedWriter` was constructed with a stream where an
            // infinite number of items will be immediately ready, for example with
            // `futures::stream::repeat()`. We escape the possible infinite loop by returning an
            // error.
            iters += 1;
            if iters > 100_000 {
                const MSG: &str =
                    "possible infinite loop in `DynamicRateLimitedWriter::poll_write`";
                tracing::debug!(MSG);
                return Poll::Ready(Err(Error::other(MSG)));
            }
        }

        // Try writing the bytes. This also registers the waker with the `RateLimitedWriter`.
        self_.writer.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().writer.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().writer.poll_close(cx)
    }
}

/// A module to make it easier to implement tokio traits without putting `cfg()` conditionals
/// everywhere.
#[cfg(feature = "tokio")]
mod tokio_impl {
    use super::*;

    use tokio_crate::io::AsyncWrite as TokioAsyncWrite;
    use tokio_util::compat::FuturesAsyncWriteCompatExt;

    use std::io::Result as IoResult;

    impl<W, S, P> TokioAsyncWrite for DynamicRateLimitedWriter<W, S, P>
    where
        W: AsyncWrite,
        S: FusedStream<Item = RateLimitedWriterConfig>,
        P: SleepProvider,
    {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<IoResult<usize>> {
            TokioAsyncWrite::poll_write(Pin::new(&mut self.compat_write()), cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
            TokioAsyncWrite::poll_flush(Pin::new(&mut self.compat_write()), cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
            TokioAsyncWrite::poll_shutdown(Pin::new(&mut self.compat_write()), cx)
        }
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use super::*;

    use std::num::NonZero;
    use std::time::Duration;

    use futures::{AsyncReadExt, AsyncWriteExt, FutureExt, SinkExt};
    use tor_rtcompat::SpawnExt;

    #[cfg(feature = "tokio")]
    use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

    /// This test ensures that a [`DynamicRateLimitedWriter`] writes the expected number of bytes,
    /// as a background task alternates the rate limit between on/off once every second.
    #[cfg(feature = "tokio")]
    #[test]
    fn alternating_on_off() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            // drive time forward from 0 to 8_000 ms in 1 ms intervals
            let rt_clone = rt.clone();
            rt.spawn(async move {
                for _ in 0..8_000 {
                    rt_clone.progress_until_stalled().await;
                    rt_clone.advance_by(Duration::from_millis(1)).await;
                }
            })
            .unwrap();

            // start with a rate limiter that doesn't allow any bytes
            let config = RateLimitedWriterConfig {
                rate: 0,
                burst: 0,
                // wake up the writer each time the rate limiter allows 10 bytes to be sent
                wake_when_bytes_available: NonZero::new(10).unwrap(),
            };

            // there are some other crates which allow you to make a data "pipe" without tokio, but
            // I don't think it's worth bringing in a new dev-dependency for this
            let (writer, reader) = tokio_crate::io::duplex(/* max_buf_size= */ 1000);
            let writer = writer.compat_write();
            let mut reader = reader.compat();

            let writer = RateLimitedWriter::new(writer, &config, rt.clone());

            // how we send rate updates to the rate-limited writer
            let (mut rate_tx, rate_rx) = futures::channel::mpsc::unbounded();

            // our rate-limited writer which can receive rate limit changes
            let mut writer = DynamicRateLimitedWriter::new(writer, rate_rx);

            /// Duration between updates. A prime number is used so that smaller intervals don't
            /// fall on this interval, which can causes issues with `MockRuntime::test_with_various`
            /// since the test becomes dependent on the order that tasks are woken.
            const UPDATE_INTERVAL: Duration = Duration::from_millis(841);

            // a background task which sends alternating on/off rate limits every 841 ms
            let rt_clone = rt.clone();
            rt.spawn(async move {
                for rate in [100, 0, 200, 0, 400, 0] {
                    rt_clone.sleep(UPDATE_INTERVAL).await;

                    // update the rate/burst
                    let mut config = config.clone();
                    config.rate = rate;
                    config.burst = rate;

                    // we expect the send() to succeed immediately
                    rate_tx.send(config).now_or_never().unwrap().unwrap();
                }
            })
            .unwrap();

            // a background task which writes as much as possible
            rt.spawn(async move {
                // write until the receiving end goes away
                while writer.write(&[0; 100]).await.is_ok() {}
            })
            .unwrap();

            // helper to make the `assert_eq` a single line
            let res_unwrap = Result::unwrap;

            let mut buf = vec![0; 1000];
            let buf = &mut buf;

            // sleep for 1 ms so that our upcoming sleeps end 1 ms after the rate limit changes
            rt.sleep(Duration::from_millis(1)).await;

            // Rate is 0, so no bytes expected.
            rt.sleep(UPDATE_INTERVAL).await;
            assert_eq!(None, reader.read(buf).now_or_never().map(res_unwrap));

            // Rate is 100 bytes/s, so 841/(1000/100) = 84 bytes expected.
            // Woken every `wake_when_bytes_available` = 10 bytes, so 80 bytes expected.
            rt.sleep(UPDATE_INTERVAL).await;
            assert_eq!(Some(80), reader.read(buf).now_or_never().map(res_unwrap));

            // Rate is 0, so no bytes expected.
            rt.sleep(UPDATE_INTERVAL).await;
            assert_eq!(None, reader.read(buf).now_or_never().map(res_unwrap));

            // Rate is 200 bytes/s, so 841/(1000/200) = 168 bytes expected.
            // Woken every `wake_when_bytes_available` = 10 bytes, so 160 bytes expected.
            rt.sleep(UPDATE_INTERVAL).await;
            assert_eq!(Some(160), reader.read(buf).now_or_never().map(res_unwrap));

            // Rate is 0, so no bytes expected.
            rt.sleep(UPDATE_INTERVAL).await;
            assert_eq!(None, reader.read(buf).now_or_never().map(res_unwrap));

            // Rate is 400 bytes/s, so 841/(1000/400) = 336 bytes expected.
            // Woken every `wake_when_bytes_available` = 10 bytes, so 330 bytes expected.
            rt.sleep(UPDATE_INTERVAL).await;
            assert_eq!(Some(330), reader.read(buf).now_or_never().map(res_unwrap));

            // Rate is 0, so no bytes expected.
            rt.sleep(UPDATE_INTERVAL).await;
            assert_eq!(None, reader.read(buf).now_or_never().map(res_unwrap));
        });
    }
}
