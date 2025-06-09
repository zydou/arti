//! An [`AsyncWrite`] rate limiter.

use std::future::Future;
use std::num::NonZero;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::io::Error;
use futures::AsyncWrite;
use sync_wrapper::SyncFuture;
use tor_rtcompat::SleepProvider;

use super::bucket::{NeverEnoughTokensError, TokenBucket, TokenBucketConfig};

/// A rate-limited async [writer](AsyncWrite).
///
/// This can be used as a wrapper around an existing [`AsyncWrite`] writer.
#[derive(educe::Educe)]
#[educe(Debug)]
#[pin_project::pin_project]
pub(crate) struct RateLimitedWriter<W: AsyncWrite, P: SleepProvider> {
    /// The token bucket.
    bucket: TokenBucket<Instant>,
    /// The sleep provider, for getting the current time and creating new sleep futures.
    ///
    /// While we use [`Instant`] for the time, we should always get the time from this
    /// [`SleepProvider`].
    /// For example, use [`SleepProvider::now()`], not [`Instant::now()`].
    #[educe(Debug(ignore))]
    sleep_provider: P,
    /// See [`RateLimitedWriterConfig::wake_when_bytes_available`].
    wake_when_bytes_available: NonZero<u64>,
    /// The inner writer.
    #[educe(Debug(ignore))]
    #[pin]
    inner: W,
    /// We need to store the sleep future if [`AsyncWrite::poll_write()`] blocks.
    #[educe(Debug(ignore))]
    #[pin]
    sleep_fut: Option<SyncFuture<P::SleepFuture>>,
}

impl<W, P> RateLimitedWriter<W, P>
where
    W: AsyncWrite,
    P: SleepProvider,
{
    /// Create a new [`RateLimitedWriter`].
    // We take the rate and bucket max directly rather than a `TokenBucket` to ensure that the token
    // bucket only ever uses times from `sleep_provider`.
    pub(crate) fn new(writer: W, config: &RateLimitedWriterConfig, sleep_provider: P) -> Self {
        let bucket_config = TokenBucketConfig {
            rate: config.rate,
            bucket_max: config.burst,
        };
        Self::from_token_bucket(
            writer,
            TokenBucket::new(&bucket_config, sleep_provider.now()),
            config.wake_when_bytes_available,
            sleep_provider,
        )
    }

    /// Create a new [`RateLimitedWriter`] from a [`TokenBucket`].
    ///
    /// The token bucket must have only been used with times created by `sleep_provider`.
    #[cfg_attr(test, visibility::make(pub(super)))]
    fn from_token_bucket(
        writer: W,
        bucket: TokenBucket<Instant>,
        wake_when_bytes_available: NonZero<u64>,
        sleep_provider: P,
    ) -> Self {
        Self {
            bucket,
            sleep_provider,
            wake_when_bytes_available,
            inner: writer,
            sleep_fut: None,
        }
    }

    /// Access the inner [`AsyncWrite`] writer.
    pub(crate) fn inner(&self) -> &W {
        &self.inner
    }

    /// Adjust the refill rate and burst.
    ///
    /// A rate and/or burst of 0 is allowed.
    pub(crate) fn adjust(
        self: &mut Pin<&mut Self>,
        now: Instant,
        config: &RateLimitedWriterConfig,
    ) {
        let self_ = self.as_mut().project();

        // destructuring allows us to make sure we aren't forgetting to handle any fields
        let RateLimitedWriterConfig {
            rate,
            burst,
            wake_when_bytes_available,
        } = *config;

        let bucket_config = TokenBucketConfig {
            rate,
            bucket_max: burst,
        };

        self_.bucket.adjust(now, &bucket_config);
        *self_.wake_when_bytes_available = wake_when_bytes_available;
    }

    /// The sleep provider.
    ///
    /// We don't want this to be generally accessible, only to other token bucket-related modules
    /// like [`DynamicRateLimitedWriter`](super::dynamic_writer::DynamicRateLimitedWriter).
    pub(super) fn sleep_provider(&self) -> &P {
        &self.sleep_provider
    }

    /// Configure this writer to sleep for `duration`.
    ///
    /// A `duration` of `None` is interpreted as "forever".
    ///
    /// It's considered a bug if asked to sleep for `Duration::ZERO` time.
    fn register_sleep(
        sleep_fut: &mut Pin<&mut Option<SyncFuture<P::SleepFuture>>>,
        sleep_provider: &mut P,
        cx: &mut Context<'_>,
        duration: Option<Duration>,
    ) -> Poll<()> {
        match duration {
            None => {
                sleep_fut.as_mut().set(None);
                Poll::Pending
            }
            Some(duration) => {
                debug_assert_ne!(duration, Duration::ZERO, "asked to sleep for 0 time");
                sleep_fut
                    .as_mut()
                    .set(Some(SyncFuture::new(sleep_provider.sleep(duration))));
                sleep_fut
                    .as_mut()
                    .as_pin_mut()
                    .expect("but we just set it to `Some`?!")
                    .poll(cx)
            }
        }
    }
}

impl<W, P> AsyncWrite for RateLimitedWriter<W, P>
where
    W: AsyncWrite,
    P: SleepProvider,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let mut self_ = self.as_mut().project();

        // this should be optimized to a no-op on at least x86-64
        fn to_u64(x: usize) -> u64 {
            x.try_into().expect("failed usize to u64 conversion")
        }

        // for an empty buffer, just defer to the inner writer's impl
        if buf.is_empty() {
            return self_.inner.poll_write(cx, buf);
        }

        let now = self_.sleep_provider.now();

        // refill the bucket and attempt to claim all of the bytes
        self_.bucket.refill(now);
        let claim = self_.bucket.claim(to_u64(buf.len()));

        let mut claim = match claim {
            // claim was successful
            Ok(x) => x,
            // not enough tokens, so let's use a smaller buffer
            Err(e) => {
                let available = e.available_tokens();

                // need to drop the old claim so that we can access the token bucket again
                drop(claim);

                // if no tokens in bucket, we must sleep
                if available == 0 {
                    // number of tokens we'll wait for
                    let wake_at_tokens = to_u64(buf.len());

                    // If the user wants to write X tokens, we don't necessarily want to sleep until
                    // we have room for X tokens. We also don't want to wake every time that a
                    // single byte can be written. We allow the user to configure this threshold
                    // with `RateLimitedWriterConfig::wake_when_bytes_available`.
                    let wake_at_tokens =
                        std::cmp::min(wake_at_tokens, self_.wake_when_bytes_available.get());

                    // max number of tokens the bucket can hold
                    let bucket_max = self_.bucket.max();

                    // how long to sleep for; `None` indicates to sleep forever
                    let sleep_for = if bucket_max == 0 {
                        // bucket can't hold any tokens, so sleep forever
                        None
                    } else {
                        // if the bucket has a max of X tokens, we should never try to wait for >X
                        // tokens
                        let wake_at_tokens = std::cmp::min(wake_at_tokens, bucket_max);

                        // if we asked for 0 tokens, we'd get a time of ~now, which is not what we
                        // want
                        debug_assert!(wake_at_tokens > 0);

                        let wake_at = self_.bucket.tokens_available_at(wake_at_tokens);
                        let sleep_for = wake_at.map(|x| x.saturating_duration_since(now));

                        match sleep_for {
                            Ok(x) => Some(x),
                            Err(NeverEnoughTokensError::ExceedsMaxTokens) => {
                                panic!(
                                    "exceeds max tokens, but we took the max into account above"
                                );
                            }
                            // we aren't refilling, so sleep forever
                            Err(NeverEnoughTokensError::ZeroRate) => None,
                            // too far in the future to be represented, so sleep forever
                            Err(NeverEnoughTokensError::InstantNotRepresentable) => None,
                        }
                    };

                    // configure the sleep future and poll it to register
                    let poll = Self::register_sleep(
                        &mut self_.sleep_fut,
                        self_.sleep_provider,
                        cx,
                        sleep_for,
                    );
                    return match poll {
                        // wait for the sleep to finish
                        Poll::Pending => Poll::Pending,
                        // The sleep is already ready?! A recursive call here isn't great, but
                        // there's not much else we can do here. Hopefully this second `poll_write`
                        // will succeed since we should now have enough tokens.
                        Poll::Ready(()) => self.poll_write(cx, buf),
                    };
                }

                /// Convert a `u64` to `usize`, saturating if size of `usize` is smaller than `u64`.
                // This is a separate function to ensure we don't accidentally try to convert a
                // signed integer into a `usize`, in which case `unwrap_or(MAX)` wouldn't make
                // sense.
                fn to_usize_saturating(x: u64) -> usize {
                    x.try_into().unwrap_or(usize::MAX)
                }

                // There are tokens, so try to write as many as are available.
                let available_usize = to_usize_saturating(available);
                buf = &buf[0..available_usize];
                self_.bucket.claim(to_u64(buf.len())).unwrap_or_else(|_| {
                    panic!(
                        "bucket has {available} tokens available, but can't claim {}?",
                        buf.len(),
                    )
                })
            }
        };

        let rv = self_.inner.poll_write(cx, buf);

        match rv {
            // no bytes were written, so discard the claim
            Poll::Pending | Poll::Ready(Err(_)) => claim.discard(),
            // `x` bytes were written, so only commit those tokens
            Poll::Ready(Ok(x)) => {
                if x <= buf.len() {
                    claim
                        .reduce(to_u64(x))
                        .expect("can't commit fewer tokens?!");
                    claim.commit();
                } else {
                    cfg_if::cfg_if! {
                        if #[cfg(debug_assertions)] {
                            panic!(
                                "Writer is claiming it wrote more bytes {x} than we gave it {}",
                                buf.len(),
                            );
                        } else {
                            // the best we can do is to just claim the original amount
                            claim.commit();
                        }
                    }
                }
            }
        };

        rv
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        // some implementers of `AsyncWrite` (like `Vec`) don't do anything other than flush when
        // closed and will continue to accept bytes even after being closed, so we must continue to
        // apply rate limiting even after being closed
        self.project().inner.poll_close(cx)
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

    impl<W, P> TokioAsyncWrite for RateLimitedWriter<W, P>
    where
        W: AsyncWrite,
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

/// The refill rate and burst for a [`RateLimitedWriter`].
#[derive(Clone, Debug)]
pub(crate) struct RateLimitedWriterConfig {
    /// The refill rate in bytes/second.
    pub(crate) rate: u64,
    /// The "burst" in bytes.
    pub(crate) burst: u64,
    /// When polled, block until at most this many bytes are available.
    ///
    /// Or in other words, wake when we can write this many bytes, even if the provided buffer is
    /// larger.
    ///
    /// For example if a user attempts to write a large buffer, we usually don't want to block until
    /// the entire buffer can be written. We'd prefer several partial writes to a single large
    /// write. So instead of blocking until the entire buffer can be written, we only block until
    /// at most this many bytes are available.
    pub(crate) wake_when_bytes_available: NonZero<u64>,
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use super::*;

    use futures::task::SpawnExt;
    use futures::{AsyncWriteExt, FutureExt};

    #[test]
    fn writer() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let start = rt.now();

            // increases 10 tokens/second (one every 100 ms)
            let config = TokenBucketConfig {
                rate: 10,
                bucket_max: 100,
            };
            let mut tb = TokenBucket::new(&config, start);
            // drain the bucket
            tb.drain(100).unwrap();

            let wake_when_bytes_available = NonZero::new(15).unwrap();

            let mut writer = Vec::new();
            let mut writer = RateLimitedWriter::from_token_bucket(
                &mut writer,
                tb,
                wake_when_bytes_available,
                rt.clone(),
            );

            // drive time forward from 0 to 20_000 ms in 50 ms intervals
            let rt_clone = rt.clone();
            rt.spawn(async move {
                for _ in 0..400 {
                    rt_clone.progress_until_stalled().await;
                    rt_clone.advance_by(Duration::from_millis(50)).await;
                }
            })
            .unwrap();

            // try writing 60 bytes, which sleeps until we can write at least 15 of them
            assert_eq!(15, writer.write(&[0; 60]).await.unwrap());
            assert_eq!(1500, rt.now().duration_since(start).as_millis());

            // wait 2 seconds
            rt.sleep(Duration::from_millis(2000)).await;

            // ensure that we can write immediately, and that we can write
            // 2000 ms / (100 ms/token) = 20 bytes
            assert_eq!(
                Some(20),
                writer.write(&[0; 60]).now_or_never().map(Result::unwrap),
            );
        });
    }

    /// Test that writing to a token bucket which has a rate and/or max of 0 works as expected.
    #[test]
    fn rate_burst_zero() {
        let configs = [
            // non-zero rate, zero max
            TokenBucketConfig {
                rate: 10,
                bucket_max: 0,
            },
            // zero rate, non-zero max
            TokenBucketConfig {
                rate: 0,
                bucket_max: 10,
            },
            // zero rate, zero max
            TokenBucketConfig {
                rate: 0,
                bucket_max: 0,
            },
        ];
        for config in configs {
            tor_rtmock::MockRuntime::test_with_various(|rt| {
                let config = config.clone();
                async move {
                    // an empty token bucket
                    let mut tb = TokenBucket::new(&config, rt.now());
                    tb.drain(tb.max()).unwrap();
                    assert!(tb.is_empty());

                    let wake_when_bytes_available = NonZero::new(2).unwrap();

                    let mut writer = Vec::new();
                    let mut writer = RateLimitedWriter::from_token_bucket(
                        &mut writer,
                        tb,
                        wake_when_bytes_available,
                        rt.clone(),
                    );

                    // drive time forward from 0 to 10_000 ms in 100 ms intervals
                    let rt_clone = rt.clone();
                    rt.spawn(async move {
                        for _ in 0..100 {
                            rt_clone.progress_until_stalled().await;
                            rt_clone.advance_by(Duration::from_millis(100)).await;
                        }
                    })
                    .unwrap();

                    // ensure that a write returns `Pending`
                    assert_eq!(
                        None,
                        writer.write(&[0; 60]).now_or_never().map(Result::unwrap),
                    );

                    // wait 5 seconds
                    rt.sleep(Duration::from_millis(5000)).await;

                    // ensure that a write still returns `Pending`
                    assert_eq!(
                        None,
                        writer.write(&[0; 60]).now_or_never().map(Result::unwrap),
                    );
                }
            });
        }
    }
}
