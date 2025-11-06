#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![allow(renamed_and_removed_lints)] // @@REMOVE_WHEN(ci_arti_stable)
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_time_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::mod_module_files)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
#![allow(clippy::needless_lifetimes)] // See arti#1765
#![allow(mismatched_lifetime_syntaxes)] // temporary workaround for arti#2060
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

mod arc_io_result;
mod copy_buf;
mod copy_buf_bidi;
pub mod eof;
mod fuse_buf_reader;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

pub use copy_buf::{CopyBuf, copy_buf};
pub use copy_buf_bidi::{CopyBufBidirectional, copy_buf_bidirectional};
pub use eof::EofStrategy;

use futures::{AsyncRead, AsyncWrite, io::BufReader};
use pin_project::pin_project;

/// Return a future to copy bytes from `reader` to `writer`.
///
/// See [`copy_buf()`] for full details.
///
/// Unlike `copy_buf`, this function does not require that `reader` implements AsyncBufRead:
/// it wraps `reader` internally in a new `BufReader` with default capacity.
///
/// ## Limitations
///
/// If an error occurs during transmission, buffered data that was read from `reader`
/// but not written to `writer` will be lost.
/// To avoid this, use [`copy_buf()`].
///
/// Similarly, if you drop this future while it is still pending,
/// any buffered data will be lost.
///
/// See the crate-level documentation for further
/// [discussion of this function's limitations](crate#Limitations).
pub fn copy<R, W>(reader: R, writer: W) -> Copy<R, W>
where
    R: AsyncRead,
    W: AsyncWrite,
{
    let reader = BufReader::new(reader);
    Copy(copy_buf(reader, writer))
}

/// Return a future to copies bytes from `stream_a` to `stream_b`,
/// and from `stream_b` to `stream_a`.
///
/// See [`copy_buf_bidirectional()`] for full details.
///
/// Unlike `copy_buf_bidirectional`, this function does not require that either stream implements AsyncBufRead:
/// it wraps them internally in a new `BufReader` with default capacity.
///
/// ## Limitations
///
/// If an error occurs during transmission, data that was read from one stream,
/// but not written to the other, will be lost.
/// To avoid this, use [`copy_buf_bidirectional()`].
///
/// Similarly, if you drop this future while it is still pending,
/// any buffered data will be lost.
///
/// See the crate-level documentation for further
/// [discussion of this function's limitations](crate#Limitations).
pub fn copy_bidirectional<A, B, AE, BE>(
    stream_a: A,
    stream_b: B,
    on_a_eof: AE,
    on_b_eof: BE,
) -> CopyBidirectional<A, B, AE, BE>
where
    A: AsyncRead + AsyncWrite,
    B: AsyncRead + AsyncWrite,
    AE: EofStrategy<B>,
    BE: EofStrategy<A>,
{
    let stream_a = BufReader::new(stream_a);
    let stream_b = BufReader::new(stream_b);
    CopyBidirectional(copy_buf_bidirectional(
        stream_a,
        stream_b,
        eof::BufReaderEofWrapper(on_a_eof),
        eof::BufReaderEofWrapper(on_b_eof),
    ))
}

/// A future returned by [`copy`].
#[derive(Debug)]
#[pin_project]
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct Copy<R, W>(#[pin] CopyBuf<BufReader<R>, W>);

/// A future returned by [`copy_bidirectional`].
#[derive(Debug)]
#[pin_project]
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct CopyBidirectional<A, B, AE, BE>(
    #[pin]
    CopyBufBidirectional<
        BufReader<A>,
        BufReader<B>,
        eof::BufReaderEofWrapper<AE>,
        eof::BufReaderEofWrapper<BE>,
    >,
);

// Note: There is intentionally no `into_inner` implementation for these types,
// since returning the original streams would discard any buffered data.

impl<R, W> Future for Copy<R, W>
where
    R: AsyncRead,
    W: AsyncWrite,
{
    type Output = std::io::Result<u64>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().0.poll(cx)
    }
}

impl<A, B, AE, BE> Future for CopyBidirectional<A, B, AE, BE>
where
    A: AsyncRead + AsyncWrite,
    B: AsyncRead + AsyncWrite,
    AE: EofStrategy<B>,
    BE: EofStrategy<A>,
{
    type Output = std::io::Result<(u64, u64)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().0.poll(cx)
    }
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
    use std::io;

    /// A struct that implements AsyncRead and AsyncWrite, but always returns an error.
    #[derive(Debug, Clone)]
    pub(crate) struct ErrorRW(pub(crate) io::ErrorKind);

    impl AsyncRead for ErrorRW {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::from(self.0)))
        }
    }

    impl AsyncWrite for ErrorRW {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::from(self.0)))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::from(self.0)))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::from(self.0)))
        }
    }

    /// A struct that implements AsyncRead, but never returns any data.
    ///
    /// (This reader is always _pending_.)
    pub(crate) struct PausedRead;

    impl AsyncRead for PausedRead {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }
    }

    /// A read-write pair, stapled into a Read+Write stream.
    #[pin_project]
    pub(crate) struct RWPair<R, W>(#[pin] pub(crate) R, #[pin] pub(crate) W);

    impl<R: AsyncRead, W> AsyncRead for RWPair<R, W> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            self.project().0.poll_read(cx, buf)
        }
    }

    impl<R, W: AsyncWrite> AsyncWrite for RWPair<R, W> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.project().1.poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.project().1.poll_flush(cx)
        }

        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.project().1.poll_close(cx)
        }
    }
}
