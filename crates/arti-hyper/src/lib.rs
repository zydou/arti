//! High-level layer for making http(s) requests the Tor network as a client.
//!
//! Work-in-progress.
//! This is **not suitable for use** right now because it does not support HTTPs.

#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::clone_on_ref_ptr)]
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
#![deny(clippy::missing_panics_doc)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]

use std::future::Future;
use std::io::Error;
use std::pin::Pin;
use std::task::{Context, Poll};

use arti_client::{DataStream, IntoTorAddr, TorClient};
use hyper::client::connect::{Connected, Connection};
use hyper::http::uri::Scheme;
use hyper::http::Uri;
use hyper::service::Service;
use pin_project::pin_project;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tor_rtcompat::Runtime;

/// Error making or using http connection
///
/// This error ends up being passed to hyper and bundled up into a [`hyper::Error`]
#[derive(Error, Clone, Debug)]
#[non_exhaustive]
pub enum ConnectionError {
    /// Unsupported URI scheme
    #[error("unsupported URI scheme in {uri:?}")]
    UnsupportedUriScheme {
        /// URI
        uri: Uri,
    },

    /// Unsupported URI scheme
    #[error("Missing hostname in {uri:?}")]
    MissingHostname {
        /// URI
        uri: Uri,
    },

    /// Tor connection failed
    #[error("Tor connection failed")]
    Arti(#[from] arti_client::Error),
}

/// We implement this for form's sake
impl tor_error::HasKind for ConnectionError {
    #[rustfmt::skip]
    fn kind(&self) -> tor_error::ErrorKind {
        use ConnectionError as CE;
        use tor_error::ErrorKind as EK;
        match self {
            CE::UnsupportedUriScheme{..} => EK::NotImplemented,
            CE::MissingHostname{..}      => EK::BadApiUsage,
            CE::Arti(e)                 => e.kind(),
        }
    }
}

/// A `hyper` connector to proxy HTTP connections via the Tor network, using Arti.
///
/// Only supports plaintext HTTP for now.
#[derive(Clone)]
pub struct ArtiHttpConnector<R: Runtime> {
    /// The client
    client: TorClient<R>,
}

impl<R: Runtime> ArtiHttpConnector<R> {
    /// Make a new `ArtiHttpConnector` using an Arti `TorClient` object.
    pub fn new(client: TorClient<R>) -> Self {
        Self { client }
    }
}

/// Wrapper type that makes an Arti `DataStream` implement necessary traits to be used as
/// a `hyper` connection object (mainly `Connection`).
#[pin_project]
pub struct ArtiHttpConnection {
    /// The stream
    #[pin]
    inner: DataStream,
}

impl Connection for ArtiHttpConnection {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

// These trait implementations just defer to the inner `DataStream`; the wrapper type is just
// there to implement the `Connection` trait.
impl AsyncRead for ArtiHttpConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl AsyncWrite for ArtiHttpConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.project().inner.poll_shutdown(cx)
    }
}

/// Convert uri to host and port
fn uri_to_host_port(uri: Uri) -> Result<(String, u16), ConnectionError> {
    if uri.scheme() != Some(&Scheme::HTTP) {
        return Err(ConnectionError::UnsupportedUriScheme { uri });
    }
    let host = match uri.host() {
        Some(h) => h,
        _ => return Err(ConnectionError::MissingHostname { uri }),
    };
    let port = uri.port().map(|x| x.as_u16()).unwrap_or(80);

    Ok((host.to_owned(), port))
}

impl<R: Runtime> Service<Uri> for ArtiHttpConnector<R> {
    type Response = ArtiHttpConnection;
    type Error = ConnectionError;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        // `TorClient` objects can be cloned cheaply (the cloned objects refer to the same
        // underlying handles required to make Tor connections internally).
        // We use this to avoid the returned future having to borrow `self`.
        let client = self.client.clone();
        Box::pin(async move {
            // Extract the host and port to connect to from the URI.
            let (host, port) = uri_to_host_port(req)?;
            // Initiate a new Tor connection, producing a `DataStream` if successful.
            let addr = (&host as &str, port)
                .into_tor_addr()
                .map_err(arti_client::Error::from)?;
            let ds = client.connect(addr).await?;
            Ok(ArtiHttpConnection { inner: ds })
        })
    }
}
