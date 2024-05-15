#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
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
#![deny(clippy::unchecked_duration_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

use std::future::Future;
use std::io::Error;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use arti_client::{DataStream, IntoTorAddr, TorClient};
use educe::Educe;
use hyper::client::connect::{Connected, Connection};
use hyper::http::uri::Scheme;
use hyper::http::Uri;
use hyper::service::Service;
use pin_project::pin_project;
use thiserror::Error;
use tls_api::TlsConnector as TlsConn; // This is different from tor_rtcompat::TlsConnector
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

    /// Missing hostname
    #[error("Missing hostname in {uri:?}")]
    MissingHostname {
        /// URI
        uri: Uri,
    },

    /// Tor connection failed
    #[error("Tor connection failed")]
    Arti(#[from] arti_client::Error),

    /// TLS connection failed
    #[error("TLS connection failed")]
    TLS(#[source] Arc<anyhow::Error>),
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
            CE::Arti(e)                  => e.kind(),
            CE::TLS(_)                   => EK::RemoteProtocolViolation,
        }
    }
}

/// **Main entrypoint**: `hyper` connector to make HTTP\[S] connections via Tor, using Arti.
///
/// An `ArtiHttpConnector` combines an Arti Tor client, and a TLS implementation,
/// in a form that can be provided to hyper
/// (e.g. to [`hyper::client::Builder`]'s `build` method)
/// so that hyper can speak HTTP and HTTPS to origin servers via Tor.
///
/// TC is the TLS to used *across* Tor to connect to the origin server.
/// For example, it could be a [`tls_api_native_tls::TlsConnector`].
/// This is a different Rust type to the TLS used *by* Tor to connect to relays etc.
/// It might even be a different underlying TLS implementation
/// (although that is usually not a particularly good idea).
#[derive(Educe)]
#[educe(Clone)] // #[derive(Debug)] infers an unwanted bound TC: Clone
pub struct ArtiHttpConnector<R: Runtime, TC: TlsConn> {
    /// The client
    client: TorClient<R>,

    /// TLS for using across Tor.
    tls_conn: Arc<TC>,
}

// #[derive(Clone)] infers a TC: Clone bound

impl<R: Runtime, TC: TlsConn> ArtiHttpConnector<R, TC> {
    /// Make a new `ArtiHttpConnector` using an Arti `TorClient` object.
    pub fn new(client: TorClient<R>, tls_conn: TC) -> Self {
        let tls_conn = tls_conn.into();
        Self { client, tls_conn }
    }
}

/// Wrapper type that makes an Arti `DataStream` implement necessary traits to be used as
/// a `hyper` connection object (mainly `Connection`).
///
/// This might represent a bare HTTP connection across Tor,
/// or it might represent an HTTPS connection through Tor to an origin server,
/// `TC::TlsStream` as the TLS layer.
///
/// An `ArtiHttpConnection` is constructed by hyper's use of the [`ArtiHttpConnector`]
/// implementation of [`hyper::service::Service`],
/// and then used by hyper as the transport for hyper's HTTP implementation.
#[pin_project]
pub struct ArtiHttpConnection<TC: TlsConn> {
    /// The stream
    #[pin]
    inner: MaybeHttpsStream<TC>,
}

/// The actual actual stream; might be TLS, might not
#[pin_project(project = MaybeHttpsStreamProj)]
enum MaybeHttpsStream<TC: TlsConn> {
    /// http
    Http(Pin<Box<DataStream>>), // Tc:TlsStream is generally boxed; box this one too

    /// https
    Https(#[pin] TC::TlsStream),
}

impl<TC: TlsConn> Connection for ArtiHttpConnection<TC> {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

// These trait implementations just defer to the inner `DataStream`; the wrapper type is just
// there to implement the `Connection` trait.
impl<TC: TlsConn> AsyncRead for ArtiHttpConnection<TC> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.project().inner.project() {
            MaybeHttpsStreamProj::Http(ds) => ds.as_mut().poll_read(cx, buf),
            MaybeHttpsStreamProj::Https(t) => t.poll_read(cx, buf),
        }
    }
}

impl<TC: TlsConn> AsyncWrite for ArtiHttpConnection<TC> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        match self.project().inner.project() {
            MaybeHttpsStreamProj::Http(ds) => ds.as_mut().poll_write(cx, buf),
            MaybeHttpsStreamProj::Https(t) => t.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.project().inner.project() {
            MaybeHttpsStreamProj::Http(ds) => ds.as_mut().poll_flush(cx),
            MaybeHttpsStreamProj::Https(t) => t.poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.project().inner.project() {
            MaybeHttpsStreamProj::Http(ds) => ds.as_mut().poll_shutdown(cx),
            MaybeHttpsStreamProj::Https(t) => t.poll_shutdown(cx),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
/// Are we doing TLS?
enum UseTls {
    /// No
    Bare,

    /// Yes
    Tls,
}

/// Convert uri to http\[s\] host and port, and whether to do tls
fn uri_to_host_port_tls(uri: Uri) -> Result<(String, u16, UseTls), ConnectionError> {
    let use_tls = {
        // Scheme doesn't derive PartialEq so can't be matched on
        let scheme = uri.scheme();
        if scheme == Some(&Scheme::HTTP) {
            UseTls::Bare
        } else if scheme == Some(&Scheme::HTTPS) {
            UseTls::Tls
        } else {
            return Err(ConnectionError::UnsupportedUriScheme { uri });
        }
    };
    let host = match uri.host() {
        Some(h) => h,
        _ => return Err(ConnectionError::MissingHostname { uri }),
    };
    let port = uri.port().map(|x| x.as_u16()).unwrap_or(match use_tls {
        UseTls::Tls => 443,
        UseTls::Bare => 80,
    });

    Ok((host.to_owned(), port, use_tls))
}

impl<R: Runtime, TC: TlsConn> Service<Uri> for ArtiHttpConnector<R, TC> {
    type Response = ArtiHttpConnection<TC>;
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
        let tls_conn = self.tls_conn.clone();
        Box::pin(async move {
            // Extract the host and port to connect to from the URI.
            let (host, port, use_tls) = uri_to_host_port_tls(req)?;
            // Initiate a new Tor connection, producing a `DataStream` if successful.
            let addr = (&host as &str, port)
                .into_tor_addr()
                .map_err(arti_client::Error::from)?;
            let ds = client.connect(addr).await?;

            let inner = match use_tls {
                UseTls::Tls => {
                    let conn = tls_conn
                        .connect_impl_tls_stream(&host, ds)
                        .await
                        .map_err(|e| ConnectionError::TLS(e.into()))?;
                    MaybeHttpsStream::Https(conn)
                }
                UseTls::Bare => MaybeHttpsStream::Http(Box::new(ds).into()),
            };

            Ok(ArtiHttpConnection { inner })
        })
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
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    fn make_uri(url: &str) -> Uri {
        url.parse::<Uri>().expect("Unable to parse uri")
    }

    #[test]
    fn check_supported_uri_schemes() {
        // Unsupported URI schemes should return an error
        let unsupported = [
            "wss://torproject.org",
            "file://torproject.org",
            "ftp://torproject.org",
            "vnc://torproject.org",
            "/no/scheme",
        ];
        for url in unsupported {
            assert!(uri_to_host_port_tls(make_uri(url)).is_err());
        }

        // Supported URI schemes should return a result with correct TLS setting
        let supported = [
            ("https://torproject.org", UseTls::Tls),
            ("http://torproject.org", UseTls::Bare),
        ];
        for (url, tls) in supported {
            let (_ret_host, _ret_port, ret_tls) =
                uri_to_host_port_tls(make_uri(url)).expect("function should return Result");

            assert_eq!(ret_tls, tls);
        }
    }

    #[test]
    fn get_correct_port_and_tls_from_uri() {
        // (1) Custom ports should be used when explicitly specified, otherwise correct defaults should be used
        // (2) TLS setting should be dependent on URI scheme, not port
        let urls = [
            ("https://torproject.org:999", 999, UseTls::Tls),
            ("https://torproject.org:80", 80, UseTls::Tls),
            ("https://torproject.org", 443, UseTls::Tls),
            ("http://torproject.org:999", 999, UseTls::Bare),
            ("http://torproject.org:443", 443, UseTls::Bare),
            ("http://torproject.org", 80, UseTls::Bare),
        ];

        for (url, port, tls) in urls {
            let (_ret_host, ret_port, ret_tls) =
                uri_to_host_port_tls(make_uri(url)).expect("function should return Result");

            assert_eq!(ret_port, port);
            assert_eq!(ret_tls, tls);
        }
    }

    #[test]
    fn get_correct_host_from_uri() {
        let urls = [
            ("https://torproject.org", "torproject.org"),
            ("http://torproject.org", "torproject.org"),
        ];

        for (url, host) in urls {
            let (ret_host, _ret_port, _ret_tls) =
                uri_to_host_port_tls(make_uri(url)).expect("function should return Result");

            assert_eq!(ret_host, host);
        }
    }
}
