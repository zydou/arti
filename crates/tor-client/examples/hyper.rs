use anyhow::{anyhow, bail, Result};
use arti_tor_client::{DataStream, IntoTorAddr, TorClient, TorClientConfig};
use hyper::client::connect::{Connected, Connection};
use hyper::http::uri::Scheme;
use hyper::http::Uri;
use hyper::service::Service;
use hyper::Body;
use pin_project::pin_project;
use std::convert::TryInto;
use std::future::Future;
use std::io::Error;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_crate as tokio;
use tor_rtcompat::tokio::TokioRuntimeHandle;
use tor_rtcompat::Runtime;

/// A `hyper` connector to proxy HTTP connections via the Tor network, using Arti.
///
/// Only supports plaintext HTTP for now.
#[derive(Clone)]
pub struct ArtiHttpConnector<R: Runtime> {
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

fn uri_to_host_port(uri: Uri) -> Result<(String, u16)> {
    if uri.scheme() != Some(&Scheme::HTTP) {
        bail!(
            "ArtiHttpConnector only supports HTTP connections for now; got {:?}",
            uri.scheme()
        );
    }
    let host = uri
        .host()
        .ok_or_else(|| anyhow!("No hostname found in URI"))?;
    let port = uri.port().map(|x| x.as_u16()).unwrap_or(80);

    Ok((host.to_owned(), port))
}

impl<R: Runtime> Service<Uri> for ArtiHttpConnector<R> {
    type Response = ArtiHttpConnection;
    type Error = anyhow::Error;
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
            let ds = client
                .connect((&host as &str, port).into_tor_addr()?, None)
                .await?;
            Ok(ArtiHttpConnection { inner: ds })
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Arti uses the `tracing` crate for logging. Install a handler for this, to print Arti's logs.
    // (You'll need to set RUST_LOG=info as an environment variable to actually see much; also try
    // =debug for more detailed logging.)
    tracing_subscriber::fmt::init();

    // You can run this example with any arbitrary (HTTP-only!) URL, but we'll default to icanhazip
    // because it's a good way of demonstrating that the connection is via Tor.
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://icanhazip.com".into());

    eprintln!("starting Arti...");

    // The client config includes things like where to store persistent Tor network state.
    // The "sane defaults" provided are the same as the Arti standalone application, and save data
    // to a conventional place depending on operating system (for example, ~/.local/share/arti
    // on Linux platforms)
    let config = TorClientConfig::sane_defaults()?;
    // Arti needs an async runtime handle to spawn async tasks.
    let rt: TokioRuntimeHandle = tokio_crate::runtime::Handle::current().into();

    // We now let the Arti client start and bootstrap a connection to the network.
    // (This takes a while to gather the necessary consensus state, etc.)
    let tor_client = TorClient::bootstrap(rt, config).await?;

    // The `ArtiHttpConnector` lets us make HTTP requests via the Tor network.
    let tor_connector = ArtiHttpConnector::new(tor_client);
    let http = hyper::Client::builder().build::<_, Body>(tor_connector);

    // The rest is just standard usage of Hyper.
    eprintln!("requesting {} via Tor...", url);
    let mut resp = http.get(url.try_into()?).await?;

    eprintln!("status: {}", resp.status());

    let body = hyper::body::to_bytes(resp.body_mut()).await?;
    eprintln!("body: {}", std::str::from_utf8(&body)?);
    Ok(())
}
