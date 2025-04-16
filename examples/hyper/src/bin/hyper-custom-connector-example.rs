use anyhow::Context;
use http_body_util::BodyExt;
use hyper::rt::{Read as HyperRead, Write as HyperWrite};
use hyper_util::client::legacy::{connect::Connection, Client};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// We use `tower_service::Service` instead of `hyper::service::Service` because
// `hyper_util::client::legacy::Client` requires the former.
use tower_service::Service;

use arti_client::{IntoTorAddr, TorClient, TorClientConfig};
use tor_rtcompat::Runtime;

const TEST_URL: &str = "https://check.torproject.org/api/ip";
const HTTPS_SCHEME: &str = "https";

// A HttpConnector containing the TorClient we can inject into the hyper client.
#[derive(Clone)]
pub struct ArtiHttpConnector<R: Runtime> {
    client: TorClient<R>,
}

// Contains the stream from the TorClient.
pub struct ArtiHttpConnection {
    stream: ConnectionStream,
}

// Stream can either be plain (http) or tls (https).
enum ConnectionStream {
    Plain(std::pin::Pin<Box<dyn AsyncReadWrite + Send + Unpin>>),
    Tls(std::pin::Pin<Box<dyn AsyncReadWrite + Send + Unpin>>),
}

#[derive(Debug)]
enum UseTls {
    Yes,
    No,
}

// Combine `AsyncRead` and `AsyncWrite` into one trait.
trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + ?Sized> AsyncReadWrite for T {}

impl<R: Runtime> ArtiHttpConnector<R> {
    pub fn new(client: TorClient<R>) -> Self {
        Self { client }
    }
}

impl Connection for ArtiHttpConnection {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        hyper_util::client::legacy::connect::Connected::new()
    }
}

// Reading incoming data from the response coming through the TorClient.
// [!] Requires unsafe code because we are using `ReadBufCursor`.
impl HyperRead for ArtiHttpConnection {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let dst = unsafe { buf.as_mut() };
        let mut read_buf = ReadBuf::uninit(dst);

        let poll = match &mut self.get_mut().stream {
            ConnectionStream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, &mut read_buf),
            ConnectionStream::Tls(s) => std::pin::Pin::new(s).poll_read(cx, &mut read_buf),
        };

        if let std::task::Poll::Ready(Ok(())) = &poll {
            let filled = read_buf.filled().len();
            unsafe { buf.advance(filled) };
        }

        poll
    }
}

// Write outgoing data through the TorClient to send a request.
impl HyperWrite for ArtiHttpConnection {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut self.get_mut().stream {
            ConnectionStream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            ConnectionStream::Tls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut self.get_mut().stream {
            ConnectionStream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            ConnectionStream::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut self.get_mut().stream {
            ConnectionStream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            ConnectionStream::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

// After injecting our custom `ArtiHttpConnector` into the hyper client,
// hyper will execute this call to create the connection.
impl<R: Runtime> Service<hyper::Uri> for ArtiHttpConnector<R> {
    type Response = ArtiHttpConnection;
    type Error = std::io::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn call(&mut self, req: http::Uri) -> Self::Future {
        let client = self.client.clone();

        Box::pin(async move {
            // Retrieve host, port and if TLS is required from the URI.
            let (host, port, use_tls) =
                uri_to_host_port_tls(&req).expect("Failed to retrieve host and port from URI");
            let addr = match (host.to_string(), port).into_tor_addr() {
                Ok(addr) => addr,
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Invalid address",
                    ));
                }
            };

            // Make a connection to the Tor client and retrieve the stream. This stream is
            // the handle we will use to bridge between hyper and the Tor client.
            let stream = client.connect(addr).await.map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!("Connection refused: {}", e),
                )
            })?;

            // Depending on `use_tls` we make a plain connection or upgrade the existing connection to TLS.
            let stream = match use_tls {
                // TLS connection.
                UseTls::Yes => {
                    // Get root_certs required for TLS.
                    let mut root_cert_store = tokio_rustls::rustls::RootCertStore::empty();
                    root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                    let config = tokio_rustls::rustls::ClientConfig::builder()
                        .with_root_certificates(root_cert_store)
                        .with_no_client_auth();

                    // Use `tokio_rustls` connector to create a TLS connection.
                    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
                    let server_name = host.to_string().try_into().map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Bad DNS name")
                    })?;

                    // Upgrade existing connection the TorClient made to TLS.
                    let tls = connector.connect(server_name, stream).await?;
                    ConnectionStream::Tls(Box::pin(tls))
                }

                // Plain connection.
                UseTls::No => ConnectionStream::Plain(Box::pin(stream)),
            };

            Ok(ArtiHttpConnection { stream })
        })
    }

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

// Helper method to retrieve host, port and if TLS is required from the URI.
fn uri_to_host_port_tls(uri: &http::Uri) -> anyhow::Result<(String, u16, UseTls), anyhow::Error> {
    let host = uri
        .host()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "Missing host"))?;
    let use_tls = if uri
        .scheme_str()
        .context("Failed to retrieve scheme as string")?
        == HTTPS_SCHEME
    {
        UseTls::Yes
    } else {
        UseTls::No
    };
    let port = match use_tls {
        UseTls::Yes => 443,
        UseTls::No => 80,
    };

    Ok((host.to_string(), port, use_tls))
}

// USAGE
// This example demonstrates how to use the custom `ArtiHttpConnector` to make a request
// using the hyper client by injecting our custom controller.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create TorClient.
    let tor_client = TorClient::create_bootstrapped(TorClientConfig::default())
        .await
        .context("Failed to create Tor client")?;

    // Create new ArtiHttpConnector with the TorClient.
    let connector = ArtiHttpConnector::new(tor_client);

    // Create hyper client with our custom connector.
    let client = Client::builder(hyper_util::rt::TokioExecutor::new())
        .build::<_, http_body_util::Empty<bytes::Bytes>>(connector);

    // Make a request to the test URL.
    println!("[+] Making request to: {}", TEST_URL);
    let uri: hyper::Uri = TEST_URL.parse().context("Failed to parse URI")?;
    let response = client
        .get(uri.clone())
        .await
        .context("Failed to make request")?;

    // Retrieve response status and body.
    let status = response.status();
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .context("Failed to collect response body")?
        .to_bytes();

    let body_str = String::from_utf8_lossy(&body_bytes);
    println!("[+] Response status: {}", status);
    println!("[+] Response body:\n\n{}", body_str);

    Ok(())
}
