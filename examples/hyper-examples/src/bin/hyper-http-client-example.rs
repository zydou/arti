use anyhow::Result;
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::http::uri::Scheme;
use hyper::{Request, Uri};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};

use arti_client::{TorClient, TorClientConfig};

const TEST_URL: &str = "https://check.torproject.org/api/ip";

#[tokio::main]
async fn main() -> Result<()> {
    // Arti uses the `tracing` crate for logging. Install a handler for this, to print Arti's logs.
    // (You'll need to set RUST_LOG=info as an environment variable to actually see much; also try
    // =debug for more detailed logging.)
    tracing_subscriber::fmt::init();

    // You can run this example with any arbitrary HTTP/1.1 (raw or within TLS) URL, but we'll default to check.torproject.org
    // because it's a good way of demonstrating that the connection is via Tor.
    let url: Uri = std::env::args()
        .nth(1)
        .unwrap_or_else(|| TEST_URL.into())
        .parse()?;
    let host = url.host().unwrap();
    let https = url.scheme() == Some(&Scheme::HTTPS);

    // The client config includes things like where to store persistent Tor network state.
    // The defaults provided are the same as the Arti standalone application, and save data
    // to a conventional place depending on operating system (for example, ~/.local/share/arti
    // on Linux platforms)
    let config = TorClientConfig::default();

    // We now let the Arti client start and bootstrap a connection to the network.
    // (This takes a while to gather the necessary consensus state, etc.)
    let tor_client = TorClient::create_bootstrapped(config).await?;

    let port = match url.port_u16() {
        Some(port) => port,
        _ if https => 443,
        _ => 80,
    };

    let stream = tor_client.connect((host, port)).await?;

    // Following part is just standard usage of Hyper.
    eprintln!("[+] Making request to: {}", url);

    if https {
        let cx = tokio_native_tls::native_tls::TlsConnector::builder().build()?;
        let cx = tokio_native_tls::TlsConnector::from(cx);
        let stream = cx.connect(host, stream).await?;
        make_request(host, stream).await
    } else {
        make_request(host, stream).await
    }
}

async fn make_request(
    host: &str,
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
) -> Result<()> {
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;

    // Spawn a task to poll the connection and drive the HTTP state.
    tokio::spawn(async move {
        connection.await.unwrap();
    });

    let mut resp = request_sender
        .send_request(
            Request::builder()
                .header("Host", host)
                .uri(TEST_URL)
                .method("GET")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;

    eprintln!("[+] Response status: {}", resp.status());
    while let Some(frame) = resp.body_mut().frame().await {
        let bytes = frame?.into_data().unwrap();
        eprintln!("[+] Response body:\n\n{}", std::str::from_utf8(&bytes)?);
    }

    Ok(())
}
