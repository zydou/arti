//! # download-manager
//!
//! Download the Tor Browser Bundle over the tor network using multiple connections.
//! We use [`HTTP Range requests`][1] to request the file in chunks.
//!
//! [1]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Range_requests

use std::{collections::HashMap, num::NonZeroU8, str::FromStr};

use anyhow::Context;
use arti_client::{TorAddr, TorClient, TorClientConfig};
use clap::Parser;
use http_body_util::{BodyExt, Empty};
use hyper::{
    Method, Request, StatusCode, Uri, body::Bytes, client::conn::http1::SendRequest, header,
    http::uri::Scheme,
};
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};
use tokio::{fs::OpenOptions, io::AsyncWriteExt};
use tor_rtcompat::PreferredRuntime;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// Tor Browser Bundle download manager
///
/// This binary downloads the Linux x86_64 version, which will not work on MacOS/Windows.
#[derive(Parser)]
struct Args {
    /// Number of simultaneous connections
    #[arg(long, short, default_value = "1")]
    connections: NonZeroU8,
    /// Version of the Tor Browser to download
    #[clap(default_value = "14.0.7")]
    version: String,
}

/// Connect to a URL using a isolated Tor Client
async fn connect_to_url(
    client: &TorClient<PreferredRuntime>,
    uri: &Uri,
) -> anyhow::Result<SendRequest<Empty<Bytes>>> {
    // isolated client makes each connection run on a separate circuit
    let isolated = client.isolated_client();

    // Create TLS connector
    let connector: tokio_native_tls::TlsConnector =
        tokio_native_tls::native_tls::TlsConnector::new()
            .unwrap()
            .into();

    // Only support HTTPS
    if uri.scheme() != Some(&Scheme::HTTPS) {
        return Err(anyhow::anyhow!("URL must use HTTPS"));
    };

    // Extract host from URI
    let host = uri.host().ok_or(anyhow::anyhow!("Missing URL host"))?;

    // Convert URL to TorAddr, defaulting to HTTPS port 443
    let tor_addr = TorAddr::from((host, uri.port_u16().unwrap_or(443)))?;

    // Connect to URL
    tracing::debug!("Connecting to URL using Tor");
    let stream = isolated.connect(tor_addr).await?;

    // Wrap connection in TLS
    tracing::debug!("Wrapping connection in TLS");
    let tls_connection = connector.connect(host, stream).await?;

    // Create HTTP connection
    tracing::debug!("Performing HTTP Handshake");
    let (sender, connection) = hyper::client::conn::http1::Builder::new()
        .handshake(TokioIo::new(tls_connection))
        .await?;

    // Spawn task to drive HTTP state forward
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::debug!("Connection closed: {e}");
        }
    });

    Ok(sender)
}

/// Fetch the size of the Tor Browser Bundle
async fn get_content_length(
    http: &mut SendRequest<Empty<Bytes>>,
    uri: &Uri,
) -> anyhow::Result<u64> {
    let host = uri.host().ok_or(anyhow::anyhow!("missing host"))?;
    tracing::debug!("Request Content-Length of resource: {uri}");

    // Create HTTP Request
    let request = Request::builder()
        .method(Method::HEAD)
        // Required header
        .header(header::HOST, host)
        .uri(uri)
        .body(Empty::new())?;
    tracing::debug!("Sending request to server: {request:?}");

    let response = http.send_request(request).await?;
    tracing::debug!("Received response from server: {response:?}");

    // Check that request succeeded
    if !response.status().is_success() {
        return Err(anyhow::anyhow!("HEAD Request failed: {response:?}"));
    };

    // Get the Content-Length header
    match response.headers().get(header::CONTENT_LENGTH) {
        Some(header) => {
            let length: u64 = header.to_str()?.parse()?;
            tracing::debug!("Content-Length of resource: {length}");
            Ok(length)
        }
        None => Err(anyhow::anyhow!("Missing Content-Length header")),
    }
}

/// Fetch a [`HashMap`] of filename to checksum from a [`Uri`]
async fn get_checksums(
    http: &mut SendRequest<Empty<Bytes>>,
    uri: Uri,
) -> anyhow::Result<HashMap<String, String>> {
    let host = uri.host().ok_or(anyhow::anyhow!("missing host in uri"))?;
    tracing::debug!("Fetching checksums from {uri}");

    let request = Request::builder()
        .method(Method::GET)
        .header(header::HOST, host)
        .uri(uri)
        .body(Empty::new())?;

    let mut response = http.send_request(request).await?;

    if response.status() != StatusCode::OK {
        return Err(anyhow::anyhow!(
            "Fetching checksum failed: {}",
            response.status()
        ));
    };

    // Extract checksums into HashMap
    let mut checksums = HashMap::new();
    let body = response.body_mut().collect().await?.to_bytes();
    let content = std::str::from_utf8(&body)?;
    for line in content.lines() {
        if let Some((checksum, filename)) = line.split_once("  ") {
            checksums.insert(filename.trim().to_string(), checksum.trim().to_string());
        }
    }
    tracing::debug!("Fetched {} checksums", checksums.len());

    Ok(checksums)
}

/// Request a range of bytes using HTTP Range requests
async fn request_range(
    // Clients should only be used once for fetching a chunk,
    // so lets consume it
    mut http: SendRequest<Empty<Bytes>>,
    uri: Uri,
    start: u64,
    end: u64,
) -> anyhow::Result<Bytes> {
    let host = uri
        .host()
        .ok_or(anyhow::anyhow!("missing host"))?
        .to_string();
    tracing::debug!("Requesting range: {} to {}", start, end);

    // Create Request
    let request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(header::HOST, host)
        .header(header::RANGE, format!("bytes={start}-{end}"))
        .body(Empty::new())?;

    let mut response = http.send_request(request).await?;

    // We're expecting partial content
    if response.status() != StatusCode::PARTIAL_CONTENT {
        tracing::debug!("Server did not send chunk");
        return Err(anyhow::anyhow!(
            "No chunk from server: {:?}",
            response.status()
        ));
    };

    let body = response.body_mut().collect().await?;
    Ok(body.to_bytes())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    let connections = args.connections.get().into();

    // Warn user when using more than 8 connections
    if connections > 8 {
        tracing::warn!(
            "The Tor network has limited bandwidth, it is recommended to use less than 8 connections"
        );
    };

    // Generate download and checksum URL from Tor version
    let filename = format!("tor-browser-linux-x86_64-{}.tar.xz", args.version);

    // Check if the file already exists
    if tokio::fs::try_exists(&filename).await? {
        tracing::info!("File already exists, skipping download");
        return Err(anyhow::anyhow!("File {filename} already exists"));
    }

    let url = format!(
        "https://dist.torproject.org/torbrowser/{}/{}",
        args.version, filename
    );
    let uri = Uri::from_str(url.as_str())?;
    let checksum_url = format!(
        "https://dist.torproject.org/torbrowser/{}/sha256sums-signed-build.txt",
        args.version
    );
    let checksum_uri = Uri::from_str(checksum_url.as_str())?;

    // Create the tor client
    let config = TorClientConfig::default();

    tracing::info!("Bootstrapping... (this may take a while)");
    let client = TorClient::create_bootstrapped(config).await?;

    // Fetch Tor Browser Bundle size using isolated tor client
    let mut connection = connect_to_url(&client, &uri).await?;
    let length = get_content_length(&mut connection, &uri).await?;
    tracing::info!("Tor Browser Bundle has size: {length} bytes");

    tracing::info!("Fetching checksum");
    let checksums = get_checksums(&mut connection, checksum_uri).await?;
    let checksum = checksums
        .get(filename.as_str())
        .ok_or(anyhow::anyhow!("Missing checksum in checksum file"))?;
    tracing::info!("Checksum for resource: {}", &checksum);

    let checksum = hex::decode(checksum).context("Failed to decode checksum")?;

    // We should never have more connections than the size of the bundle
    let connections = std::cmp::min(connections, length);

    // Calculate HTTP Range chunks
    let chunk_size = length / connections;
    let remainder = length % connections;

    let mut ranges = Vec::new();
    let mut start = 0;
    for i in 0..connections {
        let extra = if i < remainder { 1 } else { 0 };
        let end = start + chunk_size + extra - 1;
        ranges.push((start, end));
        start = end + 1;
    }

    tracing::info!("Creating {connections} connections");
    let connections = ranges.iter().map(|(start, end)| async {
        // Create new connection for chunk
        let connection = connect_to_url(&client, &uri).await?;
        Ok::<_, anyhow::Error>((connection, *start, *end))
    });
    let connections = futures::future::try_join_all(connections).await?;

    // Distribute work across multiple connections
    let mut tasks = Vec::new();

    for (client, start, end) in connections {
        // Start future to request chunk
        let task = tokio::spawn(request_range(client, uri.clone(), start, end));
        tasks.push(task);
    }

    // Store downloaded content in memory
    let mut content = Vec::new();

    // Create SHA256 hasher
    let mut hasher: Sha256 = Sha256::new();

    // Write requested ranges sequentially into file
    tracing::info!("Streaming download into file");
    for task in tasks {
        let data = task.await??;
        hasher.update(&data);
        content.extend_from_slice(&data);
    }

    if checksum != hasher.finalize().as_slice() {
        return Err(anyhow::anyhow!("Mismatched checksum"));
    }
    tracing::info!("Checksum match!");

    // Write content to file
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&filename)
        .await?;

    file.write_all(&content).await?;
    tracing::info!("Saved file: {}", &filename);

    Ok(())
}
