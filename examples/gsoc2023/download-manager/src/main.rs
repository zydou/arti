#![warn(clippy::missing_docs_in_private_items)]
//! # download-manager
//! Use Tor to download the Tor Browser Bundle
//!
//! ### Intro
//! This is a project intended to illustrate how Arti can be used to tunnel an HTTPS
//! based project through Tor and also some of the design choices that go into making that
//! happen, most notably, the usage of isolated clients to create different connections
//! which won't lock each other up or run into some Arti shared state issues.
//!
//! ### Usage
//! Simply run the program:
//! `cargo run`
//!
//! The program will then attempt to create new Tor connections and download the Linux version of
//! the Tor Browser Bundle in chunks using [HTTP Range requests](https://developer.mozilla.org/en-US/docs/Web/HTTP/Range_requests)
//! in order to overcome the relatively slow connections that the Tor network provides.
//! It is currently capped to six concurrent connections in order to respect the Tor network's bandwidth
//! The Tor Browser Bundle is saved as `download.tar.xz`
//!
//! ### Disclaimer
//! The download manager showcased is not really meant for production. It is simply an example of how Arti
//! can be utilized. Many features, like resumeable downloads, aren't present. Don't use it for any real
//! usage other than academic
use arti_client::{TorClient, TorClientConfig};
use arti_hyper::*;
use futures::future::join_all;
use hyper::{Body, Client, Method, Request, StatusCode, Uri};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::str::FromStr;
use tls_api::{TlsConnector as TlsConnectorTrait, TlsConnectorBuilder};
use tls_api_native_tls::TlsConnector;
use tor_rtcompat::PreferredRuntime;
use tracing::{debug, error, info, warn};

/// REQSIZE is just the size of each chunk we get from a particular circuit
const REQSIZE: u64 = 1024 * 1024;
/// This denotes the version of Tor Browser to get
///
/// It also helps us create the URL to get the SHA256 sums for the browser we download
const TOR_VERSION: &str = "13.0";
/// Number of simultaneous connections that are made
// TODO: make this user configurable
const MAX_CONNECTIONS: usize = 6;
/// Number of retries to make if a particular request failed
const MAX_RETRIES: usize = 6;

#[derive(thiserror::Error, Debug)]
#[error("Download Manager Error")]
/// Enum storing all the Errors that our program can raise
enum DownloadMgrError {
    #[error("Download failed due to unspecified reason")]
    /// Blanket download error to catch almost all download errors
    DownloadError,
    #[error("Got unexpected status code")]
    /// Error to represent an unexpected status code from the network
    RequestFailed {
        /// The status code that we got instead of the intended one
        status: StatusCode,
    },
    /// Error to represent raw bytes properly
    #[error("Unable to read body into bytes")]
    BodyDownload {
        /// Error raised while reading body into bytes, wraps [hyper::Error]`
        error: hyper::Error,
    },
    #[error("Failed to get a connection from pool")]
    /// Used to denote a failed .get() request from `Vec<Client>`
    ConnectionError,
}

/// Create a single TorClient which will be used to spawn isolated connections
///
/// This Client uses the default config with no other changes
async fn create_tor_client() -> Result<TorClient<PreferredRuntime>, arti_client::Error> {
    let config = TorClientConfig::default();
    TorClient::create_bootstrapped(config).await
}

/// Creates a `hyper::Client` for sending HTTPS requests over Tor
///
/// Note that it first creates an isolated circuit from the `TorClient`
/// passed into it, this is generally an Arti best practice
async fn build_tor_hyper_client(
    baseconn: &TorClient<PreferredRuntime>,
) -> anyhow::Result<Client<ArtiHttpConnector<PreferredRuntime, TlsConnector>>> {
    let tor_client = baseconn.isolated_client();
    let tls_connector = TlsConnector::builder()?.build()?;

    let connector = ArtiHttpConnector::new(tor_client, tls_connector);
    Ok(hyper::Client::builder().build::<_, Body>(connector))
}

/// Get the size of file to be downloaded so we can prep main loop
async fn get_content_length(
    url: String,
    baseconn: &TorClient<PreferredRuntime>,
) -> anyhow::Result<u64> {
    let http = build_tor_hyper_client(baseconn).await?;
    let uri = Uri::from_str(url.as_str())?;
    debug!("Requesting content length of {} via Tor...", url);
    // Create a new request
    let req = Request::builder()
        .method(Method::HEAD)
        .uri(uri)
        .body(Body::empty())?;

    let resp = http.request(req).await?;
    // Get Content-Length
    match resp.headers().get("Content-Length") {
        Some(raw_length) => {
            let length = raw_length.to_str()?.parse::<u64>()?;
            debug!("Content-Length of resource: {}", length);
            // Return it after a suitable typecast
            Ok(length)
        }
        None => Err(DownloadMgrError::DownloadError.into()),
    }
}

/// Gets a portion of the file from the server and store it in a Vec if successful
///
/// Note that it returns a Result to denote any network issues that may have arisen from the request
async fn request_range(
    url: &String,
    start: usize,
    end: usize,
    http: &Client<ArtiHttpConnector<PreferredRuntime, TlsConnector>>,
) -> anyhow::Result<Vec<u8>> {
    warn!("Requesting {} via Tor...", url);
    let uri = Uri::from_str(url)?;
    let partial_req_value = format!("bytes={}-{}", start, end);
    // GET the contents of URL from byte offset "start" to "end"
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("Range", partial_req_value)
        .body(Body::default())?;
    let mut resp = http.request(req).await?;

    // Got partial content, this is good
    if resp.status() == hyper::StatusCode::PARTIAL_CONTENT {
        debug!("Good request, getting partial content...");
        // Get the body of the response
        return match hyper::body::to_bytes(resp.body_mut()).await {
            Ok(bytes) => Ok(bytes.to_vec()),
            Err(e) => Err(DownloadMgrError::BodyDownload { error: e }.into()),
        };
    }
    // Got something else, return an Error
    warn!("Non 206 Status code: {}", resp.status());
    Err(DownloadMgrError::RequestFailed {
        status: resp.status(),
    }
    .into())
}

/// Gets the expected SHA256 sum of the download file from the server
///
/// Note that it returns a Result to denote any network issues that may have arisen from the request
async fn request_sha256_sum(
    url: String,
    http: &Client<ArtiHttpConnector<PreferredRuntime, TlsConnector>>,
    file_name: &str,
) -> anyhow::Result<String> {
    let uri = Uri::from_str(url.as_str())?;
    // GET the contents of URL from byte offset "start" to "end"
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::default())?;
    let mut resp = http.request(req).await?;

    if resp.status() == hyper::StatusCode::OK {
        debug!("Good request, getting content...");
        // Get the body of the response
        return match hyper::body::to_bytes(resp.body_mut()).await {
            Ok(bytes) => {
                let bytes_vec = bytes.to_vec();
                let str_body = std::str::from_utf8(&bytes_vec)?;
                for line in str_body.lines() {
                    let parts: Vec<&str> = line.splitn(2, "  ").collect();
                    if parts[1] == file_name {
                        return Ok(parts[0].to_string());
                    }
                }
                Err(DownloadMgrError::DownloadError.into())
            }
            Err(e) => Err(DownloadMgrError::BodyDownload { error: e }.into()),
        };
    }
    // Got something else, return an Error
    warn!("Non 200 Status code: {}", resp.status());
    Err(DownloadMgrError::RequestFailed {
        status: resp.status(),
    }
    .into())
}

/// Backoff function for determining timeout duration for each repeated download try
fn wait_time_for_iteration(iteration: usize) -> u64 {
    1000.min(500 + 100 * iteration as u64)
}

/// Wrapper around [request_range] in order to overcome network issues
///
/// We try a maximum of [MAX_RETRIES] to get the portion of the file we require
///
/// If we are successful, we return the bytes to be later written to disk, else we simply return None
async fn download_segment(
    url: String,
    start: usize,
    end: usize,
    newhttp: Client<ArtiHttpConnector<PreferredRuntime, TlsConnector>>,
) -> Result<Vec<u8>, crate::DownloadMgrError> {
    for trial in 0..MAX_RETRIES {
        if trial != 0 {
            tokio::time::sleep(std::time::Duration::from_millis(wait_time_for_iteration(
                trial,
            )))
            .await;
        }
        // request via new Tor connection
        match request_range(&url, start, end, &newhttp).await {
            // save to disk
            Ok(body) => {
                return Ok(body);
            }
            // retry if we failed
            Err(e) => {
                warn!(
                    "Error while trying to get a segment: {}, retrying...",
                    e.to_string()
                );
            }
        }
    }
    Err(DownloadMgrError::DownloadError)
}

/// Main method which brings it all together
///
/// Summary:
///
/// 1. Get the SHA256 checksum of the Tor Browser Bundle for later
/// verification of the downloaded data
///
/// 2. Create [MAX_CONNECTIONS] number of connections, these will be all
/// that is used for the main loop of the program
///
/// 3. Get content length of the Tor Browser Bundle so we know how
/// many loops to run
///
/// 4. Create the main loop of the program; it simply cycles through the
/// connections we initialized in step 2 and makes a request with them for the
/// bulk of the payload we request from the network
///
/// 5. Check SHA256 checksum of the file in memory and compare it to the
/// expected value we got from the Tor Project's website
///
/// 6. Write all that data to the disk
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    // generate the URLs and file names from the version number
    // and some known conventions
    let download_file_name = format!("tor-browser-linux-x86_64-{}.tar.xz", TOR_VERSION);
    let url = format!(
        "https://dist.torproject.org/torbrowser/{}/{}",
        TOR_VERSION, download_file_name
    );
    let verification_url = format!(
        "https://dist.torproject.org/torbrowser/{}/sha256sums-signed-build.txt",
        TOR_VERSION
    );
    let baseconn = create_tor_client().await?;
    let length = get_content_length(url.clone(), &baseconn).await?;

    let sha_http_client = build_tor_hyper_client(&baseconn).await?;
    let expected_sha256sum =
        request_sha256_sum(verification_url, &sha_http_client, &download_file_name).await?;
    debug!("Expected SHA256 sum of file: {}", expected_sha256sum);

    // Initialize the connections we will use for this download
    let mut connections: Vec<Client<_>> = Vec::with_capacity(MAX_CONNECTIONS);
    for _ in 0..MAX_CONNECTIONS {
        let newhttp = build_tor_hyper_client(&baseconn).await?;
        connections.push(newhttp);
    }

    // determine the amount of iterations required
    let steps = length / REQSIZE;
    let mut downloadtasks = Vec::with_capacity(steps as usize);
    let mut start = 0;
    let mut taskid = 0;
    while start < length as usize {
        // the upper bound of what block we need from the server
        let end = (start + (REQSIZE as usize) - 1).min(length as usize);
        let http = connections
            .get(taskid)
            .ok_or(DownloadMgrError::ConnectionError)?;
        let newhttp = http.clone();
        let urlclone = url.clone();
        downloadtasks.push(tokio::spawn(async move {
            download_segment(urlclone, start, end, newhttp)
                .await
                .map(|body| (start, body))
        }));
        start = end + 1;
        taskid = (taskid + 1) % MAX_CONNECTIONS;
    }
    let results_options: Vec<Result<_, _>> = join_all(downloadtasks)
        .await
        .into_iter()
        .flatten()
        .collect();
    // if we got an Error from network operations, that means we don't have entire file
    // thus we delete the partial file and print an error
    let has_err = results_options.iter().any(|result_op| result_op.is_err());
    if has_err {
        error!("Possible missing chunk! Aborting");
        return Ok(());
    }
    let mut results: Vec<_> = results_options
        .into_iter()
        .filter_map(|result| result.ok())
        .collect();
    results.sort_by(|a, b| a.0.cmp(&b.0));
    let mut file_vec: Vec<u8> = Vec::new();
    // write all chunks to memory representation of file, checking along the
    // way if the offsets match our expectations
    let mut start_check = 0;
    for (start, chunk) in results.iter() {
        if *start != start_check {
            error!("Mismatch in expected and observed offset! Aborting");
            return Ok(());
        }
        let end_check = start_check + (REQSIZE as usize) - 1;
        debug!(
            "Writing chunk offset {} to memory representation of file...",
            start
        );
        file_vec.extend(chunk);
        start_check = end_check + 1;
    }

    // Verify downloaded content's checksum
    let mut sha256 = Sha256::new();
    sha256.update(&file_vec);
    let hash_result = sha256.finalize();
    let observed_hash = format!("{:x}", hash_result);
    if observed_hash != expected_sha256sum {
        error!("Incorrect SHA 256 sum in download! Aborting");
        return Ok(());
    }
    // Write validated data to disk
    info!("Creating download file");
    let mut fd = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&download_file_name)?;
    debug!("Created file, now writing downloaded content to disk...");
    fd.write_all(&file_vec)?;
    Ok(())
}
