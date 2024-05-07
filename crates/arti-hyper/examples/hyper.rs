// @@ begin example lint list maintained by maint/add_warning @@
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
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
//! <!-- @@ end example lint list maintained by maint/add_warning @@ -->

#![allow(clippy::uninlined_format_args)]

use arti_hyper::*;

use anyhow::Result;
use arti_client::{TorClient, TorClientConfig};
use hyper::Body;
use tls_api::{TlsConnector as TlsConnectorTrait, TlsConnectorBuilder};

// On apple-darwin targets there is an issue with the native and rustls
// tls implementation so this makes it fall back to the openssl variant.
//
// https://gitlab.torproject.org/tpo/core/arti/-/issues/715
#[cfg(not(target_vendor = "apple"))]
use tls_api_native_tls::TlsConnector;
#[cfg(target_vendor = "apple")]
use tls_api_openssl::TlsConnector;

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
    // The defaults provided are the same as the Arti standalone application, and save data
    // to a conventional place depending on operating system (for example, ~/.local/share/arti
    // on Linux platforms)
    let config = TorClientConfig::default();

    // We now let the Arti client start and bootstrap a connection to the network.
    // (This takes a while to gather the necessary consensus state, etc.)
    let tor_client = TorClient::create_bootstrapped(config).await?;

    let tls_connector = TlsConnector::builder()?.build()?;

    // The `ArtiHttpConnector` lets us make HTTP requests via the Tor network.
    let tor_connector = ArtiHttpConnector::new(tor_client, tls_connector);
    let http = hyper::Client::builder().build::<_, Body>(tor_connector);

    // The rest is just standard usage of Hyper.
    eprintln!("requesting {} via Tor...", url);
    let mut resp = http.get(url.try_into()?).await?;

    eprintln!("status: {}", resp.status());

    let body = hyper::body::to_bytes(resp.body_mut()).await?;
    eprintln!("body: {}", std::str::from_utf8(&body)?);
    Ok(())
}
