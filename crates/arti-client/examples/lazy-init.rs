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

use anyhow::Result;
use arti_client::{TorClient, TorClientConfig};
use tokio_crate as tokio;

use futures::io::{AsyncReadExt, AsyncWriteExt};
use once_cell::sync::OnceCell;
use tor_rtcompat::PreferredRuntime;

static TOR_CLIENT: OnceCell<TorClient<PreferredRuntime>> = OnceCell::new();

/// Get a `TorClient` by copying the globally shared client stored in `TOR_CLIENT`.
/// If that client hasn't been initialized yet, initializes it first.
///
/// # Errors
///
/// Errors if called outside a Tokio runtime context, or creating the Tor client
/// failed.
pub fn get_tor_client() -> Result<TorClient<PreferredRuntime>> {
    let client = TOR_CLIENT.get_or_try_init(|| -> Result<TorClient<_>> {
        // The client config includes things like where to store persistent Tor network state.
        // The defaults provided are the same as the Arti standalone application, and save data
        // to a conventional place depending on operating system (for example, ~/.local/share/arti
        // on Linux platforms)
        let config = TorClientConfig::default();

        eprintln!("creating unbootstrapped Tor client");

        // Create an unbootstrapped Tor client. Bootstrapping will happen when the client is used,
        // since `BootstrapBehavior::OnDemand` is the default.
        Ok(TorClient::builder()
            .config(config)
            .create_unbootstrapped()?)
    })?;

    Ok(client.clone())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Arti uses the `tracing` crate for logging. Install a handler for this, to print Arti's logs.
    tracing_subscriber::fmt::init();

    eprintln!("getting shared Tor client...");

    let tor_client = get_tor_client()?;

    eprintln!("connecting to example.com...");

    // Initiate a connection over Tor to example.com, port 80.
    let mut stream = tor_client.connect(("example.com", 80)).await?;

    eprintln!("sending request...");

    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await?;

    // IMPORTANT: Make sure the request was written.
    // Arti buffers data, so flushing the buffer is usually required.
    stream.flush().await?;

    eprintln!("reading response...");

    // Read and print the result.
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;

    println!("{}", String::from_utf8_lossy(&buf));

    Ok(())
}
