#![cfg_attr(not(ci_arti_nightly), allow(unknown_lints))]
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
use tor_error::ErrorReport;

#[tokio::main]
async fn main() -> Result<()> {
    // Arti uses the `tracing` crate for logging. Install a handler for this, to print Arti's logs.
    tracing_subscriber::fmt::init();

    // The client config includes things like where to store persistent Tor network state.
    // The defaults provided are the same as the Arti standalone application, and save data
    // to a conventional place depending on operating system (for example, ~/.local/share/arti
    // on Linux platforms)
    let config = TorClientConfig::default();

    eprintln!("connecting to Tor...");

    // We now let the Arti client start and bootstrap a connection to the network.
    // (This takes a while to gather the necessary consensus state, etc.)
    let tor_client = TorClient::create_bootstrapped(config).await?;

    eprintln!("connecting to example.com...");

    // Initiate a connection over Tor to example.com, port 80.
    // Note: here we try to handle the potential error using match
    match tor_client.connect(("example.com", 80)).await {
        Ok(mut stream) => {
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
        }
        Err(err) => {
            // Use .report() on an error to get a nicer error message
            // Raw Debug output will be much harder to decipher for all parties involved
            eprintln!("{}", err.report());
        }
    }
    Ok(())
}
