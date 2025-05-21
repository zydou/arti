// Use your own instance of an `arti_client::TorClient` with arti-ureq to make a GET request.

use anyhow::Context;

const TEST_URL: &str = "https://check.torproject.org/api/ip";

fn main() -> anyhow::Result<()> {
    // Create your own instance of a Tor client.
    let tor_client = arti_ureq::arti_client::TorClient::with_runtime(
        arti_ureq::tor_rtcompat::PreferredRuntime::create().context("Failed to create runtime.")?,
    )
    .create_unbootstrapped()
    .context("Error creating Tor Client.")?;

    // Make a Connector and get ureq agent.
    let ureq_agent = arti_ureq::Connector::with_tor_client(tor_client).agent();

    // Make request.
    let mut request = ureq_agent
        .get(TEST_URL)
        .call()
        .context("Failed to make request.")?;

    // Get response body.
    let response = request
        .body_mut()
        .read_to_string()
        .context("Failed to read body.")?;

    // Will output if request was made using Tor.
    println!("Response: {response}");

    Ok(())
}
