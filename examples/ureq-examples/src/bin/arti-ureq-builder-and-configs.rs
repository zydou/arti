// Configure arti-ureq using custom configurations and the ConnectorBuilder.

use anyhow::Context;
use arti_ureq::ureq::tls::RootCerts;

const TEST_URL: &str = "https://check.torproject.org/api/ip";

fn main() -> anyhow::Result<()> {
    // Build tor client config.
    let tor_client_config = arti_ureq::arti_client::config::TorClientConfig::default();

    // Create tor client.
    let tor_client = arti_ureq::arti_client::TorClient::with_runtime(
        arti_ureq::tor_rtcompat::PreferredRuntime::create().context("Failed to create runtime.")?,
    )
    .config(tor_client_config)
    .create_unbootstrapped()
    .context("Error creating Tor Client.")?;

    // Define the TLS provider.
    // This method returns the default TLS provider based on the feature flags.
    let tls_provider = arti_ureq::get_default_tls_provider();

    // You can also manually set the TLS provider.
    // let tls_provider = arti_ureq::ureq::tls::TlsProvider::Rustls; // To use Rustls.
    // let tls_provider = arti_ureq::ureq::tls::TlsProvider::NativeTls; // To use NativeTls.

    // Build arti_ureq::Connector.
    let connector_builder =
        arti_ureq::Connector::<arti_ureq::tor_rtcompat::PreferredRuntime>::builder()
            .context("Failed to create ConnectorBuilder")?
            .tor_client(tor_client) // Set Tor client.
            .tls_provider(tls_provider); // Set TLS provider.

    // Build ureq TLS config.
    let ureq_tls_config = arti_ureq::ureq::tls::TlsConfig::builder()
        .root_certs(RootCerts::PlatformVerifier)
        .provider(tls_provider) // TLS provider in ureq config must match the one in Connector.
        .build();

    // Build ureq config.
    let ureq_config = arti_ureq::ureq::config::Config::builder()
        .user_agent("arti-ureq-custom-user-agent")
        .tls_config(ureq_tls_config)
        .build();

    // Get ureq agent with ureq_config.
    let ureq_agent = connector_builder
        .build()
        .context("Failed to build Connector")?
        .agent_with_ureq_config(ureq_config)
        .context("Failed to create ureq agent.")?;

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
