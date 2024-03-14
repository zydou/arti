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

#[cfg(feature = "pt-client")]
use {anyhow::Result, tokio_crate as tokio};

#[cfg(feature = "pt-client")]
#[tokio::main]
async fn main() -> Result<()> {
    use arti_client::config::pt::TransportConfigBuilder;
    use arti_client::config::{BridgeConfigBuilder, CfgPath};
    use arti_client::{TorClient, TorClientConfig};

    use futures::io::{AsyncReadExt, AsyncWriteExt};

    // Arti uses the `tracing` crate for logging. Install a handler for this, to print Arti's logs.
    tracing_subscriber::fmt::init();

    let mut builder = TorClientConfig::builder();

    // Add a single bridge to the list of bridges, from a bridge line.
    // This line comes from https://gitlab.torproject.org/tpo/applications/tor-browser-build/-/blob/main/projects/common/bridges_list.snowflake.txt
    // this is a real bridge line you can use as-is, after making sure it's still up to date with
    // above link.
    const BRIDGE1_LINE : &str = "Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://snowflake-broker.torproject.net.global.prod.fastly.net/ front=cdn.sstatic.net ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478,stun:stun.sonetel.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.voys.nl:3478 utls-imitate=hellorandomizedalpn";
    let bridge_1: BridgeConfigBuilder = BRIDGE1_LINE.parse()?;
    builder.bridges().bridges().push(bridge_1);

    // Add a second bridge, built by hand. We use the 2nd bridge line from above, but modify some
    // parameters to use AMP Cache instead of Fastly as a signaling channel. The difference in
    // configuration is detailed in
    // https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/tree/main/client#amp-cache
    let mut bridge2_builder = BridgeConfigBuilder::default();
    bridge2_builder
        .transport("snowflake")
        .push_setting(
            "fingerprint",
            "8838024498816A039FCBBAB14E6F40A0843051FA"
        )
        .push_setting("url", "https://snowflake-broker.torproject.net/")
        .push_setting("ampcache", "https://cdn.ampproject.org/")
        .push_setting("front", "www.google.com")
        .push_setting(
            "ice",
            "stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478,stun:stun.sonetel.net:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.voys.nl:3478",
        )
        .push_setting("utls-imitate", "hellorandomizedalpn");
    bridge2_builder.set_addrs(vec!["192.0.2.4:80".parse()?]);
    bridge2_builder.set_ids(vec!["8838024498816A039FCBBAB14E6F40A0843051FA".parse()?]);
    // Now insert the second bridge into our config builder.
    builder.bridges().bridges().push(bridge2_builder);

    // Now configure an snowflake transport. (Requires the "pt-client" feature)
    let mut transport = TransportConfigBuilder::default();
    transport
        .protocols(vec!["snowflake".parse()?])
        // this might be named differently on some systems, this should work on Debian, but Archlinux is known to use `snowflake-pt-client` instead for instance.
        .path(CfgPath::new("snowflake-client".into()))
        .run_on_startup(true);
    builder.bridges().transports().push(transport);

    let config = builder.build()?;

    eprintln!("connecting to Tor...");

    // We now let the Arti client start and bootstrap a connection to the network.
    // (This takes a while to gather the necessary consensus state, etc.)
    let tor_client = TorClient::create_bootstrapped(config).await?;

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

#[cfg(not(feature = "pt-client"))]
pub fn main() {
    panic!("this example can only run with feature `pt-client` enabled");
}
