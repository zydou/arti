#![warn(clippy::missing_docs_in_private_items)]
//! # connection-checker
//! Use methods to test connections to Tor: directly or by using
//! pluggable transports snowflake, obfs4, and meek
//!
//! ### Intro
//! This project aims to illustrate how to make connections to Tor using
//! different methods, and uses those to create a tool that users can run
//! to see if they can connect to the Tor network in any way from their own
//! networks.
//!
//! For more info on pluggable transports, you can refer to
//! [these docs](https://tb-manual.torproject.org/circumvention/)
//!
//! ### Usage
//! Run the program:
//! `cargo run`
//!
//! By default only a direct Tor connection is tested. In order to test
//! other pluggable transports, we can pass the path to the PT binary to the
//! program.
//!
//! For example, if you wished to test an obfs4 and snowflake connection,
//! pass `--snowflake-path snowflake-client --obfs4-client lyrebird`,
//! where `lyrebird` is the path to the obfs4 pluggable transport binary
//! and `snowflake-client` is the Snowflake counterpart
//!
//! You can also optionally specify a different host:port than the default `torproject.org:80`
//! to be tested by passing the value using the `--connect-to` argument.
//!
//! For more information please refer to `cargo run -- --help`
//!
//! The program can test connections using snowflake, obfs4, and meek,
//! and thus requires the pluggable transports which are to be tested are already installed.
//! To install the pluggable transports, you can check your package manager
//! or build "lyrebird", "meek" and "snowflake" from source, obtainable
//! from the [corresponding Tor Project's GitLab repositories](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/)
//!
//! ### Disclaimer
//! The connection-checker is experimental, not for production use. It's
//! intended for experimental purposes, providing insights into
//! connection methods.
use anyhow::Result;
use arti_client::config::pt::TransportConfigBuilder;
use arti_client::config::{BridgeConfigBuilder, CfgPath, Reconfigure};
use arti_client::{TorClient, TorClientConfig};
use clap::Parser;
use tor_error::ErrorReport;
use tor_rtcompat::PreferredRuntime;
use tracing::{error, info};

/// Test connections to the Tor network via different methods
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Opts {
    /// Snowflake binary to use, implies Snowflake is to be tested
    #[arg(long, required = false, default_value = None)]
    snowflake_path: Option<String>,
    /// obfs4 binary to use, implies obfs4 is to be tested
    #[arg(long, required = false, default_value = None)]
    obfs4_path: Option<String>,
    /// meek binary to use, implies meek is to be tested
    #[arg(long, required = false, default_value = None)]
    meek_path: Option<String>,

    /// Specify a custom host:port to connect to for testing purposes
    #[arg(long, required = false, default_value = "torproject.org:80")]
    connect_to: String,
}

/// Denotes the connection type
enum ConnType {
    /// Snowflake
    Snowflake,
    /// obfs4
    Obfs4,
    /// Meek
    Meek,
    /// direct
    Direct,
}

/// Test bridge we will use for validating obfs4 connections
const OBFS4_BRIDGE_LINE: &str = include_str!("../bridges/bridge_obfs4.txt");
/// Test bridge we will use for validating snowflake connections
const SNOWFLAKE_BRIDGE_LINE: &str = include_str!("../bridges/bridge_snowflake.txt");
/// Test bridge we will use for validating meek connections
const MEEK_BRIDGE_LINE: &str = include_str!("../bridges/bridge_meek.txt");

/// Connect to a sample host and print the path it used to get there.
/// Note that due to the way Tor works, other requests may use a different
/// path than the one we obtain using this function, so this is mostly
/// for demonstration purposes.
async fn build_circuit(tor_client: &TorClient<PreferredRuntime>, remote: &str) -> bool {
    info!("Attempting to build circuit...");
    match tor_client.connect(remote).await {
        Ok(stream) => {
            let circ = stream.circuit().path_ref();
            for node in circ.iter() {
                println!("Node: {}", node);
            }
            true
        }
        Err(e) => {
            eprintln!("{}", e.report());
            false
        }
    }
}

/// Attempts to build a pluggable transport-enabled [TorClientConfig] using
/// the supplied data
fn build_pt_config(
    bridge_line: &str,
    protocol_name: &str,
    client_path: &str,
) -> Result<TorClientConfig> {
    let mut builder = TorClientConfig::builder();
    let bridge: BridgeConfigBuilder = bridge_line.parse()?;
    builder.bridges().bridges().push(bridge);
    let mut transport = TransportConfigBuilder::default();
    transport
        .protocols(vec![protocol_name.parse()?])
        .path(CfgPath::new(client_path.into()))
        .run_on_startup(true);
    builder.bridges().transports().push(transport);
    Ok(builder.build()?)
}

/// Reconfigure a given [TorClient] and try getting the circuit
async fn test_connection_via_config(
    tor_client: &TorClient<PreferredRuntime>,
    config: TorClientConfig,
    msg: &str,
    remote_url: &str,
) {
    let isolated = tor_client.isolated_client();
    println!("Testing {}...", msg);
    match isolated.reconfigure(&config, Reconfigure::WarnOnFailures) {
        Ok(_) => match build_circuit(&isolated, remote_url).await {
            true => println!("{} successful!", msg),
            false => println!("{} FAILED", msg),
        },
        Err(e) => {
            error!("{}", e.report());
            println!("{} FAILED", msg);
        }
    }
}

/// Main function ends up running most of the tests one by one
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let opts = Opts::parse();
    let initialconfig = TorClientConfig::default();
    let tor_client = TorClient::create_bootstrapped(initialconfig).await?;
    let mut tests = Vec::with_capacity(4);
    tests.push((ConnType::Direct, None));
    if let Some(path) = opts.snowflake_path {
        tests.push((ConnType::Snowflake, Some(path)));
    }
    if let Some(path) = opts.obfs4_path {
        tests.push((ConnType::Obfs4, Some(path)));
    }
    if let Some(path) = opts.meek_path {
        tests.push((ConnType::Meek, Some(path)));
    }
    for (connection_type, connection_bin_shared) in tests.iter() {
        // This will only go to the "or" condition if we have a direct connection
        // and that code doesn't use this variable anyway
        let connection_bin = connection_bin_shared.to_owned().unwrap_or(String::new());
        let (msg, config) = match connection_type {
            ConnType::Obfs4 => {
                let msg = "obfs4 Tor connection";
                (
                    msg,
                    build_pt_config(OBFS4_BRIDGE_LINE, "obfs4", &connection_bin)?,
                )
            }
            ConnType::Snowflake => {
                let msg = "Snowflake Tor connection";
                (
                    msg,
                    build_pt_config(SNOWFLAKE_BRIDGE_LINE, "snowflake", &connection_bin)?,
                )
            }
            ConnType::Meek => {
                let msg = "Meek Tor connection";
                (
                    msg,
                    build_pt_config(MEEK_BRIDGE_LINE, "meek", &connection_bin)?,
                )
            }
            ConnType::Direct => {
                let msg = "direct Tor connection";
                (msg, TorClientConfig::default())
            }
        };
        test_connection_via_config(&tor_client, config, msg, &opts.connect_to).await;
    }
    Ok(())
}
