// TODO #1645 (either remove this, or decide to have it everywhere)
#![cfg_attr(not(all(feature = "full", feature = "experimental")), allow(unused))]

use anyhow::Result;
use std::ops::Deref;
use std::sync::Arc;
use tokio_crate as tokio;
use tracing_subscriber::{filter, prelude::*};

use arti_client::{TorClient, TorClientConfig};
use tor_netdir::{NetDir, Relay};
use tor_relay_selection::{RelayExclusion, RelaySelector, RelayUsage};
use tor_rtcompat::Runtime;

/// Find a random relay suitable to use for a directory request.
fn find_one_hop_dir_cache(netdir: &NetDir) -> Option<Relay> {
    let mut rng = rand::thread_rng();
    let exclusion = RelayExclusion::no_relays_excluded();
    let selector = RelaySelector::new(RelayUsage::directory_cache(), exclusion);
    let (relay, _info) = selector.select_relay(&mut rng, netdir);

    relay
}

/// Launch one-hop circuit using a random relay suitable for a directory
/// request.
#[cfg(all(feature = "experimental-api", feature = "full"))]
async fn launch_one_hop_dir_circ<R: Runtime>(
    arti_client: &arti_client::TorClient<R>,
) -> Result<()> {
    let netdir = arti_client.dirmgr().timely_netdir().unwrap();

    let relay = find_one_hop_dir_cache(&netdir);

    if let Some(relay) = relay {
        let fp = relay.rsa_id().to_string();

        let circuit = arti_client.circmgr().deref();
        let one_hop_circ = circuit.get_or_launch_dir_specific(&relay).await;
        match one_hop_circ {
            Err(e) => println!("[-] Unable to launch one-hop circuit: {}", e),
            Ok(_) => println!("[+] Successful one-hop circuit to: {:?}", fp),
        };
    } else {
        println!("Could not find a relay suitable for a directory request.");
    }
    Ok(())
}

#[cfg(all(feature = "experimental-api", feature = "full"))]
#[tokio::main]
/// Example using `arti_client::TorClient`
/// and `tor_circmgr::get_or_launch_dir_specific` to launch a one-hop circuit
/// with a random relay suitable for it.
async fn main() -> Result<()> {
    let stdout_log = tracing_subscriber::fmt::layer().pretty();
    tracing_subscriber::registry()
        .with(stdout_log.with_filter(filter::LevelFilter::DEBUG))
        .init();
    let config = TorClientConfig::default();
    let arti_client = Arc::new(TorClient::create_bootstrapped(config).await?);
    launch_one_hop_dir_circ(&arti_client).await
}

#[cfg(not(all(feature = "experimental-api", feature = "full")))]
pub fn main() {
    panic!("this example can only run with features `full` and `experimental-api` enabled");
}
