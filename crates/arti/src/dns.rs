//! Implement a simple DNS resolver that relay request over Tor.
//!
//! A resolver is launched with [`run_dns_resolver()`], which listens for new
//! connections and then runs

use arti_client::TorClient;
use tor_rtcompat::Runtime;

use anyhow::Result;

/// Launch a DNS resolver to lisetn on a given local port, and run
/// indefinitely.
pub(crate) async fn run_dns_resolver<R: Runtime>(
    runtime: R,
    _tor_client: TorClient<R>,
    _dns_port: u16,
) -> Result<()> {
    loop {
        runtime.sleep(std::time::Duration::from_secs(5)).await;
    }
}
