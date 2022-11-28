//! Very very very basic soak test that runs obfs4proxy.

use anyhow::Result;
use tor_ptmgr::ipc::{PluggableTransport, PtParameters};
use tor_rtcompat::PreferredRuntime;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let params = PtParameters::builder()
        .state_location("/tmp/arti-pt".into())
        .transports(vec!["obfs4".parse().unwrap()])
        .build()
        .unwrap();
    let mut pt = PluggableTransport::new("./obfs4proxy".into(), vec![], params);
    pt.launch(PreferredRuntime::current()?).await?;
    loop {
        info!("message: {:?}", pt.next_message().await?);
    }
}
