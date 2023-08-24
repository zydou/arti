//! Very very very basic soak test that runs obfs4proxy.

use anyhow::Result;
use tor_ptmgr::ipc::{
    PluggableClientTransport, PluggableTransport, PtClientParameters, PtCommonParameters,
};
use tor_rtcompat::PreferredRuntime;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let common_params = PtCommonParameters::builder()
        .state_location("/tmp/arti-pt".into())
        .build()
        .unwrap();
    let client_params = PtClientParameters::builder()
        .transports(vec!["obfs4".parse().unwrap()])
        .build()
        .unwrap();
    let mut pt =
        PluggableClientTransport::new("./obfs4proxy".into(), vec![], common_params, client_params);
    pt.launch(PreferredRuntime::current()?).await?;
    loop {
        info!("message: {:?}", pt.next_message().await?);
    }
}
