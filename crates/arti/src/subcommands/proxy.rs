//! The `proxy` subcommand.

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::ArgMatches;
use tracing::{info, warn};

use arti_client::TorClientConfig;
use tor_config::{ConfigurationSources, Listen};
use tor_rtcompat::Runtime;

#[cfg(feature = "dns-proxy")]
use crate::dns;
use crate::{exit, process, reload_cfg, socks, ArtiConfig, TorClient};

#[cfg(feature = "rpc")]
use crate::rpc;

#[cfg(feature = "onion-service-service")]
use crate::onion_proxy;

/// Shorthand for a boxed and pinned Future.
type PinnedFuture<T> = std::pin::Pin<Box<dyn futures::Future<Output = T>>>;

/// Run the `proxy` subcommand.
pub(crate) fn run<R: Runtime>(
    runtime: R,
    proxy_matches: &ArgMatches,
    cfg_sources: ConfigurationSources,
    config: ArtiConfig,
    client_config: TorClientConfig,
) -> Result<()> {
    // Override configured SOCKS and DNS listen addresses from the command line.
    // This implies listening on localhost ports.
    let socks_listen = match proxy_matches.get_one::<String>("socks-port") {
        Some(p) => Listen::new_localhost(p.parse().expect("Invalid port specified")),
        None => config.proxy().socks_listen.clone(),
    };

    let dns_listen = match proxy_matches.get_one::<String>("dns-port") {
        Some(p) => Listen::new_localhost(p.parse().expect("Invalid port specified")),
        None => config.proxy().dns_listen.clone(),
    };

    info!(
        "Starting Arti {} in SOCKS proxy mode on {} ...",
        env!("CARGO_PKG_VERSION"),
        socks_listen
    );

    process::use_max_file_limit(&config);

    let rt_copy = runtime.clone();
    rt_copy.block_on(run_proxy(
        runtime,
        socks_listen,
        dns_listen,
        cfg_sources,
        config,
        client_config,
    ))?;

    Ok(())
}

/// Run the main loop of the proxy.
///
/// # Panics
///
/// Currently, might panic if things go badly enough wrong
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental-api")))]
async fn run_proxy<R: Runtime>(
    runtime: R,
    socks_listen: Listen,
    dns_listen: Listen,
    config_sources: ConfigurationSources,
    arti_config: ArtiConfig,
    client_config: TorClientConfig,
) -> Result<()> {
    // Using OnDemand arranges that, while we are bootstrapping, incoming connections wait
    // for bootstrap to complete, rather than getting errors.
    use arti_client::BootstrapBehavior::OnDemand;
    use futures::FutureExt;

    #[cfg(feature = "rpc")]
    let rpc_path = {
        if let Some(path) = &arti_config.rpc().rpc_listen {
            let path = path.path()?;
            let parent = path
                .parent()
                .ok_or(anyhow::anyhow!("No parent directory for rpc_listen path?"))?;
            client_config
                .fs_mistrust()
                .verifier()
                .make_secure_dir(parent)?;
            // It's just a unix thing; if we leave this sitting around, binding to it won't
            // work right.  There is probably a better solution.
            if path.try_exists()? {
                std::fs::remove_file(&path)?;
            }

            Some(path)
        } else {
            None
        }
    };

    let client_builder = TorClient::with_runtime(runtime.clone())
        .config(client_config)
        .bootstrap_behavior(OnDemand);
    let client = client_builder.create_unbootstrapped_async().await?;

    #[allow(unused_mut)]
    let mut reconfigurable_modules: Vec<Arc<dyn reload_cfg::ReconfigurableModule>> = vec![
        Arc::new(client.clone()),
        Arc::new(reload_cfg::Application::new(arti_config.clone())),
    ];

    #[cfg(feature = "onion-service-service")]
    {
        let onion_services =
            onion_proxy::ProxySet::launch_new(&client, arti_config.onion_services.clone())?;
        reconfigurable_modules.push(Arc::new(onion_services));
    }

    // We weak references here to prevent the thread spawned by watch_for_config_changes from
    // keeping these modules alive after this function exits.
    //
    // NOTE: reconfigurable_modules stores the only strong references to these modules,
    // so we must keep the variable alive until the end of the function
    let weak_modules = reconfigurable_modules.iter().map(Arc::downgrade).collect();
    reload_cfg::watch_for_config_changes(
        client.runtime(),
        config_sources,
        &arti_config,
        weak_modules,
    )?;

    #[cfg(all(feature = "rpc", feature = "tokio"))]
    let rpc_data = {
        // TODO RPC This code doesn't really belong here; it's just an example.
        if let Some(listen_path) = rpc_path {
            let (rpc_state, rpc_state_sender) = rpc::RpcVisibleArtiState::new();
            // TODO Conceivably this listener belongs on a renamed "proxy" list.
            let rpc_mgr =
                rpc::launch_rpc_listener(&runtime, listen_path, client.clone(), rpc_state)?;
            Some((rpc_mgr, rpc_state_sender))
        } else {
            None
        }
    };

    let mut proxy: Vec<PinnedFuture<(Result<()>, &str)>> = Vec::new();
    if !socks_listen.is_empty() {
        let runtime = runtime.clone();
        let client = client.isolated_client();
        proxy.push(Box::pin(async move {
            let res = socks::run_socks_proxy(
                runtime,
                client,
                socks_listen,
                #[cfg(all(feature = "rpc", feature = "tokio"))]
                rpc_data,
            )
            .await;
            (res, "SOCKS")
        }));
    }

    #[cfg(feature = "dns-proxy")]
    if !dns_listen.is_empty() {
        let runtime = runtime.clone();
        let client = client.isolated_client();
        proxy.push(Box::pin(async move {
            let res = dns::run_dns_resolver(runtime, client, dns_listen).await;
            (res, "DNS")
        }));
    }

    #[cfg(not(feature = "dns-proxy"))]
    if !dns_listen.is_empty() {
        warn!(
            "Tried to specify a DNS proxy address, but Arti was built without dns-proxy support."
        );
        return Ok(());
    }

    if proxy.is_empty() {
        warn!("No proxy port set; specify -p PORT (for `socks_port`) or -d PORT (for `dns_port`). Alternatively, use the `socks_port` or `dns_port` configuration option.");
        return Ok(());
    }

    let proxy = futures::future::select_all(proxy).map(|(finished, _index, _others)| finished);
    futures::select!(
        r = exit::wait_for_ctrl_c().fuse()
            => r.context("waiting for termination signal"),
        r = proxy.fuse()
            => r.0.context(format!("{} proxy failure", r.1)),
        r = async {
            client.bootstrap().await?;
            info!("Sufficiently bootstrapped; system SOCKS now functional.");
            futures::future::pending::<Result<()>>().await
        }.fuse()
            => r.context("bootstrap"),
    )?;

    // The modules can be dropped now, because we are exiting.
    drop(reconfigurable_modules);

    Ok(())
}
