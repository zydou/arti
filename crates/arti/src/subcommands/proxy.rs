//! The `proxy` subcommand.

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::ArgMatches;
#[allow(unused)]
use tor_config_path::CfgPathResolver;
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

    if !socks_listen.is_empty() {
        info!(
            "Starting Arti {} in SOCKS proxy mode on {} ...",
            env!("CARGO_PKG_VERSION"),
            socks_listen
        );
    }

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

    // TODO RPC: We may instead want to provide a way to get these items out of TorClient.
    #[allow(unused)]
    let fs_mistrust = client_config.fs_mistrust().clone();
    #[allow(unused)]
    let path_resolver: CfgPathResolver = AsRef::<CfgPathResolver>::as_ref(&client_config).clone();

    let client_builder = TorClient::with_runtime(runtime.clone())
        .config(client_config)
        .bootstrap_behavior(OnDemand);
    let client = client_builder.create_unbootstrapped_async().await?;

    #[allow(unused_mut)]
    let mut reconfigurable_modules: Vec<Arc<dyn reload_cfg::ReconfigurableModule>> = vec![
        Arc::new(client.clone()),
        Arc::new(reload_cfg::Application::new(arti_config.clone())),
    ];

    cfg_if::cfg_if! {
        if #[cfg(feature = "onion-service-service")] {
            let onion_services =
                onion_proxy::ProxySet::launch_new(&client, arti_config.onion_services.clone())?;
            let launched_onion_svc = !onion_services.is_empty();
            reconfigurable_modules.push(Arc::new(onion_services));
        } else {
            let launched_onion_svc = false;
        }
    };

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

    #[cfg(feature = "rpc")]
    let rpc_data = {
        rpc::launch_rpc_mgr(
            &runtime,
            &arti_config.rpc,
            &path_resolver,
            &fs_mistrust,
            client.clone(),
        )
        .await?
    };

    let mut proxy: Vec<PinnedFuture<(Result<()>, &str)>> = Vec::new();
    if !socks_listen.is_empty() {
        let runtime = runtime.clone();
        let client = client.isolated_client();
        let socks_listen = socks_listen.clone();
        proxy.push(Box::pin(async move {
            let res = socks::run_socks_proxy(
                runtime,
                client,
                socks_listen,
                #[cfg(feature = "rpc")]
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
        if !launched_onion_svc {
            warn!("No proxy port set; specify -p PORT (for `socks_port`) or -d PORT (for `dns_port`). Alternatively, use the `socks_port` or `dns_port` configuration option.");
            return Ok(());
        } else {
            // Push a dummy future to appease future::select_all,
            // which expects a non-empty list
            proxy.push(Box::pin(futures::future::pending()));
        }
    }

    let proxy = futures::future::select_all(proxy).map(|(finished, _index, _others)| finished);
    futures::select!(
        r = exit::wait_for_ctrl_c().fuse()
            => r.context("waiting for termination signal"),
        r = proxy.fuse()
            => r.0.context(format!("{} proxy failure", r.1)),
        r = async {
            client.bootstrap().await?;
            if !socks_listen.is_empty() {
                info!("Sufficiently bootstrapped; system SOCKS now functional.");
            } else {
                info!("Sufficiently bootstrapped.");
            }
            futures::future::pending::<Result<()>>().await
        }.fuse()
            => r.context("bootstrap"),
    )?;

    // The modules can be dropped now, because we are exiting.
    drop(reconfigurable_modules);

    Ok(())
}
