//! Code to watch configuration files for any changes.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use anyhow::Context;
use arti_client::TorClient;
use arti_client::config::Reconfigure;
use futures::StreamExt;
use futures::stream::BoxStream;
use futures::{FutureExt as _, Stream, select_biased};
use tor_basic_utils::error_sources::ErrorSources;
#[cfg(feature = "rpc")]
use tor_config::ConfigurationTree;
use tor_config::ReconfigureError;
use tor_config::file_watcher::{
    self, FileEventReceiver, FileEventSender, FileWatcher, FileWatcherBuilder,
};
use tor_config::load::{ConfigResolveOptions, DisfavouredKey};
use tor_config::{ConfigurationSource, ConfigurationSources, sources::FoundConfigFiles};
#[cfg(feature = "harden")]
use tor_error::into_internal;
use tor_error::warn_report;
use tor_rtcompat::Runtime;
use tor_rtcompat::SpawnExt;
use tracing::{debug, error, info, instrument, warn};

#[cfg(target_family = "unix")]
use crate::process::sighup_stream;

#[cfg(not(target_family = "unix"))]
use futures::stream;

use crate::{ArtiCombinedConfig, ArtiConfig};

/// How long to wait after an event got received, before we try to process it.
const DEBOUNCE_INTERVAL: Duration = Duration::from_secs(1);

/// An object that can be reconfigured when our configuration changes.
///
/// We use this trait so that we can represent abstract modules in our
/// application, and pass the configuration to each of them.
//
// TODO: It is very likely we will want to refactor this even further once we
// have a notion of what our modules truly are.
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) trait ReconfigurableModule: Send + Sync {
    /// Try to reconfigure this module according to a newly loaded configuration.
    ///
    /// See [`Reconfigure`] for a description of error-handling behavior.
    fn reconfigure(
        &self,
        new: &ArtiCombinedConfig,
        how: Reconfigure,
    ) -> Result<(), ReconfigureError>;
}

/// Structure to reload configuration as necessary.
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) struct CfgMgr<R> {
    /// A runtime that we use when constructing [`FileWatcher`]s.
    runtime: R,

    /// The sources from which we read our configuration.
    sources: ConfigurationSources,

    /// A sender to use when constructing new [`FileWatcher`]s.
    tx: FileEventSender,

    /// Mutable state.
    inner: Mutex<CfgMgrInner>,
}

/// Mutable part of a CfgMgr.
#[derive(Default)]
struct CfgMgrInner {
    /// A list of modules to alert whenever the configuration has changed.
    modules: Vec<Weak<dyn ReconfigurableModule>>,

    /// If present, a [`FileWatcher`] that is currently watching for changes
    /// in the configuration files and directories.
    watcher: Option<FileWatcher>,

    /// RPC only: a fully populated, normalized configuration tree, based on the most recent time
    /// that we called [`CfgMgr::reload_configuration`].
    #[cfg(feature = "rpc")]
    normalized_cfg: ConfigurationTree,

    /// RPC only: a set of unrecognized options from the configuration.
    #[cfg(feature = "rpc")]
    unrecognized_keys: HashSet<DisfavouredKey>,

    /// RPC only: a set of deprecated options from the configuration
    #[cfg(feature = "rpc")]
    deprecated_keys: HashSet<DisfavouredKey>,
}

/// A watcher process that we have not yet launched.
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
#[must_use = "UnlaunchedWatcher does nothing unless you launch it."]
pub(crate) struct UnlaunchedWatcher<R> {
    /// The related [`CfgMgr`] that we should tell about reconfiguration events.
    weak_mgr: Weak<CfgMgr<R>>,

    /// A stream on which we will get alerts about SIGHUP events.
    sighup_stream: BoxStream<'static, ()>,

    /// A stream that will tell us when our files are changed.
    watcher_rx: FileEventReceiver,

    /// An interval that we wait to debounce events from watcher_rx or sighup_stream.
    debounce_interval: Option<Duration>,

    /// If true, we start watching for file changes immediately at launch.
    watch_files_at_start: bool,
}

impl<R: Runtime> CfgMgr<R> {
    /// Construct a new CfgMgr, and launch a task to watch for any events
    /// that mean we have to reload our configuration.
    ///
    /// If the provided configuration requires it, watch for changes in `sources`
    /// and try to reload our configuration. On unix platforms, also watch
    /// for SIGHUP and reload configuration then.
    ///
    /// The modules are `Weak` references to prevent this background task
    /// from keeping them alive.
    ///
    /// See the [`FileWatcher`](FileWatcher#Limitations) docs for limitations.
    #[cfg_attr(feature = "experimental-api", visibility::make(pub))]
    #[instrument(level = "trace", skip_all)]
    pub(crate) fn new(
        runtime: R,
        sources: ConfigurationSources,
        config: &ArtiConfig,
        modules: Vec<Weak<dyn ReconfigurableModule>>,
    ) -> anyhow::Result<(Arc<Self>, UnlaunchedWatcher<R>)> {
        let (tx, rx) = file_watcher::channel();
        let mgr = Arc::new(CfgMgr {
            runtime,
            sources,
            tx,
            inner: Mutex::new(CfgMgrInner {
                modules,
                ..Default::default()
            }),
        });

        cfg_if::cfg_if! {
            if #[cfg(target_family = "unix")] {
                let sighup_stream = sighup_stream()?;
            } else {
                let sighup_stream = stream::pending();
            }
        }
        let sighup_stream = sighup_stream.boxed();

        let watcher = UnlaunchedWatcher {
            weak_mgr: Arc::downgrade(&mgr),
            sighup_stream,
            watcher_rx: rx,
            debounce_interval: Some(DEBOUNCE_INTERVAL),
            watch_files_at_start: config.application().watch_configuration,
        };

        Ok((mgr, watcher))
    }

    /// Create a new [`FileWatcher`] for the files in this configuration.
    ///
    /// Return it, along with the set of files we found.
    ///
    /// The caller is responsible for storing the `FileWatcher`; when it is dropped,
    /// it stops watching.
    fn launch_file_watcher(&self) -> anyhow::Result<(FileWatcher, FoundConfigFiles<'_>)> {
        let mut watcher = FileWatcher::builder(self.runtime.clone());
        let found_files = prepare(&mut watcher, &self.sources)?;
        let watcher = watcher.start_watching(self.tx.clone())?;
        Ok((watcher, found_files))
    }

    /// Reload the configuration.
    #[instrument(level = "trace", skip_all)]
    #[cfg_attr(feature = "experimental-api", visibility::make(pub))]
    pub(crate) fn reload_configuration(&self, how: Reconfigure) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().expect("Lock poisoned");
        let _ = how; // XXXX Actually use how.

        // Question: I do not understand why we are making a new file watcher unconditionally
        // at this point. -nm
        let (found_files, new_watcher) = if inner.watcher.is_some() {
            let (watcher, files) = self
                .launch_file_watcher()
                .context("Failed to re-scan config")?;
            (files, Some(watcher))
        } else {
            let files = self
                .sources
                .scan()
                .context("FS watch: failed to rescan config")?;
            (files, None)
        };

        let config = found_files.load()?;

        // XXXX: Use `how` more sensibly here; pick a better how.
        match reconfigure(config, &mut inner, Reconfigure::WarnOnFailures) {
            Ok(watch) => {
                info!("Successfully reloaded configuration.");
                if watch && inner.watcher.is_none() {
                    info!("Starting watching over configuration.");
                    let (watcher, _files) = self
                        .launch_file_watcher()
                        .context("Starting to watch over config")?;
                    inner.watcher = Some(watcher);
                } else if !watch && inner.watcher.is_some() {
                    info!("Stopped watching over configuration.");
                    inner.watcher = None;
                } else {
                    inner.watcher = new_watcher;
                }
            }
            Err(e) => warn_report!(e, "Couldn't reload configuration"),
        }

        Ok(())
    }
}

impl<R: Runtime> UnlaunchedWatcher<R> {
    /// Begin running the file watcher task for a given configuration manager.
    #[cfg_attr(feature = "experimental-api", visibility::make(pub))]
    #[instrument(level = "trace", skip_all)]
    pub(crate) fn launch(self) -> anyhow::Result<()> {
        let UnlaunchedWatcher {
            weak_mgr,
            sighup_stream,
            watcher_rx,
            debounce_interval,
            watch_files_at_start,
        } = self;
        let Some(mgr) = weak_mgr.upgrade() else {
            return Err(anyhow::anyhow!(
                "CfgMgr disappeared before we could launch the monitor task"
            ));
        };

        let rt = mgr.runtime.clone();
        let weak_mgr = Arc::downgrade(&mgr);
        mgr.runtime
            .spawn(async move {
                let res: anyhow::Result<()> =
                    run_watcher(rt, watcher_rx, sighup_stream, weak_mgr, debounce_interval).await;
                match res {
                    Ok(()) => debug!("Config watcher task exiting"),
                    // TODO: warn_report does not work on anyhow::Error.
                    Err(e) => error!("Config watcher task exiting: {}", tor_error::Report(e)),
                }
            })
            .context("failed to spawn task")?;

        if watch_files_at_start {
            // Note: You might think that there was a race condition here, where launching the
            // watcher _now_ would fail to catch any file changes that had happened between
            // reading the configuration initially and now.
            //
            // You'd be right, except that the [`FileWatcher`] code starts every new FileWatcher
            // with a pending `rescan` event.
            let (watcher, _files) = mgr.launch_file_watcher()?;
            mgr.inner.lock().expect("lock poisoned").watcher = Some(watcher);
        }

        Ok(())
    }

    /// Add `module` to the set of modules that need to be reconfigured when the configuration changes.
    ///
    /// This method is on the [`UnlaunchedWatcher`] because is not (yet) meant to be called after
    /// the watcher task is launched.
    #[cfg_attr(feature = "experimental-api", visibility::make(pub))]
    pub(crate) fn add_module(&self, module: &Arc<dyn ReconfigurableModule>) -> anyhow::Result<()> {
        let weak_module = Arc::downgrade(module);

        let Some(mgr) = self.weak_mgr.upgrade() else {
            return Err(anyhow::anyhow!(
                "CfgMgr disappeared before launching watcher task."
            ));
        };

        let mut inner = mgr.inner.lock().expect("poisoned lock");
        inner.modules.push(weak_module);
        Ok(())
    }
}

/// Start watching for configuration changes.
///
/// Spawned from [`UnlaunchedWatcher::launch`].
#[instrument(level = "trace", skip_all)]
async fn run_watcher<R: Runtime>(
    runtime: R,
    mut rx: FileEventReceiver,
    mut sighup_stream: impl Stream<Item = ()> + Unpin,
    weak_mgr: Weak<CfgMgr<R>>,
    debounce_interval: Option<Duration>,
) -> anyhow::Result<()> {
    debug!("Entering FS event loop");

    loop {
        select_biased! {
            event = sighup_stream.next().fuse() => {
                let Some(()) = event else {
                    break;
                };

                info!("Received SIGHUP");
            },
            event = rx.next().fuse() => {
                if let Some(debounce_interval) = debounce_interval {
                    runtime.sleep(debounce_interval).await;
                }

                while let Some(_ignore) = rx.try_recv() {
                    // Discard other events, so that we only reload once.
                    //
                    // We can afford to treat both error cases from try_recv [Empty
                    // and Disconnected] as meaning that we've discarded other
                    // events: if we're disconnected, we'll notice it when we next
                    // call recv() in the outer loop.
                }
                debug!("Config reload event {:?}: reloading configuration.", event);
            },
        }

        if let Some(mgr) = weak_mgr.upgrade() {
            mgr.reload_configuration(Reconfigure::WarnOnFailures)?;
            drop(mgr);
        } else {
            debug!("Configuration mgr disappeared; exiting loop");
            break;
        }
    }

    Ok(())
}

/// A TorClient that we may or may not have told to start bootstrapping.
pub(crate) struct LaunchableTorClient<R: Runtime> {
    /// Original value of defer_bootstrap.
    orig_defer_bootstrap: bool,

    /// True if we have launched bootstrapping on the the client.
    have_launched: Mutex<bool>,

    /// The client itself.
    client: Arc<TorClient<R>>,
}

impl<R: Runtime> ReconfigurableModule for LaunchableTorClient<R> {
    #[instrument(level = "trace", skip_all)]
    fn reconfigure(
        &self,
        new: &ArtiCombinedConfig,
        how: Reconfigure,
    ) -> Result<(), ReconfigureError> {
        if how == Reconfigure::AllOrNothing {
            // If we're in all-or-nothing mode, we check it first.
            self.reconfigure(new, Reconfigure::CheckAllOrNothing)?;
        }
        let dry_run = how == Reconfigure::CheckAllOrNothing;

        if new.0.application().defer_bootstrap && !self.orig_defer_bootstrap {
            how.cannot_change_specific("defer_bootstrap", "from off to on")?;
        }
        if !dry_run && !new.0.application().defer_bootstrap {
            self.ensure_bootstrap_launched()
                .map_err(into_internal!("Unable to launch client bootstrap"))?;
        }

        TorClient::reconfigure(&self.client, &new.1, how).map_err(extract_reconfigure_error)?;
        Ok(())
    }
}

/// If possible, extract the ReconfigureError from `err`.  Otherwise,
/// return `err` as an internal ReconfigureError.
//
// (We could get rid of this function if arti_client::Error were not opaque,
// or if arti_client::reconfigure were to return a ReconfigureError.
// But  now is not the time to revisit those decisions.)
fn extract_reconfigure_error(err: arti_client::Error) -> ReconfigureError {
    for e in ErrorSources::new(&err) {
        if let Some(reconfig_error) = e.downcast_ref::<ReconfigureError>() {
            return reconfig_error.clone();
        };
    }
    (into_internal!("Foo")(err)).into()
}

impl<R: Runtime> LaunchableTorClient<R> {
    /// Create a new LaunchableTorClient.
    ///
    /// We assume that it has (or has not) been told to bootstrap itself based on `cfg`.
    pub(crate) fn new(client: Arc<TorClient<R>>, cfg: &crate::ApplicationConfig) -> Self {
        Self {
            orig_defer_bootstrap: cfg.defer_bootstrap,
            have_launched: Mutex::new(!cfg.defer_bootstrap),
            client,
        }
    }

    /// If we have not already told this LaunchableTorClient to bootstrap itself, do so.
    fn ensure_bootstrap_launched(&self) -> Result<(), futures::task::SpawnError> {
        let mut have_launched = self.have_launched.lock().expect("lock poisoned");

        if *have_launched {
            return Ok(());
        }

        let client = Arc::clone(&self.client);
        // We spawn this as a new task since `bootstrap` is very much async,
        // but this needs to be called from `reconfigure`, which is not.
        self.client.runtime().spawn(async move {
            let _outcome = client.bootstrap().await;
        })?;

        *have_launched = true;
        Ok(())
    }

    /// As [`TorClient::bootstrap`], but performs necessary bookkeeping to remember
    /// that we have launched a bootstrap attempt.
    pub(crate) async fn bootstrap(&self) -> arti_client::Result<()> {
        *self.have_launched.lock().expect("lock poisoned") = true;

        self.client.bootstrap().await
    }
}

/// Internal type to represent the Arti application as a `ReconfigurableModule`.
pub(crate) struct Application {
    /// The configuration that Arti had at startup.
    ///
    /// We use this to check whether the user is asking for any impermissible
    /// transitions.
    original_config: ArtiConfig,
}

impl Application {
    /// Construct a new `Application` to receive configuration changes for the
    /// arti application.
    pub(crate) fn new(cfg: ArtiConfig) -> Self {
        Self {
            original_config: cfg,
        }
    }
}

impl ReconfigurableModule for Application {
    #[instrument(level = "trace", skip_all)]
    fn reconfigure(
        &self,
        new: &ArtiCombinedConfig,
        how: Reconfigure,
    ) -> Result<(), ReconfigureError> {
        if how == Reconfigure::AllOrNothing {
            // If we're in all-or-nothing mode, we check it first.
            self.reconfigure(new, Reconfigure::CheckAllOrNothing)?;
        }
        let dry_run = how == Reconfigure::CheckAllOrNothing;

        let original = &self.original_config;
        let config = &new.0;

        if config.proxy() != original.proxy() {
            how.cannot_change("proxy settings")?;
        }
        if config.logging() != original.logging() {
            how.cannot_change("logging")?;
        }
        #[cfg(feature = "rpc")]
        if config.rpc != original.rpc {
            how.cannot_change("RPC settings")?;
        }
        if config.application().permit_debugging && !original.application().permit_debugging {
            how.cannot_change_specific("application hardening", "from on to off")?;
        }
        // Note that this is the only config transition we actually perform so far.
        if !dry_run && !config.application().permit_debugging {
            #[cfg(feature = "harden")]
            crate::process::enable_process_hardening()
                .map_err(into_internal!("can't disable debugging"))?;
        }

        Ok(())
    }
}

/// Find the configuration files and prepare the watcher
fn prepare<'a, R: Runtime>(
    watcher: &mut FileWatcherBuilder<R>,
    sources: &'a ConfigurationSources,
) -> anyhow::Result<FoundConfigFiles<'a>> {
    let sources = sources.scan()?;
    for source in sources.iter() {
        match source {
            ConfigurationSource::Dir(dir) => watcher.watch_dir(dir, "toml")?,
            ConfigurationSource::File(file) => watcher.watch_path(file)?,
            ConfigurationSource::Verbatim(_) => {}
        }
    }
    Ok(sources)
}

/// Reload the configuration files, apply the runtime configuration, and
/// reconfigure the client as much as we can.
///
/// Return true if we should be watching for configuration changes.
#[instrument(level = "trace", skip_all)]
fn reconfigure(
    config: ConfigurationTree,
    mgr_inner: &mut CfgMgrInner,
    how: Reconfigure,
) -> Result<bool, ChangeConfigurationError> {
    #[allow(unused_mut)]
    let mut resolve_options = ConfigResolveOptions::default();
    #[cfg(feature = "rpc")]
    {
        resolve_options.want_output_tree = true;
    }

    let rs = tor_config::resolve_return_results::<ArtiCombinedConfig>(config, &resolve_options)?;
    let config = rs.value;

    // Filter out the modules that have been dropped
    let reconfigurable: Vec<_> = mgr_inner.modules.iter().flat_map(Weak::upgrade).collect();
    let has_modules = !reconfigurable.is_empty();

    if how == Reconfigure::AllOrNothing {
        for module in &reconfigurable {
            module.reconfigure(&config, Reconfigure::CheckAllOrNothing)?;
        }
    }
    for module in &reconfigurable {
        module.reconfigure(&config, how)?;
    }

    #[cfg(feature = "rpc")]
    {
        mgr_inner.normalized_cfg = rs
            .output_tree
            .expect("normalized cfg not exposed as expected!?");
        mgr_inner.deprecated_keys = rs.deprecated.into_iter().collect();
        mgr_inner.unrecognized_keys = rs.unrecognized.into_iter().collect();
    }

    Ok(has_modules && config.0.application().watch_configuration)
}

/// An error that occurred while trying to reload and/or replace our configuration
#[derive(thiserror::Error, Clone, Debug)]
pub(crate) enum ChangeConfigurationError {
    /// We couldn't turn the configuration tree into the appropriate set of data structures.
    #[error("Invalid configuration")]
    Resolve(#[from] tor_config::load::ConfigResolveError),

    /// One of the transitions we tried to make was not allowed, or failed as we tried to apply it.
    #[error("Configuration transition failed")]
    Transition(#[from] ReconfigureError),
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use crate::ArtiConfigBuilder;

    use super::*;
    use futures::SinkExt as _;
    use futures::channel::mpsc;
    use postage::watch;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use test_temp_dir::{TestTempDir, test_temp_dir};
    use tor_async_utils::PostageWatchSenderExt;
    use tor_config::sources::MustRead;

    /// Filename for config1
    const CONFIG_NAME1: &str = "config1.toml";
    /// Filename for config2
    const CONFIG_NAME2: &str = "config2.toml";
    /// Filename for config3
    const CONFIG_NAME3: &str = "config3.toml";

    struct TestModule {
        // A sender for sending the new config to the test function
        tx: Arc<Mutex<watch::Sender<ArtiCombinedConfig>>>,
    }

    impl ReconfigurableModule for TestModule {
        fn reconfigure(
            &self,
            new: &ArtiCombinedConfig,
            _how: Reconfigure,
        ) -> Result<(), ReconfigureError> {
            let config = new.clone();
            self.tx.lock().unwrap().maybe_send(|_| config);

            Ok(())
        }
    }

    /// Create a test reconfigurable module.
    ///
    /// Returns the module and a channel on which the new configs received by the module are sent.
    async fn create_module() -> (
        Arc<dyn ReconfigurableModule>,
        watch::Receiver<ArtiCombinedConfig>,
    ) {
        let (tx, mut rx) = watch::channel();
        // Read the initial value from the postage::watch stream
        // (the first observed value on this test stream is always the default config)
        let _: ArtiCombinedConfig = rx.next().await.unwrap();

        (
            Arc::new(TestModule {
                tx: Arc::new(Mutex::new(tx)),
            }),
            rx,
        )
    }

    /// Write `data` to file `name` within `dir`.
    fn write_file(dir: &TestTempDir, name: &str, data: &[u8]) -> PathBuf {
        let tmp = dir.as_path_untracked().join("tmp");
        std::fs::write(&tmp, data).unwrap();
        let path = dir.as_path_untracked().join(name);
        // Atomically write the config file
        std::fs::rename(tmp, &path).unwrap();
        path
    }

    /// Write an `ArtiConfigBuilder` to a file within `dir`.
    fn write_config(dir: &TestTempDir, name: &str, config: &ArtiConfigBuilder) -> PathBuf {
        let s = toml::to_string(&config).unwrap();
        write_file(dir, name, s.as_bytes())
    }

    #[test]
    fn watch_single_file() {
        tor_rtcompat::test_with_one_runtime!(|rt| async move {
            let temp_dir = test_temp_dir!();
            let mut config_builder = ArtiConfigBuilder::default();
            config_builder.application().watch_configuration(true);

            let cfg_file = write_config(&temp_dir, CONFIG_NAME1, &config_builder);
            let mut cfg_sources = ConfigurationSources::new_empty();
            cfg_sources.push_source(ConfigurationSource::File(cfg_file), MustRead::MustRead);

            let (module, mut rx) = create_module().await;

            config_builder.logging().log_sensitive_information(true);
            let _: PathBuf = write_config(&temp_dir, CONFIG_NAME1, &config_builder);

            let (fw_tx, fw_rx) = file_watcher::channel();
            let mgr = Arc::new(CfgMgr {
                runtime: rt.clone(),
                sources: cfg_sources,
                tx: fw_tx,
                inner: Mutex::new(CfgMgrInner {
                    modules: vec![Arc::downgrade(&module)],
                    ..Default::default()
                }),
            });

            let (watcher, _) = mgr.launch_file_watcher().unwrap();
            mgr.inner.lock().unwrap().watcher = Some(watcher);
            let weak_mgr = Arc::downgrade(&mgr);

            // Use a fake sighup stream to wait until run_watcher()'s select_biased!
            // loop is entered
            let (mut sighup_tx, sighup_rx) = mpsc::unbounded();
            let runtime = rt.clone();
            let () = rt
                .spawn(async move {
                    run_watcher(runtime.clone(), fw_rx, sighup_rx, weak_mgr, None)
                        .await
                        .unwrap();
                })
                .unwrap();

            sighup_tx.send(()).await.unwrap();

            // The reconfigurable modules should've been reloaded in response to sighup
            let config = rx.next().await.unwrap();
            assert_eq!(config.0, config_builder.build().unwrap());

            // Overwrite the config
            config_builder.logging().log_sensitive_information(false);
            let _: PathBuf = write_config(&temp_dir, CONFIG_NAME1, &config_builder);
            // The reconfigurable modules should've been reloaded in response to the config change
            let config = rx.next().await.unwrap();
            assert_eq!(config.0, config_builder.build().unwrap());
        });
    }

    // TODO: Ignored until #1607 is fixed
    #[test]
    #[ignore]
    fn watch_multiple() {
        tor_rtcompat::test_with_one_runtime!(|rt| async move {
            let temp_dir = test_temp_dir!();
            let mut config_builder1 = ArtiConfigBuilder::default();
            config_builder1.application().watch_configuration(true);

            let _: PathBuf = write_config(&temp_dir, CONFIG_NAME1, &config_builder1);
            let mut cfg_sources = ConfigurationSources::new_empty();
            cfg_sources.push_source(
                ConfigurationSource::Dir(temp_dir.as_path_untracked().to_path_buf()),
                MustRead::MustRead,
            );

            let (module, mut rx) = create_module().await;

            let (fw_tx, fw_rx) = file_watcher::channel();
            let mgr = Arc::new(CfgMgr {
                runtime: rt.clone(),
                sources: cfg_sources,
                tx: fw_tx,
                inner: Mutex::new(CfgMgrInner {
                    modules: vec![Arc::downgrade(&module)],
                    ..Default::default()
                }),
            });

            let (watcher, _) = mgr.launch_file_watcher().unwrap();
            mgr.inner.lock().unwrap().watcher = Some(watcher);
            let weak_mgr = Arc::downgrade(&mgr);

            // Use a fake sighup stream to wait until run_watcher()'s select_biased!
            // loop is entered
            let (mut sighup_tx, sighup_rx) = mpsc::unbounded();
            let runtime = rt.clone();
            let () = rt
                .spawn(async move {
                    run_watcher(runtime.clone(), fw_rx, sighup_rx, weak_mgr, None)
                        .await
                        .unwrap();
                })
                .unwrap();

            config_builder1.logging().log_sensitive_information(true);
            let _: PathBuf = write_config(&temp_dir, CONFIG_NAME1, &config_builder1);
            sighup_tx.send(()).await.unwrap();
            // The reconfigurable modules should've been reloaded in response to sighup
            let config = rx.next().await.unwrap();
            assert_eq!(config.0, config_builder1.build().unwrap());

            let mut config_builder2 = ArtiConfigBuilder::default();
            config_builder2.application().watch_configuration(true);
            // Write another config file...
            config_builder2.system().max_files(0_u64);
            let _: PathBuf = write_config(&temp_dir, CONFIG_NAME2, &config_builder2);
            // Check that the 2 config files are merged
            let mut config_builder_combined = config_builder1.clone();
            config_builder_combined.system().max_files(0_u64);
            let config = rx.next().await.unwrap();
            assert_eq!(config.0, config_builder_combined.build().unwrap());
            // Now write a new config file to the watched dir
            config_builder2.logging().console("foo".to_string());
            let mut config_builder_combined2 = config_builder_combined.clone();
            config_builder_combined2
                .logging()
                .console("foo".to_string());
            let config3: PathBuf = write_config(&temp_dir, CONFIG_NAME3, &config_builder2);
            let config = rx.next().await.unwrap();
            assert_eq!(config.0, config_builder_combined2.build().unwrap());

            // Removing the file should also trigger an event
            std::fs::remove_file(config3).unwrap();
            let config = rx.next().await.unwrap();
            assert_eq!(config.0, config_builder_combined.build().unwrap());
        });
    }
}
