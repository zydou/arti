//! Code to watch configuration files for any changes.

use std::sync::Weak;
use std::time::Duration;

use anyhow::Context;
use arti_client::config::Reconfigure;
use arti_client::TorClient;
use futures::{select_biased, FutureExt as _, Stream};
use tor_config::file_watcher::{self, FileWatcherBuilder, FileEventSender, FileWatcher};
use tor_config::{sources::FoundConfigFiles, ConfigurationSource, ConfigurationSources};
use tor_rtcompat::Runtime;
use tracing::{debug, error, info, warn};
use futures::task::SpawnExt;
use futures::StreamExt;

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
    /// By convention, this should only return fatal errors; any such error
    /// should cause the program to exit.  For other cases, we should just warn.
    //
    // TODO: This should probably take "how: Reconfigure" as an argument, and
    // pass it down as appropriate. See issue #1156.
    fn reconfigure(&self, new: &ArtiCombinedConfig) -> anyhow::Result<()>;
}

/// Launch a thread to reload our configuration files.
///
/// If current configuration requires it, watch for changes in `sources`
/// and try to reload our configuration. On unix platforms, also watch
/// for SIGHUP and reload configuration then.
///
/// The modules are `Weak` references to prevent this background task
/// from keeping them alive.
///
/// See the [`FileWatcher`](FileWatcher#Limitations) docs for limitations.
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) fn watch_for_config_changes<R: Runtime>(
    runtime: &R,
    sources: ConfigurationSources,
    config: &ArtiConfig,
    modules: Vec<Weak<dyn ReconfigurableModule>>,
) -> anyhow::Result<()> {
    let watch_file = config.application().watch_configuration;

    cfg_if::cfg_if! {
        if #[cfg(target_family = "unix")] {
            let sighup_stream = sighup_stream()?;
        } else {
            let sighup_stream = stream::pending();
        }
    }

    let rt = runtime.clone();
    let () = runtime.clone().spawn(async move {
        let res: anyhow::Result<()> = run_watcher(
            rt,
            sources,
            modules,
            watch_file,
            sighup_stream,
            Some(DEBOUNCE_INTERVAL)
        ).await;

        match res {
            Ok(()) => debug!("Config watcher task exiting"),
            // TODO: warn_report does not work on anyhow::Error.
            Err(e) => error!("Config watcher task exiting: {}", tor_error::Report(e)),
        }
    }).context("failed to spawn task")?;

    Ok(())
}

/// Start watching for configuration changes.
///
/// Spawned from `watch_for_config_changes`.
async fn run_watcher<R: Runtime>(
    runtime: R,
    sources: ConfigurationSources,
    modules: Vec<Weak<dyn ReconfigurableModule>>,
    watch_file: bool,
    mut sighup_stream: impl Stream<Item = ()> + Unpin,
    debounce_interval: Option<Duration>,
) -> anyhow::Result<()> {
    let (tx, mut rx) = file_watcher::channel();
    let mut watcher = if watch_file {
        let mut watcher = FileWatcher::builder(runtime.clone());
        prepare(&mut watcher, &sources)?;
        Some(watcher.start_watching(tx.clone())?)
    } else {
        None
    };

    debug!("Entering FS event loop");

    loop {
        select_biased! {
            event = sighup_stream.next().fuse() => {
                let Some(()) = event else {
                    break;
                };

                info!("Received SIGHUP");

                watcher = reload_configuration(
                    runtime.clone(),
                    watcher,
                    &sources,
                    &modules,
                    tx.clone()
                ).await?;
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
                watcher = reload_configuration(
                    runtime.clone(),
                    watcher,
                    &sources,
                    &modules,
                    tx.clone()
                ).await?;
            },
        }
    }

    Ok(())
}

/// Reload the configuration.
async fn reload_configuration<R: Runtime>(
    runtime: R,
    mut watcher: Option<FileWatcher>,
    sources: &ConfigurationSources,
    modules: &[Weak<dyn ReconfigurableModule>],
    tx: FileEventSender,
) -> anyhow::Result<Option<FileWatcher>> {

    let found_files = if watcher.is_some() {
        let mut new_watcher = FileWatcher::builder(runtime.clone());
        let found_files = prepare(&mut new_watcher, sources)
            .context("FS watch: failed to rescan config and re-establish watch")?;
        let new_watcher = new_watcher
            .start_watching(tx.clone())
            .context("FS watch: failed to start watching config")?;
        watcher = Some(new_watcher);
        found_files
    } else {
        sources
            .scan()
            .context("FS watch: failed to rescan config")?
    };

    match reconfigure(found_files, modules) {
        Ok(watch) => {
            info!("Successfully reloaded configuration.");
            if watch && watcher.is_none() {
                info!("Starting watching over configuration.");
                let mut new_watcher = FileWatcher::builder(runtime.clone());
                let _found_files = prepare(&mut new_watcher, sources).context(
                    "FS watch: failed to rescan config and re-establish watch: {}",
                )?;
                let new_watcher = new_watcher.start_watching(tx.clone()).context(
                    "FS watch: failed to rescan config and re-establish watch: {}",
                )?;
                watcher = Some(new_watcher);
            } else if !watch && watcher.is_some() {
                info!("Stopped watching over configuration.");
                watcher = None;
            }
        }
        // TODO: warn_report does not work on anyhow::Error.
        Err(e) => warn!("Couldn't reload configuration: {}", tor_error::Report(e)),
    }

    Ok(watcher)
}

impl<R: Runtime> ReconfigurableModule for TorClient<R> {
    fn reconfigure(&self, new: &ArtiCombinedConfig) -> anyhow::Result<()> {
        TorClient::reconfigure(self, &new.1, Reconfigure::WarnOnFailures)?;
        Ok(())
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
    // TODO: This should probably take "how: Reconfigure" as an argument, and
    // pass it down as appropriate. See issue #1156.
    #[allow(clippy::cognitive_complexity)]
    fn reconfigure(&self, new: &ArtiCombinedConfig) -> anyhow::Result<()> {
        let original = &self.original_config;
        let config = &new.0;

        if config.proxy() != original.proxy() {
            warn!("Can't (yet) reconfigure proxy settings while arti is running.");
        }
        if config.logging() != original.logging() {
            warn!("Can't (yet) reconfigure logging settings while arti is running.");
        }
        if config.application().permit_debugging && !original.application().permit_debugging {
            warn!("Cannot disable application hardening when it has already been enabled.");
        }

        // Note that this is the only config transition we actually perform so far.
        if !config.application().permit_debugging {
            #[cfg(feature = "harden")]
            crate::process::enable_process_hardening()?;
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
//
// TODO: This should probably take "how: Reconfigure" as an argument, and
// pass it down as appropriate. See issue #1156.
fn reconfigure(
    found_files: FoundConfigFiles<'_>,
    reconfigurable: &[Weak<dyn ReconfigurableModule>],
) -> anyhow::Result<bool> {
    let _ = reconfigurable;
    let config = found_files.load()?;
    let config = tor_config::resolve::<ArtiCombinedConfig>(config)?;

    // Filter out the modules that have been dropped
    let reconfigurable = reconfigurable.iter().flat_map(Weak::upgrade);
    // If there are no more modules, we should exit.
    let mut has_modules = false;

    for module in reconfigurable {
        has_modules = true;
        module.reconfigure(&config)?;
    }

    Ok(has_modules && config.0.application().watch_configuration)
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
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use crate::ArtiConfigBuilder;

    use super::*;
    use futures::channel::mpsc;
    use futures::SinkExt as _;
    use tor_config::sources::MustRead;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use test_temp_dir::{test_temp_dir, TestTempDir};
    use postage::watch;
    use tor_async_utils::PostageWatchSenderExt;

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
        fn reconfigure(&self, new: &ArtiCombinedConfig) -> anyhow::Result<()> {
            let config = new.clone();
            self.tx.lock().unwrap().maybe_send(|_| config);

            Ok(())
        }
    }

    /// Create a test reconfigurable module.
    ///
    /// Returns the module and a channel on which the new configs received by the module are sent.
    async fn create_module(
    ) -> (Arc<dyn ReconfigurableModule>, watch::Receiver<ArtiCombinedConfig>) {
        let (tx, mut rx) = watch::channel();
        // Read the initial value from the postage::watch stream
        // (the first observed value on this test stream is always the default config)
        let _: ArtiCombinedConfig = rx.next().await.unwrap();

        (Arc::new(TestModule { tx: Arc::new(Mutex::new(tx)) }), rx)
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
    #[ignore] // TODO(#1607): Re-enable
    fn watch_single_file() {
        tor_rtcompat::test_with_one_runtime!(|rt| async move {
            let temp_dir = test_temp_dir!();
            let mut config_builder =  ArtiConfigBuilder::default();
            config_builder.application().watch_configuration(true);

            let cfg_file = write_config(&temp_dir, CONFIG_NAME1, &config_builder);
            let mut cfg_sources = ConfigurationSources::new_empty();
            cfg_sources.push_source(ConfigurationSource::File(cfg_file), MustRead::MustRead);

            let (module, mut rx) = create_module().await;

            // Use a fake sighup stream to wait until run_watcher()'s select_biased!
            // loop is entered
            let (mut sighup_tx, sighup_rx) = mpsc::unbounded();
            let runtime = rt.clone();
            let () = rt.spawn(async move {
                run_watcher(
                    runtime,
                    cfg_sources,
                    vec![Arc::downgrade(&module)],
                    true,
                    sighup_rx,
                    None,
                ).await.unwrap();
            }).unwrap();

            config_builder.logging().log_sensitive_information(true);
            let _: PathBuf = write_config(&temp_dir, CONFIG_NAME1, &config_builder);
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

    #[test]
    fn watch_multiple() {
        tor_rtcompat::test_with_one_runtime!(|rt| async move {
            let temp_dir = test_temp_dir!();
            let mut config_builder1 =  ArtiConfigBuilder::default();
            config_builder1.application().watch_configuration(true);

            let _: PathBuf = write_config(&temp_dir, CONFIG_NAME1, &config_builder1);
            let mut cfg_sources = ConfigurationSources::new_empty();
            cfg_sources.push_source(
                ConfigurationSource::Dir(temp_dir.as_path_untracked().to_path_buf()),
                MustRead::MustRead
            );

            let (module, mut rx) = create_module().await;
            // Use a fake sighup stream to wait until run_watcher()'s select_biased!
            // loop is entered
            let (mut sighup_tx, sighup_rx) = mpsc::unbounded();
            let runtime = rt.clone();
            let () = rt.spawn(async move {
                run_watcher(
                    runtime,
                    cfg_sources,
                    vec![Arc::downgrade(&module)],
                    true,
                    sighup_rx,
                    None,
                ).await.unwrap();
            }).unwrap();

            config_builder1.logging().log_sensitive_information(true);
            let _: PathBuf = write_config(&temp_dir, CONFIG_NAME1, &config_builder1);
            sighup_tx.send(()).await.unwrap();
            // The reconfigurable modules should've been reloaded in response to sighup
            let config = rx.next().await.unwrap();
            assert_eq!(config.0, config_builder1.build().unwrap());

            let mut config_builder2 =  ArtiConfigBuilder::default();
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
            config_builder_combined2.logging().console("foo".to_string());
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
