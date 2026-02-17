//! Types and functions to configure a Tor client.
//!
//! Some of these are re-exported from lower-level crates.

use crate::err::ErrorDetail;
use derive_deftly::Deftly;
use derive_more::AsRef;
use fs_mistrust::{Mistrust, MistrustBuilder};
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::result::Result as StdResult;
use std::time::Duration;

pub use tor_chanmgr::{ChannelConfig, ChannelConfigBuilder};
pub use tor_config::convert_helper_via_multi_line_list_builder;
use tor_config::derive::prelude::*;
use tor_config::extend_builder::extend_with_replace;
pub use tor_config::impl_standard_builder;
pub use tor_config::list_builder::{MultilineListBuilder, MultilineListBuilderError};
pub use tor_config::mistrust::BuilderExt as _;
pub use tor_config::{BoolOrAuto, ConfigError};
pub use tor_config::{ConfigBuildError, ConfigurationSource, ConfigurationSources, Reconfigure};
pub use tor_config::{define_list_builder_accessors, define_list_builder_helper};
pub use tor_config_path::{CfgPath, CfgPathError, CfgPathResolver};
pub use tor_linkspec::{ChannelMethod, HasChanMethod, PtTransportName, TransportId};

pub use tor_guardmgr::bridge::BridgeConfigBuilder;

#[cfg(feature = "bridge-client")]
pub use tor_guardmgr::bridge::BridgeParseError;

use tor_guardmgr::bridge::BridgeConfig;
use tor_keymgr::config::{ArtiKeystoreConfig, ArtiKeystoreConfigBuilder};

/// Types for configuring how Tor circuits are built.
pub mod circ {
    pub use tor_circmgr::{
        CircMgrConfig, CircuitTiming, CircuitTimingBuilder, PathConfig, PathConfigBuilder,
        PreemptiveCircuitConfig, PreemptiveCircuitConfigBuilder,
    };
}

/// Types for configuring how Tor accesses its directory information.
pub mod dir {
    pub use tor_dircommon::authority::{AuthorityContacts, AuthorityContactsBuilder};
    pub use tor_dircommon::config::{
        DirTolerance, DirToleranceBuilder, DownloadScheduleConfig, DownloadScheduleConfigBuilder,
        NetworkConfig, NetworkConfigBuilder,
    };
    pub use tor_dircommon::retry::{DownloadSchedule, DownloadScheduleBuilder};
    pub use tor_dirmgr::{DirMgrConfig, FallbackDir, FallbackDirBuilder};
}

/// Types for configuring pluggable transports.
#[cfg(feature = "pt-client")]
pub mod pt {
    pub use tor_ptmgr::config::{TransportConfig, TransportConfigBuilder};
}

/// Types for configuring onion services.
#[cfg(feature = "onion-service-service")]
pub mod onion_service {
    pub use tor_hsservice::config::{OnionServiceConfig, OnionServiceConfigBuilder};
}

/// Types for configuring vanguards.
pub mod vanguards {
    pub use tor_guardmgr::{VanguardConfig, VanguardConfigBuilder};
}

#[cfg(not(all(
    feature = "vanguards",
    any(feature = "onion-service-client", feature = "onion-service-service"),
)))]
use {
    std::sync::LazyLock,
    tor_config::ExplicitOrAuto,
    tor_guardmgr::{VanguardConfig, VanguardConfigBuilder, VanguardMode},
};

/// A [`VanguardConfig`] which is disabled.
// It would be nice if the builder were const, but this is the best we can do.
// Boxed so that this is guaranteed to use very little space if it's unused.
#[cfg(not(all(
    feature = "vanguards",
    any(feature = "onion-service-client", feature = "onion-service-service"),
)))]
static DISABLED_VANGUARDS: LazyLock<Box<VanguardConfig>> = LazyLock::new(|| {
    Box::new(
        VanguardConfigBuilder::default()
            .mode(ExplicitOrAuto::Explicit(VanguardMode::Disabled))
            .build()
            .expect("Could not build a disabled `VanguardConfig`"),
    )
});

/// Configuration for client behavior relating to addresses.
///
/// This type is immutable once constructed. To create an object of this type,
/// use [`ClientAddrConfigBuilder`].
///
/// You can replace this configuration on a running Arti client.  Doing so will
/// affect new streams and requests, but will have no effect on existing streams
/// and requests.
#[derive(Debug, Clone, Deftly, Eq, PartialEq)]
#[derive_deftly(TorConfig)]
pub struct ClientAddrConfig {
    /// Should we allow attempts to make Tor connections to local addresses?
    ///
    /// This option is off by default, since (by default) Tor exits will
    /// always reject connections to such addresses.
    #[deftly(tor_config(default))]
    pub(crate) allow_local_addrs: bool,

    /// Should we allow attempts to connect to hidden services (`.onion` services)?
    ///
    /// This option is on by default.
    //
    // NOTE: This could use tor_config(cfg) instead, but that would change the API.
    #[cfg(feature = "onion-service-client")]
    #[deftly(tor_config(default = "true"))]
    pub(crate) allow_onion_addrs: bool,
}

/// Configuration for client behavior relating to stream connection timeouts
///
/// This type is immutable once constructed. To create an object of this type,
/// use [`StreamTimeoutConfigBuilder`].
///
/// You can replace this configuration on a running Arti client.  Doing so will
/// affect new streams and requests, but will have no effect on existing streams
/// and requests—even those that are currently waiting.
#[derive(Debug, Clone, Deftly, Eq, PartialEq)]
#[derive_deftly(TorConfig)]
#[non_exhaustive]
pub struct StreamTimeoutConfig {
    /// How long should we wait before timing out a stream when connecting
    /// to a host?
    #[deftly(tor_config(default = "default_connect_timeout()"))]
    pub(crate) connect_timeout: Duration,

    /// How long should we wait before timing out when resolving a DNS record?
    #[deftly(tor_config(default = "default_dns_resolve_timeout()"))]
    pub(crate) resolve_timeout: Duration,

    /// How long should we wait before timing out when resolving a DNS
    /// PTR record?
    #[deftly(tor_config(default = "default_dns_resolve_ptr_timeout()"))]
    pub(crate) resolve_ptr_timeout: Duration,
}

/// Return the default stream timeout
fn default_connect_timeout() -> Duration {
    Duration::new(10, 0)
}

/// Return the default resolve timeout
fn default_dns_resolve_timeout() -> Duration {
    Duration::new(10, 0)
}

/// Return the default PTR resolve timeout
fn default_dns_resolve_ptr_timeout() -> Duration {
    Duration::new(10, 0)
}

/// Configuration for overriding the status of our software.
///
/// # Issues
///
/// We only check these configuration values when we receive a new consensus,
/// or when we're starting up.  Therefore, if you change these values,
/// they won't have any effect until the next consensus is received.
#[derive(Debug, Clone, Deftly, Eq, PartialEq)]
#[derive_deftly(TorConfig)]
pub struct SoftwareStatusOverrideConfig {
    /// A list of protocols to pretend that we have,
    /// when checking whether our software is obsolete.
    //
    // We make this type a String in the builder, to avoid exposing Protocols in our API.
    //
    // NOTE: Emulating the old behavior for this was pretty tricky, but we are slated to
    // (possibly) deprecate this option entirely.
    #[deftly(tor_config(
        no_magic,
        field(ty = "String"),
        setter(skip),
        try_build = "Self::parse_protos",
        extend_with = "extend_with_replace"
    ))]
    pub(crate) ignore_missing_required_protocols: tor_protover::Protocols,
}

impl SoftwareStatusOverrideConfigBuilder {
    /// Helper: Parse the ignore_missing_required_protocols field.
    fn parse_protos(&self) -> Result<tor_protover::Protocols, ConfigBuildError> {
        use std::str::FromStr as _;

        tor_protover::Protocols::from_str(&self.ignore_missing_required_protocols).map_err(|e| {
            ConfigBuildError::Invalid {
                field: "ignore_missing_required_protocols".to_string(),
                problem: e.to_string(),
            }
        })
    }

    /// Set a list of protocols that we pretend that we have
    /// when checking whether our software is obsolete.
    pub fn ignore_missing_required_protocols(&mut self, s: impl AsRef<str>) -> &mut Self {
        self.ignore_missing_required_protocols = s.as_ref().to_string();
        self
    }
}

/// Configuration for where information should be stored on disk.
///
/// By default, cache information will be stored in `${ARTI_CACHE}`, and
/// persistent state will be stored in `${ARTI_LOCAL_DATA}`.  That means that
/// _all_ programs using these defaults will share their cache and state data.
/// If that isn't what you want,  you'll need to override these directories.
///
/// On unix, the default directories will typically expand to `~/.cache/arti`
/// and `~/.local/share/arti/` respectively, depending on the user's
/// environment. Other platforms will also use suitable defaults. For more
/// information, see the documentation for [`CfgPath`].
///
/// This section is for read/write storage.
///
/// You cannot change this section on a running Arti client.
#[derive(Debug, Clone, Deftly, Eq, PartialEq)]
#[derive_deftly(TorConfig)]
pub struct StorageConfig {
    /// Location on disk for cached information.
    ///
    /// This follows the rules for `/var/cache`: "sufficiently old" filesystem objects
    /// in it may be deleted outside of the control of Arti,
    /// and Arti will continue to function properly.
    /// It is also fine to delete the directory as a whole, while Arti is not running.
    //
    // Usage note, for implementations of Arti components:
    //
    // When files in this directory are to be used by a component, the cache_dir
    // value should be passed through to the component as-is, and the component is
    // then responsible for constructing an appropriate sub-path (for example,
    // tor-dirmgr receives cache_dir, and appends components such as "dir_blobs".
    //
    // (This consistency rule is not current always followed by every component.)
    #[deftly(tor_config(default = "default_cache_dir()", setter(into)))]
    cache_dir: CfgPath,

    /// Location on disk for less-sensitive persistent state information.
    // Usage note: see the note for `cache_dir`, above.
    #[deftly(tor_config(default = "default_state_dir()", setter(into)))]
    state_dir: CfgPath,

    /// Location on disk for the Arti keystore.
    //
    // NOTE: This could use tor_config(cfg) instead, but that would change the API.
    #[cfg(feature = "keymgr")]
    #[deftly(tor_config(sub_builder))]
    keystore: ArtiKeystoreConfig,

    /// Configuration about which permissions we want to enforce on our files.
    #[deftly(tor_config(
        sub_builder(build_fn = "build_for_arti"),
        extend_with = "extend_with_replace"
    ))]
    permissions: Mistrust,
}

/// Return the default cache directory.
fn default_cache_dir() -> CfgPath {
    CfgPath::new("${ARTI_CACHE}".to_owned())
}

/// Return the default state directory.
fn default_state_dir() -> CfgPath {
    CfgPath::new("${ARTI_LOCAL_DATA}".to_owned())
}

/// Macro to avoid repeating code for `expand_*_dir` functions on StorageConfig
// TODO: generate the expand_*_dir functions using d-a instead
macro_rules! expand_dir {
    ($self:ident, $dirname:ident, $dircfg:ident) => {
        $self
            .$dirname
            .path($dircfg)
            .map_err(|e| ConfigBuildError::Invalid {
                field: stringify!($dirname).to_owned(),
                problem: e.to_string(),
            })
    };
}

impl StorageConfig {
    /// Try to expand `state_dir` to be a path buffer.
    pub(crate) fn expand_state_dir(
        &self,
        path_resolver: &CfgPathResolver,
    ) -> Result<PathBuf, ConfigBuildError> {
        expand_dir!(self, state_dir, path_resolver)
    }
    /// Try to expand `cache_dir` to be a path buffer.
    pub(crate) fn expand_cache_dir(
        &self,
        path_resolver: &CfgPathResolver,
    ) -> Result<PathBuf, ConfigBuildError> {
        expand_dir!(self, cache_dir, path_resolver)
    }
    /// Return the keystore config
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn keystore(&self) -> ArtiKeystoreConfig {
        cfg_if::cfg_if! {
            if #[cfg(feature="keymgr")] {
                self.keystore.clone()
            } else {
                Default::default()
            }
        }
    }
    /// Return the FS permissions to use for state and cache directories.
    pub(crate) fn permissions(&self) -> &Mistrust {
        &self.permissions
    }
}

/// Configuration for anti-censorship features: bridges and pluggable transports.
///
/// A "bridge" is a relay that is not listed in the regular Tor network directory;
/// clients use them to reach the network when a censor is blocking their
/// connection to all the regular Tor relays.
///
/// A "pluggable transport" is a tool that transforms and conceals a user's connection
/// to a bridge; clients use them to reach the network when a censor is blocking
/// all traffic that "looks like Tor".
///
/// A [`BridgesConfig`] configuration has the following pieces:
///    * A [`BridgeList`] of [`BridgeConfig`]s, which describes one or more bridges.
///    * An `enabled` boolean to say whether or not to use the listed bridges.
///    * A list of [`pt::TransportConfig`]s.
///
/// # Example
///
/// Here's an example of building a bridge configuration, and using it in a
/// TorClientConfig.
///
/// The bridges here are fictitious; you'll need to use real bridges
/// if you want a working configuration.
///
/// ```
/// ##[cfg(feature = "pt-client")]
/// # fn demo() -> anyhow::Result<()> {
/// use arti_client::config::{TorClientConfig, BridgeConfigBuilder, CfgPath};
/// // Requires that the pt-client feature is enabled.
/// use arti_client::config::pt::TransportConfigBuilder;
///
/// let mut builder = TorClientConfig::builder();
///
/// // Add a single bridge to the list of bridges, from a bridge line.
/// // This bridge line is made up for demonstration, and won't work.
/// const BRIDGE1_LINE : &str = "Bridge obfs4 192.0.2.55:38114 316E643333645F6D79216558614D3931657A5F5F cert=YXJlIGZyZXF1ZW50bHkgZnVsbCBvZiBsaXR0bGUgbWVzc2FnZXMgeW91IGNhbiBmaW5kLg iat-mode=0";
/// let bridge_1: BridgeConfigBuilder = BRIDGE1_LINE.parse()?;
/// // This is where we pass `BRIDGE1_LINE` into the BridgeConfigBuilder.
/// builder.bridges().bridges().push(bridge_1);
///
/// // Add a second bridge, built by hand.  This way is harder.
/// // This bridge is made up for demonstration, and won't work.
/// let mut bridge2_builder = BridgeConfigBuilder::default();
/// bridge2_builder
///     .transport("obfs4")
///     .push_setting("iat-mode", "1")
///     .push_setting(
///         "cert",
///         "YnV0IHNvbWV0aW1lcyB0aGV5IGFyZSByYW5kb20u8x9aQG/0cIIcx0ItBcTqiSXotQne+Q"
///     );
/// bridge2_builder.set_addrs(vec!["198.51.100.25:443".parse()?]);
/// bridge2_builder.set_ids(vec!["7DD62766BF2052432051D7B7E08A22F7E34A4543".parse()?]);
/// // Now insert the second bridge into our config builder.
/// builder.bridges().bridges().push(bridge2_builder);
///
/// // Now configure an obfs4 transport. (Requires the "pt-client" feature)
/// let mut transport = TransportConfigBuilder::default();
/// transport
///     .protocols(vec!["obfs4".parse()?])
///     // Specify either the name or the absolute path of pluggable transport client binary, this
///     // may differ from system to system.
///     .path(CfgPath::new("/usr/bin/obfs4proxy".into()))
///     .run_on_startup(true);
/// builder.bridges().transports().push(transport);
///
/// let config = builder.build()?;
/// // Now you can pass `config` to TorClient::create!
/// # Ok(())}
/// ```
/// You can also find an example based on snowflake in arti-client example folder.
//
// We leave this as an empty struct even when bridge support is disabled,
// as otherwise the default config file would generate an unknown section warning.
#[derive(Debug, Clone, Deftly, Eq, PartialEq)]
#[derive_deftly(TorConfig)]
#[deftly(tor_config(pre_build = "validate_bridges_config", attr = "non_exhaustive"))]
#[non_exhaustive]
pub struct BridgesConfig {
    /// Should we use configured bridges?
    ///
    /// The default (`Auto`) is to use bridges if they are configured.
    /// `false` means to not use even configured bridges.
    /// `true` means to insist on the use of bridges;
    /// if none are configured, that's then an error.
    #[deftly(tor_config(default))]
    pub(crate) enabled: BoolOrAuto,

    /// Configured list of bridges (possibly via pluggable transports)
    //
    // NOTE: This isn't using the automatic list_builder code, because it doesn't yet
    // support MultilineListBuilder.
    #[deftly(tor_config(no_magic, sub_builder, setter(skip)))]
    bridges: BridgeList,

    /// Configured list of pluggable transports.
    #[cfg(feature = "pt-client")] // NOTE: Could use tor_config(cfg)
    #[deftly(tor_config(
        list(element(build), listtype = "TransportConfigList"),
        default = "vec![]"
    ))]
    pub(crate) transports: Vec<pt::TransportConfig>,
}

#[cfg(feature = "pt-client")]
/// Determine if we need any pluggable transports.
///
/// If we do and their transports don't exist, we have a problem
fn validate_pt_config(bridges: &BridgesConfigBuilder) -> Result<(), ConfigBuildError> {
    use std::collections::HashSet;
    use std::str::FromStr;

    // These are all the protocols that the user has defined
    let mut protocols_defined: HashSet<PtTransportName> = HashSet::new();
    if let Some(transportlist) = bridges.opt_transports() {
        for protocols in transportlist.iter() {
            for protocol in protocols.get_protocols() {
                protocols_defined.insert(protocol.clone());
            }
        }
    }

    // Iterate over all the transports that bridges are going to use
    // If any one is valid, we validate the entire config
    for maybe_protocol in bridges
        .bridges
        .bridges
        .as_deref()
        .unwrap_or_default()
        .iter()
    {
        match maybe_protocol.get_transport() {
            Some(raw_protocol) => {
                // We convert the raw protocol string representation
                // into a more proper one using PtTransportName
                let protocol = TransportId::from_str(raw_protocol)
                    // If id can't be parsed, simply skip it here.
                    // The rest of the config validation/processing will generate an error for it.
                    .unwrap_or_default()
                    .into_pluggable();
                // The None case represents when we aren't using a PT at all
                match protocol {
                    Some(protocol_required) => {
                        if protocols_defined.contains(&protocol_required) {
                            return Ok(());
                        }
                    }
                    None => return Ok(()),
                }
            }
            None => {
                return Ok(());
            }
        }
    }

    Err(ConfigBuildError::Inconsistent {
        fields: ["bridges.bridges", "bridges.transports"].map(Into::into).into_iter().collect(),
        problem: "Bridges configured, but all bridges unusable due to lack of corresponding pluggable transport in `[bridges.transports]`".into(),
    })
}

/// Check that the bridge configuration is right
#[allow(clippy::unnecessary_wraps)]
fn validate_bridges_config(bridges: &BridgesConfigBuilder) -> Result<(), ConfigBuildError> {
    let _ = bridges; // suppresses unused variable for just that argument

    use BoolOrAuto as BoA;

    // Ideally we would run this post-build, rather than pre-build;
    // doing it here means we have to recapitulate the defaulting.
    // Happily the defaulting is obvious, cheap, and not going to change.
    //
    // Alternatively we could have derive_builder provide `build_unvalidated`,
    // but that involves re-setting the build fn name for every field.
    match (
        bridges.enabled.unwrap_or_default(),
        bridges.bridges.bridges.as_deref().unwrap_or_default(),
    ) {
        (BoA::Auto, _) | (BoA::Explicit(false), _) | (BoA::Explicit(true), [_, ..]) => {}
        (BoA::Explicit(true), []) => {
            return Err(ConfigBuildError::Inconsistent {
                fields: ["enabled", "bridges"].map(Into::into).into_iter().collect(),
                problem: "bridges.enabled=true, but no bridges defined".into(),
            });
        }
    }
    #[cfg(feature = "pt-client")]
    {
        if bridges_enabled(
            bridges.enabled.unwrap_or_default(),
            bridges.bridges.bridges.as_deref().unwrap_or_default(),
        ) {
            validate_pt_config(bridges)?;
        }
    }

    Ok(())
}

/// Generic logic to check if bridges should be used or not
fn bridges_enabled(enabled: BoolOrAuto, bridges: &[impl Sized]) -> bool {
    #[cfg(feature = "bridge-client")]
    {
        enabled.as_bool().unwrap_or(!bridges.is_empty())
    }

    #[cfg(not(feature = "bridge-client"))]
    {
        let _ = (enabled, bridges);
        false
    }
}

impl BridgesConfig {
    /// Should the bridges be used?
    fn bridges_enabled(&self) -> bool {
        bridges_enabled(self.enabled, &self.bridges)
    }
}

/// List of configured bridges, as found in the built configuration
//
// This type alias arranges that we can put `BridgeList` in `BridgesConfig`
// and have derive_builder put a `BridgeListBuilder` in `BridgesConfigBuilder`.
pub type BridgeList = Vec<BridgeConfig>;

define_list_builder_helper! {
    struct BridgeListBuilder {
        bridges: [BridgeConfigBuilder],
    }
    built: BridgeList = bridges;
    default = vec![];
    #[serde(try_from="MultilineListBuilder<BridgeConfigBuilder>")]
    #[serde(into="MultilineListBuilder<BridgeConfigBuilder>")]
}

convert_helper_via_multi_line_list_builder! {
    struct BridgeListBuilder {
        bridges: [BridgeConfigBuilder],
    }
}

#[cfg(feature = "bridge-client")]
define_list_builder_accessors! {
    struct BridgesConfigBuilder {
        pub bridges: [BridgeConfigBuilder],
    }
}

/// A configuration used to bootstrap a [`TorClient`](crate::TorClient).
///
/// In order to connect to the Tor network, Arti needs to know a few
/// well-known directory caches on the network, and the public keys of the
/// network's directory authorities.  It also needs a place on disk to
/// store persistent state and cached directory information. (See [`StorageConfig`]
/// for default directories.)
///
/// Most users will create a TorClientConfig by running
/// [`TorClientConfig::default`].
///
/// If you need to override the locations where Arti stores its
/// information, you can make a TorClientConfig with
/// [`TorClientConfigBuilder::from_directories`].
///
/// Finally, you can get fine-grained control over the members of a
/// TorClientConfig using [`TorClientConfigBuilder`].
#[derive(Clone, Deftly, Debug, AsRef, educe::Educe)]
#[educe(PartialEq, Eq)]
#[derive_deftly(TorConfig)]
#[non_exhaustive]
pub struct TorClientConfig {
    /// Information about the Tor network we want to connect to.
    #[deftly(tor_config(sub_builder))]
    tor_network: dir::NetworkConfig,

    /// Directories for storing information on disk
    #[deftly(tor_config(sub_builder))]
    pub(crate) storage: StorageConfig,

    /// Information about when and how often to download directory information
    #[deftly(tor_config(sub_builder))]
    download_schedule: dir::DownloadScheduleConfig,

    /// Information about how premature or expired our directories are allowed
    /// to be.
    ///
    /// These options help us tolerate clock skew, and help survive the case
    /// where the directory authorities are unable to reach consensus for a
    /// while.
    #[deftly(tor_config(sub_builder))]
    directory_tolerance: dir::DirTolerance,

    /// Facility to override network parameters from the values set in the
    /// consensus.
    #[deftly(tor_config(
        setter(skip), // See note on accessor. This isn't the best way to do this.
        field(ty = "HashMap<String, i32>"),
        build = "|this: &Self| default_extend(this.override_net_params.clone())",
        extend_with = "extend_with_replace"
    ))]
    pub(crate) override_net_params: tor_netdoc::doc::netstatus::NetParams<i32>,

    /// Information about bridges, pluggable transports, and so on
    #[deftly(tor_config(sub_builder))]
    pub(crate) bridges: BridgesConfig,

    /// Information about how to build paths through the network.
    #[deftly(tor_config(sub_builder))]
    pub(crate) channel: ChannelConfig,

    /// Configuration for system resources used by Arti
    ///
    /// Note that there are other settings in this section,
    /// in `arti::cfg::SystemConfig` -
    /// these two structs overlay here.
    #[deftly(tor_config(sub_builder))]
    pub(crate) system: SystemConfig,

    /// Information about how to build paths through the network.
    #[as_ref]
    #[deftly(tor_config(sub_builder))]
    path_rules: circ::PathConfig,

    /// Information about preemptive circuits.
    #[as_ref]
    #[deftly(tor_config(sub_builder))]
    preemptive_circuits: circ::PreemptiveCircuitConfig,

    /// Information about how to retry and expire circuits and request for circuits.
    #[as_ref]
    #[deftly(tor_config(sub_builder))]
    circuit_timing: circ::CircuitTiming,

    /// Rules about which addresses the client is willing to connect to.
    #[deftly(tor_config(sub_builder))]
    pub(crate) address_filter: ClientAddrConfig,

    /// Information about timing out client requests.
    #[deftly(tor_config(sub_builder))]
    pub(crate) stream_timeouts: StreamTimeoutConfig,

    /// Information about vanguards.
    // NOTE: Don't use `#[as_ref]` below, since we provide our own AsRef impl to handle when
    // vanguards are disabled.
    #[deftly(tor_config(sub_builder))]
    pub(crate) vanguards: vanguards::VanguardConfig,

    /// Support for running with known-obsolete versions.
    #[deftly(tor_config(sub_builder))]
    pub(crate) use_obsolete_software: SoftwareStatusOverrideConfig,

    /// Resolves paths in this configuration.
    ///
    /// This is not [reconfigurable](crate::TorClient::reconfigure).
    // We don't accept this from the builder/serde, and don't inspect it when comparing configs.
    // This should be considered as ancillary data rather than a configuration option.
    // TorClientConfig maybe isn't the best place for this, but this is where it needs to go to not
    // require public API changes.
    #[as_ref]
    #[deftly(tor_config(skip, build = "|_| tor_config_path::arti_client_base_resolver()"))]
    #[educe(PartialEq(ignore), Eq(ignore))]
    pub(crate) path_resolver: CfgPathResolver,
}

impl tor_config::load::TopLevel for TorClientConfig {
    type Builder = TorClientConfigBuilder;
}

/// Helper to add overrides to a default collection.
fn default_extend<T: Default + Extend<X>, X>(to_add: impl IntoIterator<Item = X>) -> T {
    let mut collection = T::default();
    collection.extend(to_add);
    collection
}

/// Configuration for system resources used by Tor.
///
/// You cannot change this section on a running Arti client.
///
/// Note that there are other settings in this section,
/// in `arti_client::config::SystemConfig`.
#[derive(Debug, Clone, Deftly, Eq, PartialEq)]
#[derive_deftly(TorConfig)]
#[non_exhaustive]
pub struct SystemConfig {
    /// Memory limits (approximate)
    #[deftly(tor_config(sub_builder))]
    pub(crate) memory: tor_memquota::Config,
}

impl AsRef<tor_guardmgr::VanguardConfig> for TorClientConfig {
    fn as_ref(&self) -> &tor_guardmgr::VanguardConfig {
        cfg_if::cfg_if! {
            if #[cfg(all(
                feature = "vanguards",
                any(feature = "onion-service-client", feature = "onion-service-service"),
            ))]
            {
                &self.vanguards
            } else {
                &DISABLED_VANGUARDS
            }
        }
    }
}

impl tor_circmgr::CircMgrConfig for TorClientConfig {}

#[cfg(feature = "onion-service-client")]
impl tor_hsclient::HsClientConnectorConfig for TorClientConfig {}

#[cfg(any(feature = "onion-service-client", feature = "onion-service-service"))]
impl tor_circmgr::hspool::HsCircPoolConfig for TorClientConfig {
    #[cfg(all(
        feature = "vanguards",
        any(feature = "onion-service-client", feature = "onion-service-service")
    ))]
    fn vanguard_config(&self) -> &tor_guardmgr::VanguardConfig {
        &self.vanguards
    }
}

impl AsRef<tor_dircommon::fallback::FallbackList> for TorClientConfig {
    fn as_ref(&self) -> &tor_dircommon::fallback::FallbackList {
        self.tor_network.fallback_caches()
    }
}
impl AsRef<[BridgeConfig]> for TorClientConfig {
    fn as_ref(&self) -> &[BridgeConfig] {
        #[cfg(feature = "bridge-client")]
        {
            &self.bridges.bridges
        }

        #[cfg(not(feature = "bridge-client"))]
        {
            &[]
        }
    }
}
impl AsRef<BridgesConfig> for TorClientConfig {
    fn as_ref(&self) -> &BridgesConfig {
        &self.bridges
    }
}
impl tor_guardmgr::GuardMgrConfig for TorClientConfig {
    fn bridges_enabled(&self) -> bool {
        self.bridges.bridges_enabled()
    }
}

impl TorClientConfig {
    /// Try to create a DirMgrConfig corresponding to this object.
    #[rustfmt::skip]
    pub fn dir_mgr_config(&self) -> Result<dir::DirMgrConfig, ConfigBuildError> {
        Ok(dir::DirMgrConfig {
            network:             self.tor_network        .clone(),
            schedule:            self.download_schedule  .clone(),
            tolerance:           self.directory_tolerance.clone(),
            cache_dir:           self.storage.expand_cache_dir(&self.path_resolver)?,
            cache_trust:         self.storage.permissions.clone(),
            override_net_params: self.override_net_params.clone(),
            extensions:          Default::default(),
        })
    }

    /// Return a reference to the [`fs_mistrust::Mistrust`] object that we'll
    /// use to check permissions on files and directories by default.
    ///
    /// # Usage notes
    ///
    /// In the future, specific files or directories may have stricter or looser
    /// permissions checks applied to them than this default.  Callers shouldn't
    /// use this [`Mistrust`] to predict what Arti will accept for a specific
    /// file or directory.  Rather, you should use this if you have some file or
    /// directory of your own on which you'd like to enforce the same rules as
    /// Arti uses.
    //
    // NOTE: The presence of this accessor is _NOT_ in any form a commitment to
    // expose every field from the configuration as an accessor.  We explicitly
    // reject that slippery slope argument.
    pub fn fs_mistrust(&self) -> &Mistrust {
        self.storage.permissions()
    }

    /// Return the keystore config
    pub fn keystore(&self) -> ArtiKeystoreConfig {
        self.storage.keystore()
    }

    /// Get the state directory and its corresponding
    /// [`Mistrust`] configuration.
    pub(crate) fn state_dir(&self) -> StdResult<(PathBuf, &fs_mistrust::Mistrust), ErrorDetail> {
        let state_dir = self
            .storage
            .expand_state_dir(&self.path_resolver)
            .map_err(ErrorDetail::Configuration)?;
        let mistrust = self.storage.permissions();

        Ok((state_dir, mistrust))
    }

    /// Access the `tor_memquota` configuration
    ///
    /// Ad-hoc accessor for testing purposes.
    /// (ideally we'd use `visibility` to make fields `pub`, but that doesn't work.)
    #[cfg(feature = "testing")]
    pub fn system_memory(&self) -> &tor_memquota::Config {
        &self.system.memory
    }
}

impl TorClientConfigBuilder {
    /// Returns a `TorClientConfigBuilder` using the specified state and cache directories.
    ///
    /// All other configuration options are set to their defaults, except `storage.keystore.path`,
    /// which is derived from the specified state directory.
    pub fn from_directories<P, Q>(state_dir: P, cache_dir: Q) -> Self
    where
        P: AsRef<Path>,
        Q: AsRef<Path>,
    {
        let mut builder = Self::default();

        builder
            .storage()
            .cache_dir(CfgPath::new_literal(cache_dir.as_ref()))
            .state_dir(CfgPath::new_literal(state_dir.as_ref()));

        builder
    }

    /// Return a mutable reference to a HashMap of `override_net_params`
    ///
    /// These parameters, if set, replace those that arrive in the network consensus document.
    //
    // NOTE: This is necessary for now because sub_builder isn't compatible with build().
    pub fn override_net_params(&mut self) -> &mut HashMap<String, i32> {
        &mut self.override_net_params
    }
}

/// Return the filenames for the default user configuration files
pub fn default_config_files() -> Result<Vec<ConfigurationSource>, CfgPathError> {
    // the base path resolver includes the 'ARTI_CONFIG' variable
    let path_resolver = tor_config_path::arti_client_base_resolver();

    ["${ARTI_CONFIG}/arti.toml", "${ARTI_CONFIG}/arti.d/"]
        .into_iter()
        .map(|f| {
            let path = CfgPath::new(f.into()).path(&path_resolver)?;
            Ok(ConfigurationSource::from_path(path))
        })
        .collect()
}

/// The environment variable we look at when deciding whether to disable FS permissions checking.
#[deprecated = "use tor-config::mistrust::ARTI_FS_DISABLE_PERMISSION_CHECKS instead"]
pub const FS_PERMISSIONS_CHECKS_DISABLE_VAR: &str = "ARTI_FS_DISABLE_PERMISSION_CHECKS";

/// Return true if the environment has been set up to disable FS permissions
/// checking.
///
/// This function is exposed so that other tools can use the same checking rules
/// as `arti-client`.  For more information, see
/// [`TorClientBuilder`](crate::TorClientBuilder).
#[deprecated(since = "0.5.0")]
#[allow(deprecated)]
pub fn fs_permissions_checks_disabled_via_env() -> bool {
    std::env::var_os(FS_PERMISSIONS_CHECKS_DISABLE_VAR).is_some()
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
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    use super::*;

    #[test]
    fn defaults() {
        let dflt = TorClientConfig::default();
        let b2 = TorClientConfigBuilder::default();
        let dflt2 = b2.build().unwrap();
        assert_eq!(&dflt, &dflt2);
    }

    #[test]
    fn builder() {
        let sec = std::time::Duration::from_secs(1);

        let mut authorities = dir::AuthorityContacts::builder();
        authorities.v3idents().push([22; 20].into());
        authorities.v3idents().push([44; 20].into());
        authorities.uploads().push(vec![
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)),
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 80, 0, 0)),
        ]);

        let mut fallback = dir::FallbackDir::builder();
        fallback
            .rsa_identity([23; 20].into())
            .ed_identity([99; 32].into())
            .orports()
            .push("127.0.0.7:7".parse().unwrap());

        let mut bld = TorClientConfig::builder();
        *bld.tor_network().authorities() = authorities;
        bld.tor_network().set_fallback_caches(vec![fallback]);
        bld.storage()
            .cache_dir(CfgPath::new("/var/tmp/foo".to_owned()))
            .state_dir(CfgPath::new("/var/tmp/bar".to_owned()));
        bld.download_schedule().retry_certs().attempts(10);
        bld.download_schedule().retry_certs().initial_delay(sec);
        bld.download_schedule().retry_certs().parallelism(3);
        bld.download_schedule().retry_microdescs().attempts(30);
        bld.download_schedule()
            .retry_microdescs()
            .initial_delay(10 * sec);
        bld.download_schedule().retry_microdescs().parallelism(9);
        bld.override_net_params()
            .insert("wombats-per-quokka".to_owned(), 7);
        bld.path_rules()
            .ipv4_subnet_family_prefix(20)
            .ipv6_subnet_family_prefix(48);
        bld.circuit_timing()
            .max_dirtiness(90 * sec)
            .request_timeout(10 * sec)
            .request_max_retries(22)
            .request_loyalty(3600 * sec);
        bld.address_filter().allow_local_addrs(true);

        let val = bld.build().unwrap();

        assert_ne!(val, TorClientConfig::default());
    }

    #[test]
    fn bridges_supported() {
        /// checks that when s is processed as TOML for a client config,
        /// the resulting number of bridges is according to `exp`
        fn chk(exp: Result<usize, ()>, s: &str) {
            eprintln!("----------\n{s}\n----------\n");
            let got = (|| {
                let cfg: toml::Value = toml::from_str(s).unwrap();
                let cfg: TorClientConfigBuilder = cfg.try_into()?;
                let cfg = cfg.build()?;
                let n_bridges = cfg.bridges.bridges.len();
                Ok::<_, anyhow::Error>(n_bridges) // anyhow is just something we can use for ?
            })()
            .map_err(|_| ());
            assert_eq!(got, exp);
        }

        let chk_enabled_or_auto = |exp, bridges_toml| {
            for enabled in [r#""#, r#"enabled = true"#, r#"enabled = "auto""#] {
                chk(exp, &format!("[bridges]\n{}\n{}", enabled, bridges_toml));
            }
        };

        let ok_1_if = |b: bool| b.then_some(1).ok_or(());

        chk(
            Err(()),
            r#"
                [bridges]
                enabled = true
            "#,
        );

        chk_enabled_or_auto(
            ok_1_if(cfg!(feature = "bridge-client")),
            r#"
                bridges = ["192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956"]
            "#,
        );

        chk_enabled_or_auto(
            ok_1_if(cfg!(feature = "pt-client")),
            r#"
                bridges = ["obfs4 bridge.example.net:80 $0bac39417268b69b9f514e7f63fa6fba1a788958 ed25519:dGhpcyBpcyBbpmNyZWRpYmx5IHNpbGx5ISEhISEhISA iat-mode=1"]
                [[bridges.transports]]
                protocols = ["obfs4"]
                path = "obfs4proxy"
            "#,
        );
    }

    #[test]
    fn check_default() {
        // We don't want to second-guess the directories crate too much
        // here, so we'll just make sure it does _something_ plausible.

        let dflt = default_config_files().unwrap();
        assert!(dflt[0].as_path().unwrap().ends_with("arti.toml"));
        assert!(dflt[1].as_path().unwrap().ends_with("arti.d"));
        assert_eq!(dflt.len(), 2);
    }

    #[test]
    #[cfg(not(all(
        feature = "vanguards",
        any(feature = "onion-service-client", feature = "onion-service-service"),
    )))]
    fn check_disabled_vanguards_static() {
        // Force us to evaluate the closure to ensure that it builds correctly.
        #[allow(clippy::borrowed_box)]
        let _: &Box<VanguardConfig> = LazyLock::force(&DISABLED_VANGUARDS);
    }

    #[test]
    #[cfg(feature = "pt-client")]
    fn check_bridge_pt() {
        let from_toml = |s: &str| -> TorClientConfigBuilder {
            let cfg: toml::Value = toml::from_str(dbg!(s)).unwrap();
            let cfg: TorClientConfigBuilder = cfg.try_into().unwrap();
            cfg
        };

        let chk = |cfg: &TorClientConfigBuilder, expected: Result<(), &str>| match (
            cfg.build(),
            expected,
        ) {
            (Ok(_), Ok(())) => {}
            (Err(e), Err(ex)) => {
                if !e.to_string().contains(ex) {
                    panic!("\"{e}\" did not contain {ex}");
                }
            }
            (Ok(_), Err(ex)) => {
                panic!("Expected {ex} but cfg succeeded");
            }
            (Err(e), Ok(())) => {
                panic!("Expected success but got error {e}")
            }
        };

        let test_cases = [
            ("# No bridges", Ok(())),
            (
                r#"
                    # No bridges but we still enabled bridges
                    [bridges]
                    enabled = true
                    bridges = []
                "#,
                Err("bridges.enabled=true, but no bridges defined"),
            ),
            (
                r#"
                    # One non-PT bridge
                    [bridges]
                    enabled = true
                    bridges = [
                        "192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956",
                    ]
                "#,
                Ok(()),
            ),
            (
                r#"
                    # One obfs4 bridge
                    [bridges]
                    enabled = true
                    bridges = [
                        "obfs4 bridge.example.net:80 $0bac39417268b69b9f514e7f63fa6fba1a788958 ed25519:dGhpcyBpcyBbpmNyZWRpYmx5IHNpbGx5ISEhISEhISA iat-mode=1",
                    ]
                    [[bridges.transports]]
                    protocols = ["obfs4"]
                    path = "obfs4proxy"
                "#,
                Ok(()),
            ),
            (
                r#"
                    # One obfs4 bridge with unmanaged transport.
                    [bridges]
                    enabled = true
                    bridges = [
                        "obfs4 bridge.example.net:80 $0bac39417268b69b9f514e7f63fa6fba1a788958 ed25519:dGhpcyBpcyBbpmNyZWRpYmx5IHNpbGx5ISEhISEhISA iat-mode=1",
                    ]
                    [[bridges.transports]]
                    protocols = ["obfs4"]
                    proxy_addr = "127.0.0.1:31337"
                "#,
                Ok(()),
            ),
            (
                r#"
                    # Transport is both managed and unmanaged.
                    [[bridges.transports]]
                    protocols = ["obfs4"]
                    path = "obfsproxy"
                    proxy_addr = "127.0.0.1:9999"
                "#,
                Err("Cannot provide both path and proxy_addr"),
            ),
            (
                r#"
                    # One obfs4 bridge and non-PT bridge
                    [bridges]
                    enabled = false
                    bridges = [
                        "192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956",
                        "obfs4 bridge.example.net:80 $0bac39417268b69b9f514e7f63fa6fba1a788958 ed25519:dGhpcyBpcyBbpmNyZWRpYmx5IHNpbGx5ISEhISEhISA iat-mode=1",
                    ]
                    [[bridges.transports]]
                    protocols = ["obfs4"]
                    path = "obfs4proxy"
                "#,
                Ok(()),
            ),
            (
                r#"
                    # One obfs4 and non-PT bridge with no transport
                    [bridges]
                    enabled = true
                    bridges = [
                        "192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956",
                        "obfs4 bridge.example.net:80 $0bac39417268b69b9f514e7f63fa6fba1a788958 ed25519:dGhpcyBpcyBbpmNyZWRpYmx5IHNpbGx5ISEhISEhISA iat-mode=1",
                    ]
                "#,
                Ok(()),
            ),
            (
                r#"
                    # One obfs4 bridge with no transport
                    [bridges]
                    enabled = true
                    bridges = [
                        "obfs4 bridge.example.net:80 $0bac39417268b69b9f514e7f63fa6fba1a788958 ed25519:dGhpcyBpcyBbpmNyZWRpYmx5IHNpbGx5ISEhISEhISA iat-mode=1",
                    ]
                "#,
                Err("all bridges unusable due to lack of corresponding pluggable transport"),
            ),
            (
                r#"
                    # One obfs4 bridge with no transport but bridges are disabled
                    [bridges]
                    enabled = false
                    bridges = [
                        "obfs4 bridge.example.net:80 $0bac39417268b69b9f514e7f63fa6fba1a788958 ed25519:dGhpcyBpcyBbpmNyZWRpYmx5IHNpbGx5ISEhISEhISA iat-mode=1",
                    ]
                "#,
                Ok(()),
            ),
            (
                r#"
                        # One non-PT bridge with a redundant transports section
                        [bridges]
                        enabled = false
                        bridges = [
                            "192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956",
                        ]
                        [[bridges.transports]]
                        protocols = ["obfs4"]
                        path = "obfs4proxy"
                "#,
                Ok(()),
            ),
        ];

        for (test_case, expected) in test_cases.iter() {
            chk(&from_toml(test_case), *expected);
        }
    }
}
