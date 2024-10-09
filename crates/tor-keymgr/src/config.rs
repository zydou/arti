//! Configuration options for types implementing [`Keystore`](crate::Keystore)

pub use tor_config::{CfgPath, CfgPathError, ConfigBuildError, ConfigurationSource, Reconfigure};

use amplify::Getters;
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use tor_config::{
    define_list_builder_helper, impl_not_auto_value, impl_standard_builder, BoolOrAuto,
    ExplicitOrAuto,
};
use tor_persist::hsnickname::HsNickname;

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::KeystoreId;

/// The kind of keystore to use
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ArtiKeystoreKind {
    /// Use the [`ArtiNativeKeystore`](crate::ArtiNativeKeystore).
    Native,
    /// Use the [`ArtiEphemeralKeystore`](crate::ArtiEphemeralKeystore).
    #[cfg(feature = "ephemeral-keystore")]
    Ephemeral,
}
impl_not_auto_value! {ArtiKeystoreKind}

/// [`ArtiNativeKeystore`](crate::ArtiNativeKeystore) configuration
#[derive(Debug, Clone, Builder, Eq, PartialEq, Serialize, Deserialize, Getters)]
#[builder(derive(Serialize, Deserialize, Debug))]
#[builder(build_fn(validate = "Self::validate", error = "ConfigBuildError"))]
#[non_exhaustive]
#[builder_struct_attr(non_exhaustive)]
pub struct ArtiKeystoreConfig {
    /// Whether keystore use is enabled.
    #[builder_field_attr(serde(default))]
    #[builder(default)]
    enabled: BoolOrAuto,

    /// The primary keystore.
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    primary: PrimaryKeystoreConfig,

    /// Optionally configure C Tor keystores for arti to use.
    ///
    /// Note: The keystores listed here are read-only (keys are only
    /// ever written to the primary keystore, configured in
    /// `storage.keystore.primary`).
    ///
    /// Each C Tor keystore **must** have a unique identifier.
    /// It is an error to configure multiple keystores with the same [`KeystoreId`].
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    ctor: CTorKeystoreConfig,
}

/// [`ArtiNativeKeystore`](crate::ArtiNativeKeystore) configuration
#[derive(Debug, Clone, Builder, Eq, PartialEq, Serialize, Deserialize, Getters)]
#[builder(derive(Serialize, Deserialize, Debug))]
#[builder(build_fn(validate = "Self::validate", error = "ConfigBuildError"))]
#[non_exhaustive]
#[builder_struct_attr(non_exhaustive)]
pub struct CTorKeystoreConfig {
    /// C Tor hidden service keystores.
    #[builder(default, sub_builder(fn_name = "build"), setter(custom))]
    #[builder_field_attr(serde(default))]
    services: CTorServiceKeystoreConfigMap,

    /// C Tor hidden service client keystores.
    #[builder(default, sub_builder(fn_name = "build"))]
    #[builder_field_attr(serde(default))]
    clients: CTorClientKeystoreConfigList,
}

/// Primary [`ArtiNativeKeystore`](crate::ArtiNativeKeystore) configuration
#[derive(Debug, Clone, Builder, Eq, PartialEq, Serialize, Deserialize)]
#[builder(derive(Serialize, Deserialize, Debug))]
#[builder(build_fn(error = "ConfigBuildError"))]
#[non_exhaustive]
#[builder_struct_attr(non_exhaustive)]
pub struct PrimaryKeystoreConfig {
    /// The type of keystore to use, or none at all.
    #[builder_field_attr(serde(default))]
    #[builder(default)]
    kind: ExplicitOrAuto<ArtiKeystoreKind>,
}

/// C Tor [`ArtiNativeKeystore`](crate::ArtiNativeKeystore) configuration
#[derive(Debug, Clone, Builder, Eq, PartialEq, Serialize, Deserialize, Getters)]
#[builder(derive(Serialize, Deserialize, Debug))]
#[builder(build_fn(error = "ConfigBuildError"))]
#[non_exhaustive]
#[builder_struct_attr(non_exhaustive)]
pub struct CTorServiceKeystoreConfig {
    /// The identifier of this keystore.
    ///
    /// Each C Tor keystore **must**:
    ///
    ///   * have a unique identifier. It is an error to configure multiple keystores
    ///     with the same [`KeystoreId`].
    ///   * have a corresponding arti hidden service configured in the
    ///     `[onion_services]` section with the same nickname
    id: KeystoreId,

    /// The root directory of this keystore.
    ///
    /// This should be set to the `HiddenServiceDirectory` of your hidden service.
    /// Arti will read `HiddenServiceDirectory/hostname` and `HiddenServiceDirectory/private_key`.
    /// (Note: if your service is running in restricted discovery mode, you must also set the
    /// `[[onion_services."<the nickname of your svc>".restricted_discovery.key_dirs]]`
    /// to `HiddenServiceDirectory/client_keys`).
    path: PathBuf,

    /// The nickname of the service this keystore is to be used with.
    nickname: HsNickname,
}

/// Alias for a `BTreeMap` of `CTorServiceKeystoreConfig`; used to make derive_builder
/// happy.
pub(crate) type CTorServiceKeystoreConfigMap = BTreeMap<HsNickname, CTorServiceKeystoreConfig>;

/// The serialized format of an CTorServiceKeystoreConfigListBuilder:
/// a map from nickname to `CTorServiceKeystoreConfigBuilder`
type CTorServiceKeystoreConfigBuilderMap = BTreeMap<HsNickname, CTorServiceKeystoreConfigBuilder>;

define_list_builder_helper! {
    pub struct CTorServiceKeystoreConfigMapBuilder {
        stores: [CTorServiceKeystoreConfigBuilder],
    }
    built: CTorServiceKeystoreConfigMap = build_ctor_service_list(stores)?;
    default = vec![];
    #[serde(try_from="CTorServiceKeystoreConfigBuilderMap", into="CTorServiceKeystoreConfigBuilderMap")]
}

impl TryFrom<CTorServiceKeystoreConfigBuilderMap> for CTorServiceKeystoreConfigMapBuilder {
    type Error = ConfigBuildError;

    fn try_from(value: CTorServiceKeystoreConfigBuilderMap) -> Result<Self, Self::Error> {
        let mut list_builder = CTorServiceKeystoreConfigMapBuilder::default();
        for (nickname, mut cfg) in value {
            match &cfg.nickname {
                Some(n) if n == &nickname => (),
                None => (),
                Some(other) => {
                    return Err(ConfigBuildError::Inconsistent {
                        fields: vec![nickname.to_string(), format!("{nickname}.{other}")],
                        problem: "mismatched nicknames on onion service.".into(),
                    });
                }
            }
            cfg.nickname = Some(nickname);
            list_builder.access().push(cfg);
        }
        Ok(list_builder)
    }
}

impl From<CTorServiceKeystoreConfigMapBuilder> for CTorServiceKeystoreConfigBuilderMap {
    // Note: this is *similar* to the OnionServiceProxyConfigMap implementation (it duplicates much
    // of that logic, so perhaps at some point it's worth abstracting all of it away behind a
    // general-purpose map builder API).
    //
    /// Convert our Builder representation of a set of C Tor service configs into the
    /// format that serde will serialize.
    ///
    /// Note: This is a potentially lossy conversion, since the serialized format
    /// can't represent partially-built configs without a nickname, or
    /// a collection of configs with duplicate nicknames.
    fn from(value: CTorServiceKeystoreConfigMapBuilder) -> CTorServiceKeystoreConfigBuilderMap {
        let mut map = BTreeMap::new();
        for cfg in value.stores.into_iter().flatten() {
            let nickname = cfg.nickname.clone().unwrap_or_else(|| {
                "Unnamed"
                    .to_string()
                    .try_into()
                    .expect("'Unnamed' was not a valid nickname")
            });
            map.insert(nickname, cfg);
        }
        map
    }
}

/// Construct a CTorServiceKeystoreConfigList from a vec of CTorServiceKeystoreConfig;
/// enforce that nicknames are unique.
///
/// Returns an error if the [`KeystoreId`] of the `CTorServiceKeystoreConfig`s are not unique.
fn build_ctor_service_list(
    ctor_stores: Vec<CTorServiceKeystoreConfig>,
) -> Result<CTorServiceKeystoreConfigMap, ConfigBuildError> {
    use itertools::Itertools as _;

    if !ctor_stores.iter().map(|s| &s.id).all_unique() {
        return Err(ConfigBuildError::Inconsistent {
            fields: ["id"].map(Into::into).into_iter().collect(),
            problem: "the C Tor keystores do not have unique IDs".into(),
        });
    }

    let mut map = BTreeMap::new();
    for service in ctor_stores {
        if let Some(previous_value) = map.insert(service.nickname.clone(), service) {
            return Err(ConfigBuildError::Inconsistent {
                fields: vec!["nickname".into()],
                problem: format!(
                    "Multiple C Tor service keystores for service with nickname {}",
                    previous_value.nickname
                ),
            });
        };
    }

    Ok(map)
}

/// C Tor [`ArtiNativeKeystore`](crate::ArtiNativeKeystore) configuration
#[derive(Debug, Clone, Builder, Eq, PartialEq, Serialize, Deserialize, Getters)]
#[builder(derive(Serialize, Deserialize, Debug))]
#[builder(build_fn(error = "ConfigBuildError"))]
#[non_exhaustive]
#[builder_struct_attr(non_exhaustive)]
pub struct CTorClientKeystoreConfig {
    /// The identifier of this keystore.
    ///
    /// Each keystore **must** have a unique identifier.
    /// It is an error to configure multiple keystores with the same [`KeystoreId`].
    id: KeystoreId,

    /// The root directory of this keystore.
    ///
    /// This should be set to the `ClientOnionAuthDir` of your client.
    /// If Arti is configured to run as a client (i.e. if it runs in SOCKS proxy mode),
    /// it will read the client restricted discovery keys from this path.
    ///
    /// The key files are expected to have the `.auth_private` extension,
    /// and their content **must** be of the form:
    /// `<56-char-onion-addr-without-.onion-part>:descriptor:x25519:<x25519 private key in base32>`.
    ///
    /// Malformed files, and files that don't have the `.auth_private` extension, will be ignored.
    path: PathBuf,
}

/// The serialized format of a [`CTorClientKeystoreConfigListBuilder`]:
pub type CTorClientKeystoreConfigList = Vec<CTorClientKeystoreConfig>;

define_list_builder_helper! {
    pub struct CTorClientKeystoreConfigListBuilder {
        stores: [CTorClientKeystoreConfigBuilder],
    }
    built: CTorClientKeystoreConfigList = build_ctor_client_store_config(stores)?;
    default = vec![];
}

/// Helper for building and validating a [`CTorClientKeystoreConfigList`].
///
/// Returns an error if the [`KeystoreId`]s of the `CTorClientKeystoreConfig`s are not unique.
fn build_ctor_client_store_config(
    ctor_stores: Vec<CTorClientKeystoreConfig>,
) -> Result<CTorClientKeystoreConfigList, ConfigBuildError> {
    use itertools::Itertools as _;

    if !ctor_stores.iter().map(|s| &s.id).all_unique() {
        return Err(ConfigBuildError::Inconsistent {
            fields: ["id"].map(Into::into).into_iter().collect(),
            problem: "the C Tor keystores do not have unique IDs".into(),
        });
    }

    Ok(ctor_stores)
}

impl ArtiKeystoreConfig {
    /// Whether the keystore is enabled.
    pub fn is_enabled(&self) -> bool {
        let default = cfg!(feature = "keymgr");

        self.enabled.as_bool().unwrap_or(default)
    }

    /// The type of keystore to use
    ///
    /// Returns `None` if keystore use is disabled.
    pub fn primary_kind(&self) -> Option<ArtiKeystoreKind> {
        use ExplicitOrAuto as EoA;

        if !self.is_enabled() {
            return None;
        }

        let kind = match self.primary.kind {
            EoA::Explicit(kind) => kind,
            EoA::Auto => ArtiKeystoreKind::Native,
        };

        Some(kind)
    }

    /// The ctor keystore configs
    pub fn ctor_svc_stores(&self) -> impl Iterator<Item = &CTorServiceKeystoreConfig> {
        self.ctor.services.values()
    }

    /// The ctor client keystore configs
    pub fn ctor_client_stores(&self) -> impl Iterator<Item = &CTorClientKeystoreConfig> {
        self.ctor.clients.iter()
    }
}

impl_standard_builder! { ArtiKeystoreConfig }

impl ArtiKeystoreConfigBuilder {
    /// Check that the keystore configuration is valid
    #[cfg(not(feature = "keymgr"))]
    #[allow(clippy::unnecessary_wraps)]
    fn validate(&self) -> Result<(), ConfigBuildError> {
        use BoolOrAuto as BoA;
        use ExplicitOrAuto as EoA;

        // Keystore support is disabled unless the `keymgr` feature is enabled.
        if self.enabled == Some(BoA::Explicit(true)) {
            return Err(ConfigBuildError::Inconsistent {
                fields: ["enabled"].map(Into::into).into_iter().collect(),
                problem: "keystore enabled=true, but keymgr feature not enabled".into(),
            });
        }

        let () = match self.primary.kind {
            // only enabled OR kind may be set, and when keymgr is not enabeld they must be false|disabled
            None | Some(EoA::Auto) => Ok(()),
            _ => Err(ConfigBuildError::Inconsistent {
                fields: ["enabled", "kind"].map(Into::into).into_iter().collect(),
                problem: "kind!=auto, but keymgr feature not enabled".into(),
            }),
        }?;

        Ok(())
    }

    /// Check that the keystore configuration is valid
    #[cfg(feature = "keymgr")]
    #[allow(clippy::unnecessary_wraps)]
    fn validate(&self) -> Result<(), ConfigBuildError> {
        Ok(())
    }

    /// Add a `CTorServiceKeystoreConfigBuilder` to this builder.
    pub fn ctor_service(&mut self, builder: CTorServiceKeystoreConfigBuilder) -> &mut Self {
        self.ctor.ctor_service(builder);
        self
    }
}

impl CTorKeystoreConfigBuilder {
    /// Ensure no C Tor keystores are configured.
    /// (C Tor keystores are only supported if the `ctor-keystore` is enabled).
    #[cfg(not(feature = "ctor-keystore"))]
    fn validate(&self) -> Result<(), ConfigBuildError> {
        let no_compile_time_support = |field: &str| ConfigBuildError::NoCompileTimeSupport {
            field: field.into(),
            problem: format!("{field} configured but ctor-keystore feature not enabled"),
        };

        if self
            .services
            .stores
            .as_ref()
            .map(|s| !s.is_empty())
            .unwrap_or_default()
        {
            return Err(no_compile_time_support("C Tor service keystores"));
        }

        if self
            .clients
            .stores
            .as_ref()
            .map(|s| !s.is_empty())
            .unwrap_or_default()
        {
            return Err(no_compile_time_support("C Tor client keystores"));
        }

        Ok(())
    }

    /// Validate the configured C Tor keystores.
    #[cfg(feature = "ctor-keystore")]
    fn validate(&self) -> Result<(), ConfigBuildError> {
        use itertools::chain;
        use itertools::Itertools as _;

        let Self {
            ref services,
            ref clients,
        } = self;
        let mut ctor_store_ids = chain![
            services.stores.iter().flatten().map(|s| &s.id),
            clients.stores.iter().flatten().map(|s| &s.id)
        ];

        // This is also validated by the KeyMgrBuilder (but it's a good idea to catch this sort of
        // mistake at configuration-time regardless).
        if !ctor_store_ids.all_unique() {
            return Err(ConfigBuildError::Inconsistent {
                fields: ["id"].map(Into::into).into_iter().collect(),
                problem: "the C Tor keystores do not have unique IDs".into(),
            });
        }

        Ok(())
    }

    /// Add a `CTorServiceKeystoreConfigBuilder` to this builder.
    pub fn ctor_service(&mut self, builder: CTorServiceKeystoreConfigBuilder) -> &mut Self {
        if let Some(ref mut stores) = self.services.stores {
            stores.push(builder);
        } else {
            self.services.stores = Some(vec![builder]);
        }

        self
    }
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

    use super::*;

    use std::path::PathBuf;
    use std::str::FromStr as _;
    use tor_config::assert_config_error;

    /// Helper for creating [`CTorServiceKeystoreConfigBuilders`].
    fn svc_config_builder(
        id: &str,
        path: &str,
        nickname: &str,
    ) -> CTorServiceKeystoreConfigBuilder {
        let mut b = CTorServiceKeystoreConfigBuilder::default();
        b.id(KeystoreId::from_str(id).unwrap());
        b.path(PathBuf::from(path));
        b.nickname(HsNickname::from_str(nickname).unwrap());
        b
    }

    /// Helper for creating [`CTorClientKeystoreConfigBuilders`].
    fn client_config_builder(id: &str, path: &str) -> CTorClientKeystoreConfigBuilder {
        let mut b = CTorClientKeystoreConfigBuilder::default();
        b.id(KeystoreId::from_str(id).unwrap());
        b.path(PathBuf::from(path));
        b
    }

    #[test]
    #[cfg(all(feature = "ctor-keystore", feature = "keymgr"))]
    fn invalid_config() {
        let mut builder = ArtiKeystoreConfigBuilder::default();
        // Push two clients with the same (default) ID:
        builder
            .ctor()
            .clients()
            .access()
            .push(client_config_builder("foo", "/var/lib/foo"));

        builder
            .ctor()
            .clients()
            .access()
            .push(client_config_builder("foo", "/var/lib/bar"));
        let err = builder.build().unwrap_err();

        assert_config_error!(
            err,
            Inconsistent,
            "the C Tor keystores do not have unique IDs"
        );

        let mut builder = ArtiKeystoreConfigBuilder::default();
        // Push two services with the same ID:
        builder
            .ctor_service(svc_config_builder("foo", "/var/lib/foo", "pungent"))
            .ctor_service(svc_config_builder("foo", "/var/lib/foo", "pungent"));
        let err = builder.build().unwrap_err();

        assert_config_error!(
            err,
            Inconsistent,
            "the C Tor keystores do not have unique IDs"
        );

        let mut builder = ArtiKeystoreConfigBuilder::default();
        // Push two services with different IDs but same nicknames:
        builder
            .ctor_service(svc_config_builder("foo", "/var/lib/foo", "pungent"))
            .ctor_service(svc_config_builder("bar", "/var/lib/bar", "pungent"));
        let err = builder.build().unwrap_err();

        assert_config_error!(
            err,
            Inconsistent,
            "Multiple C Tor service keystores for service with nickname pungent"
        );
    }

    #[test]
    #[cfg(all(not(feature = "ctor-keystore"), feature = "keymgr"))]
    fn invalid_config() {
        let mut builder = ArtiKeystoreConfigBuilder::default();
        builder
            .ctor()
            .clients()
            .access()
            .push(client_config_builder("foo", "/var/lib/foo"));
        let err = builder.build().unwrap_err();

        assert_config_error!(
            err,
            NoCompileTimeSupport,
            "C Tor client keystores configured but ctor-keystore feature not enabled"
        );

        let mut builder = ArtiKeystoreConfigBuilder::default();
        builder.ctor_service(svc_config_builder("foo", "/var/lib/foo", "pungent"));
        let err = builder.build().unwrap_err();

        assert_config_error!(
            err,
            NoCompileTimeSupport,
            "C Tor service keystores configured but ctor-keystore feature not enabled"
        );
    }

    #[test]
    #[cfg(not(feature = "keymgr"))]
    fn invalid_config() {
        let mut builder = ArtiKeystoreConfigBuilder::default();
        builder.enabled(BoolOrAuto::Explicit(true));

        let err = builder.build().unwrap_err();
        assert_config_error!(
            err,
            Inconsistent,
            "keystore enabled=true, but keymgr feature not enabled"
        );
    }

    #[test]
    #[cfg(feature = "ctor-keystore")]
    fn valid_config() {
        let mut builder = ArtiKeystoreConfigBuilder::default();
        builder
            .ctor()
            .clients()
            .access()
            .push(client_config_builder("foo", "/var/lib/foo"));
        builder
            .ctor()
            .clients()
            .access()
            .push(client_config_builder("bar", "/var/lib/bar"));

        let res = builder.build();
        assert!(res.is_ok(), "{:?}", res);
    }

    #[test]
    #[cfg(all(not(feature = "ctor-keystore"), feature = "keymgr"))]
    fn valid_config() {
        let mut builder = ArtiKeystoreConfigBuilder::default();
        builder
            .enabled(BoolOrAuto::Explicit(true))
            .primary()
            .kind(ExplicitOrAuto::Explicit(ArtiKeystoreKind::Native));

        let res = builder.build();
        assert!(res.is_ok(), "{:?}", res);
    }
}
