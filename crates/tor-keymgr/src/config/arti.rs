//! Configuration options for types implementing [`Keystore`](crate::Keystore)

pub use tor_config::{CfgPath, CfgPathError, ConfigBuildError, ConfigurationSource, Reconfigure};

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use tor_config::{impl_not_auto_value, impl_standard_builder, BoolOrAuto, ExplicitOrAuto};

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
#[derive(Debug, Clone, Builder, Eq, PartialEq, Serialize, Deserialize)]
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

        match self.primary.kind {
            // only enabled OR kind may be set, and when keymgr is not enabeld they must be false|disabled
            None | Some(EoA::Auto) => Ok(()),
            _ => Err(ConfigBuildError::Inconsistent {
                fields: ["enabled", "kind"].map(Into::into).into_iter().collect(),
                problem: "kind!=auto, but keymgr feature not enabled".into(),
            }),
        }
    }

    /// Check that the keystore configuration is valid
    #[cfg(feature = "keymgr")]
    #[allow(clippy::unnecessary_wraps)]
    fn validate(&self) -> Result<(), ConfigBuildError> {
        Ok(())
    }
}
