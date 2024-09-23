//! Configuration options for types implementing [`Keystore`](crate::Keystore)

pub use tor_config::{CfgPath, CfgPathError, ConfigBuildError, ConfigurationSource, Reconfigure};

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use tor_config::{impl_not_auto_value, impl_standard_builder, BoolOrAuto, ExplicitOrAuto};
use tracing::warn;

/// The kind of keystore to use
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ArtiKeystoreKind {
    /// Do not use a KeyStore
    Disabled,
    /// Use the ArtiNativeKeystore
    Native,
    /// Use the ArtiEphemeralKeystore
    #[cfg(feature = "ephemeral-keystore")]
    Ephemeral,
}
impl_not_auto_value! {ArtiKeystoreKind}

impl Default for ArtiKeystoreKind {
    fn default() -> Self {
        if cfg!(feature = "keymgr") {
            ArtiKeystoreKind::Native
        } else {
            ArtiKeystoreKind::Disabled
        }
    }
}

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

    /// The type of keystore to use, or none at all.
    #[builder_field_attr(serde(default))]
    #[builder(default)]
    kind: ExplicitOrAuto<ArtiKeystoreKind>,
}

impl ArtiKeystoreConfig {
    /// The type of keystore to use
    pub fn kind(&self) -> ArtiKeystoreKind {
        use BoolOrAuto as BoA;
        match self.enabled {
            BoA::Explicit(true) | BoA::Auto => match self.kind.as_value() {
                Some(kind) => *kind,
                None => ArtiKeystoreKind::default(),
            },
            BoA::Explicit(false) => ArtiKeystoreKind::Disabled,
        }
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

        if self.enabled.is_some() {
            warn!("keystore.enabled config option is deprecated, use keystore.type instead");
        }

        match (self.enabled, self.kind) {
            // only enabled OR kind may be set, and when keymgr is not enabeld they must be false|disabled
            (Some(BoA::Explicit(false)), None) | (None, Some(EoA::Explicit(ArtiKeystoreKind::Disabled))) => Ok(()),
            // either neither are set, one or both are auto
            (None, None) | (Some(BoA::Auto), Some(EoA::Auto)) | (Some(BoA::Auto), None) | (None, Some(EoA::Auto)) => Ok(()),
            // both may not be explicitly set
            (Some(_), Some(_)) => Err(ConfigBuildError::Inconsistent {
                fields: ["enabled", "type"].map(Into::into).into_iter().collect(),
                problem: "keystore enabled and type may not both be present and non-auto".into(),
            }),
            _ => Err(ConfigBuildError::Inconsistent {
                fields: ["enabled", "type"].map(Into::into).into_iter().collect(),
                problem: "keystore enabled!=auto|false or type!=auto|disabled, but keymgr feature not enabled"
                    .into(),
            }),
        }
    }

    /// Check that the keystore configuration is valid
    #[cfg(feature = "keymgr")]
    #[allow(clippy::unnecessary_wraps)]
    fn validate(&self) -> Result<(), ConfigBuildError> {
        use BoolOrAuto as BoA;
        use ExplicitOrAuto as EoA;

        if self.enabled.is_some() {
            warn!("keystore.enabled config option is deprecated, use keystore.type instead");
        }

        match (self.enabled, self.kind) {
            // only enabled OR kind may be set
            (None, None) | (Some(_), None) | (None, Some(_)) => Ok(()),
            // or both may be auto
            (Some(BoA::Auto), Some(EoA::Auto)) => Ok(()),
            _ => Err(ConfigBuildError::Inconsistent {
                fields: ["enabled", "type"].map(Into::into).into_iter().collect(),
                problem: "keystore enabled and type may not both be present and non-auto".into(),
            }),
        }
    }
}
