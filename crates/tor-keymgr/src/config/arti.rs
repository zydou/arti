//! Configuration options for types implementing [`Keystore`](crate::Keystore)

pub use tor_config::{CfgPath, CfgPathError, ConfigBuildError, ConfigurationSource, Reconfigure};

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use tor_config::{impl_standard_builder, BoolOrAuto};

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
}

impl_standard_builder! { ArtiKeystoreConfig }

impl ArtiKeystoreConfigBuilder {
    /// Check that the keystore configuration is valid
    #[cfg(not(feature = "keymgr"))]
    #[allow(clippy::unnecessary_wraps)]
    fn validate(&self) -> Result<(), ConfigBuildError> {
        use BoolOrAuto as BoA;

        // Keystore support is disabled unless the `keymgr` feature is enabled.
        if self.enabled == Some(BoA::Explicit(true)) {
            return Err(ConfigBuildError::Inconsistent {
                fields: ["enabled"].map(Into::into).into_iter().collect(),
                problem: "keystore enabled=true, but keymgr feature not enabled".into(),
            });
        }

        Ok(())
    }

    /// Check that the keystore configuration is valid
    #[cfg(feature = "keymgr")]
    #[allow(clippy::unnecessary_wraps)]
    fn validate(&self) -> Result<(), ConfigBuildError> {
        Ok(())
    }
}

impl ArtiKeystoreConfig {
    /// Whether the keystore is enabled.
    pub fn is_enabled(&self) -> bool {
        let default = cfg!(feature = "keymgr");

        self.enabled.as_bool().unwrap_or(default)
    }
}
