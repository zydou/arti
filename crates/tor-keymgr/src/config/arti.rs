//! Configuration options for [`ArtiNativeKeystore`](crate::ArtiNativeKeystore)

use std::path::PathBuf;

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
pub struct ArtiNativeKeystoreConfig {
    /// Whether keystore use is enabled.
    #[builder_field_attr(serde(default))]
    #[builder(default)]
    enabled: BoolOrAuto,

    /// Location on disk for the Arti keystore.
    #[builder_field_attr(serde(default))]
    #[builder(setter(into), default = "default_keystore_dir()")]
    path: CfgPath,
}

impl_standard_builder! { ArtiNativeKeystoreConfig }

impl ArtiNativeKeystoreConfigBuilder {
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

impl ArtiNativeKeystoreConfig {
    /// Try to expand `path` to be a path buffer.
    #[allow(clippy::unnecessary_wraps)] // needed because of the experimental-api branch
    pub fn expand_keystore_dir(&self) -> Result<PathBuf, ConfigBuildError> {
        self.path.path().map_err(|e| ConfigBuildError::Invalid {
            field: "path".to_owned(),
            problem: e.to_string(),
        })
    }

    /// Whether the keystore is enabled.
    pub fn is_enabled(&self) -> bool {
        let default = cfg!(feature = "keymgr");

        self.enabled.as_bool().unwrap_or(default)
    }
}

/// Return the default keystore directory.
fn default_keystore_dir() -> CfgPath {
    CfgPath::new("${ARTI_LOCAL_DATA}/keystore".to_owned())
}
