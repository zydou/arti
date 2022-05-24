//! Processing a config::Config into a validated configuration

use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::ConfigBuildError;

/// Error resolveing a configuration (during deserialize, or build)
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ConfigResolveError {
    /// Deserialize failed
    #[error("config contents not as expected: {0}")]
    Deserialize(#[from] config::ConfigError),

    /// Build failed
    #[error("config semantically incorrect: {0}")]
    Build(#[from] ConfigBuildError),
}

/// A type that can be built from a builder via a build method
pub trait Builder {
    ///
    type Built;
    /// Build into a `Built`
    ///
    /// Often shadows an inherent `build` method
    fn build(&self) -> Result<Self::Built, ConfigBuildError>;
}
