//! Error module for `tor-dirserver`

use thiserror::Error;

/// An error while building a builder struct to the target structure.
#[derive(Debug, Error)]
pub enum BuilderError {
    /// Some builders have mandatory fields (i.e. fields that must be set before
    /// calling `.build()`).  In those cases, we need to yield a semantic error.
    #[error("missing field: {0}")]
    MissingField(&'static str),
}
