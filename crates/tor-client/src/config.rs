//! Configuration logic for launching a circuit manager.

use derive_builder::Builder;
use serde::Deserialize;

/// Configuration for clients
///
/// This type is immutable once constructed. To create an object of this type,
/// use [`ClientConfigBuilder`].
#[derive(Debug, Clone, Builder, Deserialize)]
#[builder]
pub struct ClientConfig {
    /// Are we running as localhost?
    #[builder(default)]
    pub(crate) is_localhost: bool,
}

// NOTE: it seems that `unwrap` may be safe because of builder defaults
// check `derive_builder` documentation for details
// https://docs.rs/derive_builder/0.10.2/derive_builder/#default-values
#[allow(clippy::unwrap_used)]
impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfigBuilder::default().build().unwrap()
    }
}
