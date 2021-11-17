//! Declare an error type.

/// An error related to an option passed to Arti via a configuration
/// builder.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigBuildError {
    /// A mandatory field was not present.
    #[error("Field was not provided: {0}")]
    MissingField(String),
    /// A single field had a value that proved to be unusable.
    #[error("Value of {0} was incorrect: {1}")]
    Invalid(String, String),
    /// Multiple fields are inconsistent.
    #[error("Fields {0:?} are inconsistent: {1}")]
    Inconsistent(Vec<String>, String),
}

impl From<derive_builder::UninitializedFieldError> for ConfigBuildError {
    fn from(val: derive_builder::UninitializedFieldError) -> Self {
        ConfigBuildError::MissingField(val.field_name().to_string())
    }
}

impl ConfigBuildError {
    /// Return a new ConfigBuildError that prefixes its field name with
    /// `prefix` and a dot.
    pub fn within(&self, prefix: &str) -> Self {
        use ConfigBuildError::*;
        match self {
            MissingField(f) => MissingField(format!("{}.{}", prefix, f)),
            Invalid(f, why) => Invalid(format!("{}.{}", prefix, f), why.clone()),
            Inconsistent(fs, why) => Inconsistent(
                fs.iter().map(|f| format!("{}.{}", prefix, f)).collect(),
                why.clone(),
            ),
        }
    }
}
