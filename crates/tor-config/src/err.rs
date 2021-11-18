//! Declare an error type.

/// An error related to an option passed to Arti via a configuration
/// builder.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigBuildError {
    /// A mandatory field was not present.
    #[error("Field was not provided: {field}")]
    MissingField {
        /// The name of the missing field.
        field: String,
    },
    /// A single field had a value that proved to be unusable.
    #[error("Value of {field} was incorrect: {problem}")]
    Invalid {
        /// The name of the invalid field
        field: String,
        /// A description of the problem.
        problem: String,
    },
    /// Multiple fields are inconsistent.
    #[error("Fields {fields:?} are inconsistent: {problem}")]
    Inconsistent {
        /// The names of the inconsistent fields
        fields: Vec<String>,
        /// The problem that makes them inconsistent
        problem: String,
    },
}

impl From<derive_builder::UninitializedFieldError> for ConfigBuildError {
    fn from(val: derive_builder::UninitializedFieldError) -> Self {
        ConfigBuildError::MissingField {
            field: val.field_name().to_string(),
        }
    }
}

impl ConfigBuildError {
    /// Return a new ConfigBuildError that prefixes its field name with
    /// `prefix` and a dot.
    pub fn within(&self, prefix: &str) -> Self {
        use ConfigBuildError::*;
        match self {
            MissingField { field } => MissingField {
                field: format!("{}.{}", prefix, field),
            },
            Invalid { field, problem } => Invalid {
                field: format!("{}.{}", prefix, field),
                problem: problem.clone(),
            },
            Inconsistent { fields, problem } => Inconsistent {
                fields: fields.iter().map(|f| format!("{}.{}", prefix, f)).collect(),
                problem: problem.clone(),
            },
        }
    }
}
