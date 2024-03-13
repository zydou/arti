//! Declare error types.

use std::sync::Arc;

use tor_error::{ErrorKind, HasKind};

/// An error related to an option passed to Arti via a configuration
/// builder.
//
// API NOTE: When possible, we should expose this error type rather than
// wrapping it in `TorError`. It can provide specific information about  what
// part of the configuration was invalid.
//
// This is part of the public API.
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
    /// The requested configuration is not supported in this build
    #[error("Field {field:?} specifies a configuration not supported in this build: {problem}")]
    // TODO should we report the cargo feature, if applicable?  And if so, of `arti`
    // or of the underlying crate?  This seems like a can of worms.
    NoCompileTimeSupport {
        /// The names of the (primary) field requesting the unsupported configuration
        field: String,
        /// The description of the problem
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

impl From<derive_builder::SubfieldBuildError<ConfigBuildError>> for ConfigBuildError {
    fn from(e: derive_builder::SubfieldBuildError<ConfigBuildError>) -> Self {
        let (field, problem) = e.into_parts();
        problem.within(field)
    }
}

impl ConfigBuildError {
    /// Return a new ConfigBuildError that prefixes its field name with
    /// `prefix` and a dot.
    #[must_use]
    pub fn within(&self, prefix: &str) -> Self {
        use ConfigBuildError::*;
        let addprefix = |field: &str| format!("{}.{}", prefix, field);
        match self {
            MissingField { field } => MissingField {
                field: addprefix(field),
            },
            Invalid { field, problem } => Invalid {
                field: addprefix(field),
                problem: problem.clone(),
            },
            Inconsistent { fields, problem } => Inconsistent {
                fields: fields.iter().map(|f| addprefix(f)).collect(),
                problem: problem.clone(),
            },
            NoCompileTimeSupport { field, problem } => NoCompileTimeSupport {
                field: addprefix(field),
                problem: problem.clone(),
            },
        }
    }
}

impl HasKind for ConfigBuildError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::InvalidConfig
    }
}

/// An error caused when attempting to reconfigure an existing Arti client, or one of its modules.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum ReconfigureError {
    /// Tried to change a field that cannot change on a running client.
    #[error("Cannot change {field} on a running client.")]
    CannotChange {
        /// The field (or fields) that we tried to change.
        field: String,
    },

    /// The requested configuration is not supported in this situation
    ///
    /// Something, probably discovered at runtime, is not compatible with
    /// the specified configuration.
    ///
    /// This ought *not* to be returned when the configuration is simply not supported
    /// by this build of arti -
    /// that should be reported at config build type as `ConfigBuildError::Unsupported`.
    #[error("Configuration not supported in this situation: {0}")]
    UnsupportedSituation(String),

    /// There was a programming error somewhere in our code, or the calling code.
    #[error("Programming error")]
    Bug(#[from] tor_error::Bug),
}

impl HasKind for ReconfigureError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::InvalidConfigTransition
    }
}

/// Wrapper for an error type from our underlying configuration library.
#[derive(Debug, Clone)]
pub struct ConfigError(Arc<config::ConfigError>);

impl ConfigError {
    /// Wrap `err` as a ConfigError.
    ///
    /// This is not a From implementation, since we don't want to expose our
    /// underlying configuration library.
    pub(crate) fn from_cfg_err(err: config::ConfigError) -> Self {
        ConfigError(Arc::new(err))
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.0.to_string();
        write!(f, "{}", s)?;
        if s.contains("invalid escape") || s.contains("invalid hex escape") {
            write!(f, "   (If you wanted to include a literal \\ character, you need to escape it by writing two in a row: \\\\)")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
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

    #[test]
    fn within() {
        let e1 = ConfigBuildError::MissingField {
            field: "lettuce".to_owned(),
        };
        let e2 = ConfigBuildError::Invalid {
            field: "tomato".to_owned(),
            problem: "too crunchy".to_owned(),
        };
        let e3 = ConfigBuildError::Inconsistent {
            fields: vec!["mayo".to_owned(), "avocado".to_owned()],
            problem: "pick one".to_owned(),
        };

        assert_eq!(
            &e1.within("sandwich").to_string(),
            "Field was not provided: sandwich.lettuce"
        );
        assert_eq!(
            &e2.within("sandwich").to_string(),
            "Value of sandwich.tomato was incorrect: too crunchy"
        );
        assert_eq!(
            &e3.within("sandwich").to_string(),
            r#"Fields ["sandwich.mayo", "sandwich.avocado"] are inconsistent: pick one"#
        );
    }

    #[derive(derive_builder::Builder, Debug, Clone)]
    #[builder(build_fn(error = "ConfigBuildError"))]
    #[allow(dead_code)]
    struct Cephalopod {
        // arms have suction cups for their whole length
        arms: u8,
        // Tentacles have suction cups at the ends
        tentacles: u8,
    }

    #[test]
    fn build_err() {
        let squid = CephalopodBuilder::default().arms(8).tentacles(2).build();
        let octopus = CephalopodBuilder::default().arms(8).build();
        assert!(squid.is_ok());
        let squid = squid.unwrap();
        assert_eq!(squid.arms, 8);
        assert_eq!(squid.tentacles, 2);
        assert!(octopus.is_err());
        assert_eq!(
            &octopus.unwrap_err().to_string(),
            "Field was not provided: tentacles"
        );
    }

    #[derive(derive_builder::Builder, Debug)]
    #[builder(build_fn(error = "ConfigBuildError"))]
    #[allow(dead_code)]
    struct Pet {
        #[builder(sub_builder)]
        best_friend: Cephalopod,
    }

    #[test]
    fn build_subfield_err() {
        let mut petb = PetBuilder::default();
        petb.best_friend().tentacles(3);
        let pet = petb.build();
        assert_eq!(
            pet.unwrap_err().to_string(),
            "Field was not provided: best_friend.arms"
        );
    }
}
