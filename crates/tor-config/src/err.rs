//! Declare error types.

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

    /// There was a programming error somewhere in our code, or the calling code.
    #[error("Programming error")]
    Bug(#[from] tor_error::Bug),
}

impl HasKind for ReconfigureError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::InvalidConfigTransition
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
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
