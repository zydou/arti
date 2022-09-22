//! Support for identifying a particular transport.
//!
//! A "transport" is a mechanism to connect to a relay on the Tor network and
//! make a `Channel`. Currently, two types of transports exist: the "built-in"
//! transport, which uses TLS over TCP, and various anti-censorship transports,
//! which use TLS over other protocols to avoid detection by censors.

/// Identify a type of Transport.
///
/// If this crate is compiled with the `pt-client` feature, this type can
/// support pluggable transports; otherwise, only the built-in transport type is
/// supported.
#[derive(Debug, Clone, Default, Eq, PartialEq, Hash)]
pub struct TransportId(Inner);

/// Helper type to implement [`TransportId`].
///
/// This is a separate type so that TransportId can be opaque.
#[derive(Debug, Clone, Eq, PartialEq, Hash, educe::Educe)]
#[educe(Default)]
enum Inner {
    /// The built-in transport type.
    #[educe(Default)]
    BuiltIn,

    /// A pluggable transport type, specified by its name.
    #[cfg(feature = "pt-client")]
    Pluggable(String),
}

/// This identifier is used to indicate the built-in transport.
const BUILT_IN_ID: &str = "<none>";

impl std::str::FromStr for TransportId {
    type Err = TransportIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == BUILT_IN_ID {
            return Ok(TransportId(Inner::BuiltIn));
        };

        #[cfg(feature = "pt-client")]
        if is_well_formed_id(s) {
            Ok(TransportId(Inner::Pluggable(s.to_string())))
        } else {
            Err(TransportIdError::BadId(s.to_string()))
        }

        #[cfg(not(feature = "pt-client"))]
        Err(TransportIdError::NoSupport)
    }
}

impl std::fmt::Display for TransportId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Inner::BuiltIn => write!(f, "{}", BUILT_IN_ID),
            #[cfg(feature = "pt-client")]
            Inner::Pluggable(name) => write!(f, "{}", name),
        }
    }
}

/// Return true if `s` is a well-formed transport ID.
///
/// According to the specification, a well-formed transport ID follows the same
/// rules as a C99 identifier: It must follow the regular expression
/// `[a-zA-Z_][a-zA-Z0-9_]*`.
#[cfg(feature = "pt-client")]
fn is_well_formed_id(s: &str) -> bool {
    // It's okay to use a bytes iterator, since non-ascii strings are not
    // allowed.
    let mut bytes = s.bytes();

    if let Some(first) = bytes.next() {
        (first.is_ascii_alphabetic() || first == b'_')
            && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
    } else {
        false
    }
}

/// An error related to parsing a TransportId.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportIdError {
    /// Arti was compiled without client-side pluggable transport support, and
    /// we tried to use a pluggable transport.
    #[error("Not compiled with pluggable transport support")]
    NoSupport,

    /// Tried to parse a pluggable transport whose name was not well-formed.
    #[error("{0:?} is not a valid pluggable transport ID.")]
    BadId(String),
}

impl TransportId {
    /// Return true if this is the built-in transport.
    pub fn is_builtin(&self) -> bool {
        self.0 == Inner::BuiltIn
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::str::FromStr;

    #[test]
    fn builtin() {
        assert!(TransportId::default().is_builtin());
        assert_eq!(
            TransportId::default(),
            "<none>".parse().expect("Couldn't parse default ID")
        );
    }

    #[test]
    #[cfg(not(feature = "pt-client"))]
    fn nosupport() {
        // We should get this error whenever we parse a non-default PT and we have no PT support.
        assert!(matches!(
            TransportId::from_str("obfs4"),
            Err(TransportIdError::NoSupport)
        ));
    }

    #[test]
    #[cfg(feature = "pt-client")]
    fn wellformed() {
        for id in &["snowflake", "obfs4", "_ohai", "Z", "future_WORK2"] {
            assert!(is_well_formed_id(id));
        }

        for id in &[" ", "Mölm", "12345", ""] {
            assert!(!is_well_formed_id(id));
        }
    }

    #[test]
    #[cfg(feature = "pt-client")]
    fn parsing() {
        let obfs = TransportId::from_str("obfs4").unwrap();
        let dflt = TransportId::default();
        let dflt2 = TransportId::from_str("<none>").unwrap();
        let snow = TransportId::from_str("snowflake").unwrap();
        let obfs_again = TransportId::from_str("obfs4").unwrap();

        assert_eq!(obfs, obfs_again);
        assert_eq!(dflt, dflt2);
        assert_ne!(snow, obfs);
        assert_ne!(snow, dflt);

        assert!(matches!(
            TransportId::from_str("12345"),
            Err(TransportIdError::BadId(_))
        ));
    }
}
