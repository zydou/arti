//! Support for shell expansion in [`general::SocketAddr`].

use crate::{CfgPath, CfgPathError};
use serde::{Deserialize, Serialize};
use std::{io, net, path::PathBuf, str::FromStr, sync::Arc};
use tor_general_addr::{general, unix};

/// A variation of [`general::SocketAddr`] that allows shell expansions in Unix paths.
///
/// The string representation for these addresses is the same as for [`general::SocketAddr`];
/// but the shell expansion syntax is the same as for [`CfgPath`].
///
/// Shell expansion is only supported _within_ paths: Even if the user has set `${HOME}`
/// to `127.0.0.1`, the address `inet:${HOME}:9999` is a syntax error.
///
/// In addition to the "inet:" and "unix:" schemas supported by `general::SocketAddr`,
/// This type also supports a "unix-literal" schema,
/// to indicate that no shell expansion should occur.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(into = "CfgAddrSerde", try_from = "CfgAddrSerde")]
pub struct CfgAddr(AddrInner);

/// Implementation type for `CfgAddr`.
///
/// This is a separate type because we can't define an public enum with private members.
#[derive(Clone, Debug, Eq, PartialEq)]
enum AddrInner {
    /// An internet address (which will not be expanded).
    Inet(net::SocketAddr),
    /// A unix path.
    Unix(CfgPath),
}

impl CfgAddr {
    /// Create a new [`CfgAddr`] that will produce an `AF_UNIX` address
    /// corresponding to the provided path.
    ///
    /// Note that not all platforms support AF_UNIX addresses;
    /// on Windows, notably, expanding this path will produce an error.
    pub fn new_unix(path: CfgPath) -> Self {
        CfgAddr(AddrInner::Unix(path))
    }

    /// Return the [`general::SocketAddr`] produced by expanding this `CfgAddr`.
    pub fn address(&self) -> Result<general::SocketAddr, CfgAddrError> {
        match &self.0 {
            AddrInner::Inet(socket_addr) => {
                // Easy case: This is an inet address.
                Ok((*socket_addr).into())
            }
            AddrInner::Unix(cfg_path) => {
                #[cfg(not(unix))]
                {
                    // Give this error early on non-unix platforms, so that we don't confuse the user.
                    return Err(unix::NoUnixAddressSupport::default().into());
                }
                #[cfg(unix)]
                {
                    Ok(unix::SocketAddr::from_pathname(cfg_path.path()?)
                        .map_err(|e| CfgAddrError::ConstructUnixAddress(Arc::new(e)))?
                        .into())
                }
            }
        }
    }

    /// Helper: if possible, format this address as a String.
    ///
    /// (This will return Err(p) if this path is a literal unix path
    /// that can't be represented as a string.)
    //
    // This is a separate function so that it can form the basis of a "display_lossy"
    // implementation, assuming we need one.
    fn try_to_string(&self) -> Result<String, &PathBuf> {
        use crate::PathInner as PI;
        use AddrInner as AI;
        match &self.0 {
            AI::Inet(socket_addr) => Ok(format!("inet:{}", socket_addr)),
            AI::Unix(cfg_path) => match &cfg_path.0 {
                PI::Shell(s) => Ok(format!("unix:{}", s)),
                PI::Literal(path) => match path.literal.to_str() {
                    Some(literal_as_str) => Ok(format!("unix-literal:{}", literal_as_str)),
                    None => Err(&path.literal),
                },
            },
        }
    }
}

/// Error produced when trying to expand a [`CfgAddr`] into a [`general::SocketAddr`].
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CfgAddrError {
    /// Tried to expand a `unix:` address on a platform where we don't support `AF_UNIX` addresses.
    #[error("No support for AF_UNIX addresses on this platform")]
    NoUnixAddressSupport(#[from] unix::NoUnixAddressSupport),
    /// Unable to expand the underlying `CfgPath`, likely due to syntax or missing variables.
    #[error("Could not expand path")]
    Path(#[from] CfgPathError),
    /// Unable to create an AF_UNIX address from a path.
    ///
    /// (This can happen if the path is too long, or contains internal NULs.)
    #[error("Could not construct unix address")]
    ConstructUnixAddress(#[source] Arc<io::Error>),
}

impl FromStr for CfgAddr {
    type Err = general::AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // NOTE: This logic is mostly duplicated from <FromStr for general::SocketAddr>;
        // I don't see an easy way to deduplicate it.
        if s.starts_with(|c: char| (c.is_ascii_digit() || c == '[')) {
            // This looks like an inet address, and cannot be a qualified address.
            Ok(s.parse::<net::SocketAddr>()?.into())
        } else if let Some((schema, remainder)) = s.split_once(':') {
            match schema {
                "unix" => {
                    let path = CfgPath::new(remainder.to_string());
                    Ok(CfgAddr::new_unix(path))
                }
                "unix-literal" => {
                    let path = CfgPath::new_literal(remainder.to_string());
                    Ok(CfgAddr::new_unix(path))
                }
                "inet" => Ok(remainder.parse::<net::SocketAddr>()?.into()),
                _ => Err(general::AddrParseError::UnrecognizedSchema(
                    schema.to_string(),
                )),
            }
        } else {
            Err(general::AddrParseError::NoSchema)
        }
    }
}

impl From<net::SocketAddr> for CfgAddr {
    fn from(value: net::SocketAddr) -> Self {
        CfgAddr(AddrInner::Inet(value))
    }
}
impl TryFrom<unix::SocketAddr> for CfgAddr {
    type Error = UnixAddrNotAPath;

    fn try_from(value: unix::SocketAddr) -> Result<Self, Self::Error> {
        // We don't need to check `#[cfg(unix)]` here:
        // if unix::SocketAddr is inhabited, then we can construct the Unix variant.
        Ok(Self::new_unix(CfgPath::new_literal(
            value.as_pathname().ok_or(UnixAddrNotAPath)?,
        )))
    }
}
// NOTE that we deliberately _don't_ implement From<Path> or From<CfgPath>;
// we want to keep open the possibility that there may be non-Unix path-based
// addresses in the future!

/// Error returned when trying to convert a non-path `unix::SocketAddr` into a `CfgAddr` .
#[derive(Clone, Debug, Default, thiserror::Error)]
#[non_exhaustive]
#[error("Unix address was not a path.")]
pub struct UnixAddrNotAPath;

/// Serde helper: We convert CfgAddr through this format in order to serialize and deserialize it.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum CfgAddrSerde {
    /// We serialize most types as a string.
    Str(String),
    /// We have another format for representing unix address literals
    /// that can't be represented as a string.
    UnixLiteral {
        /// A path that won't be expanded.
        unix_literal: PathBuf,
    },
}

impl TryFrom<CfgAddrSerde> for CfgAddr {
    type Error = general::AddrParseError;

    fn try_from(value: CfgAddrSerde) -> Result<Self, Self::Error> {
        use CfgAddrSerde as S;
        match value {
            S::Str(s) => s.parse(),
            S::UnixLiteral { unix_literal } => {
                Ok(CfgAddr::new_unix(CfgPath::new_literal(unix_literal)))
            }
        }
    }
}
impl From<CfgAddr> for CfgAddrSerde {
    fn from(value: CfgAddr) -> Self {
        match value.try_to_string() {
            Ok(s) => CfgAddrSerde::Str(s),
            Err(unix_literal) => CfgAddrSerde::UnixLiteral {
                unix_literal: unix_literal.clone(),
            },
        }
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
    use assert_matches::assert_matches;
    use std::path::PathBuf;

    #[test]
    fn parse_inet_ok() {
        fn check(s: &str) {
            let a: general::SocketAddr = CfgAddr::from_str(s).unwrap().address().unwrap();
            assert_eq!(a, general::SocketAddr::from_str(s).unwrap());
        }

        check("127.0.0.1:9999");
        check("inet:127.0.0.1:9999");
        check("[2001:db8::413]:443");
        check("inet:[2001:db8::413]:443");
    }

    #[test]
    fn parse_inet_bad() {
        assert_matches!(
            CfgAddr::from_str("612"),
            Err(general::AddrParseError::InvalidInetAddress(_))
        );
        assert_matches!(
            CfgAddr::from_str("612unix:/home"),
            Err(general::AddrParseError::InvalidInetAddress(_))
        );
        assert_matches!(
            CfgAddr::from_str("127.0.0.1.1:99"),
            Err(general::AddrParseError::InvalidInetAddress(_))
        );
        assert_matches!(
            CfgAddr::from_str("inet:6"),
            Err(general::AddrParseError::InvalidInetAddress(_))
        );
        assert_matches!(
            CfgAddr::from_str("[[[[[]]]]]"),
            Err(general::AddrParseError::InvalidInetAddress(_))
        );
    }

    #[test]
    fn parse_bad_schemas() {
        assert_matches!(
            CfgAddr::from_str("uranian:umbra"),
            Err(general::AddrParseError::UnrecognizedSchema(_))
        );
    }

    #[test]
    fn unix_literal() {
        let pb = PathBuf::from("${USER_HOME}/.local/socket");
        let a1 = CfgAddr::new_unix(CfgPath::new_literal(&pb));
        let a2 = CfgAddr::from_str("unix-literal:${USER_HOME}/.local/socket").unwrap();
        #[cfg(unix)]
        {
            assert_eq!(a1.address().unwrap(), a2.address().unwrap());
            match a1.address().unwrap() {
                general::SocketAddr::Unix(socket_addr) => {
                    // can't use assert_eq because these types are not Debug.
                    assert!(socket_addr.as_pathname() == Some(pb.as_ref()));
                }
                _ => panic!("Expected a unix address"),
            }
        }
        #[cfg(not(unix))]
        assert_matches!(a.address(), Err(CfgAddrError::NoUnixAddressSupport(_)));
    }

    fn try_unix(addr: &str, want: &str) {
        let p = CfgPath::new(want.to_string());
        let expansion = p.path().unwrap();
        let cfg_addr = CfgAddr::from_str(addr).unwrap();
        assert_matches!(&cfg_addr.0, AddrInner::Unix(_));
        #[cfg(unix)]
        {
            let gen_addr = cfg_addr.address().unwrap();
            let expected_addr = unix::SocketAddr::from_pathname(expansion).unwrap();
            assert_eq!(gen_addr, expected_addr.into());
        }
        #[cfg(not(unix))]
        {
            assert_matches!(
                cfg_addr.address(),
                Err(CfgAddrError::NoUnixAddressSupport(_))
            );
        }
    }

    #[test]
    fn unix_no_substitution() {
        try_unix("unix:/home/mayor/.socket", "/home/mayor/.socket");
    }

    #[test]
    #[cfg(feature = "expand-paths")]
    fn unix_substitution() {
        try_unix("unix:${PROGRAM_DIR}/socket", "${PROGRAM_DIR}/socket");
    }

    #[test]
    fn serde() {
        fn testcase_with_provided_addr(json: &str, addr: &CfgAddr) {
            let a1: CfgAddr = serde_json::from_str(json).unwrap();
            assert_eq!(&a1, addr);
            let encoded = serde_json::to_string(&a1).unwrap();
            let a2: CfgAddr = serde_json::from_str(&encoded).unwrap();
            assert_eq!(&a2, addr);
        }
        fn testcase(json: &str, addr: &str) {
            let addr = CfgAddr::from_str(addr).unwrap();
            testcase_with_provided_addr(json, &addr);
        }

        testcase(r#" "inet:127.0.0.1:443" "#, "inet:127.0.0.1:443");
        testcase(r#" "unix:${HOME}/socket" "#, "unix:${HOME}/socket");
        testcase(
            r#" "unix-literal:${HOME}/socket" "#,
            "unix-literal:${HOME}/socket",
        );
    }
}
