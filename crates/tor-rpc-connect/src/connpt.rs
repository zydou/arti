//! Connect point types, and the code to parse them and resolve them.

use serde::Deserialize;
use std::{fmt::Debug, path::PathBuf, str::FromStr};
use tor_config_path::{
    addr::{CfgAddr, CfgAddrError},
    CfgPath, CfgPathError,
};
use tor_general_addr::general;

use crate::HasClientErrorAction;

/// A connect point, as deserialized from TOML.
///
/// Connect points tell an RPC client how to reach an RPC server,
/// and tell an RPC server where and how to listen for connections for RPC clients.
///
/// This type may have members containing symbolic paths, such as
/// `${USER_HOME}` or `${ARTI_LOCAL_STATE}`.
/// To convert these paths to a usable format,
/// invoke [`ParsedConnectPoint::resolve()`] on this object.
#[derive(Clone, Debug)]
pub struct ParsedConnectPoint(ConnectPointEnum<Unresolved>);

/// A connect point, with all paths resolved.
///
/// Connect points tell an RPC client how to reach an RPC server,
/// and tell an RPC server where and how to listen for connections for RPC clients.
///
/// This type is returned by [`ParsedConnectPoint::resolve()`],
/// and can be used to connect or bind.
#[derive(Clone, Debug)]
pub struct ResolvedConnectPoint(pub(crate) ConnectPointEnum<Resolved>);

impl ParsedConnectPoint {
    /// Try to resolve all symbolic paths in this connect point,
    /// using the rules of [`CfgPath`] and [`CfgAddr`].
    pub fn resolve(&self) -> Result<ResolvedConnectPoint, ResolveError> {
        use ConnectPointEnum as CPE;
        // TODO RPC: Make sure that all paths are absolute after we resolve them.
        //
        // See also #1748, #1749.
        Ok(ResolvedConnectPoint(match &self.0 {
            CPE::Connect(connect) => CPE::Connect(connect.resolve()?),
            CPE::Builtin(builtin) => CPE::Builtin(builtin.clone()),
        }))
    }
}

impl FromStr for ParsedConnectPoint {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let de: ConnectPointDe = toml::from_str(s).map_err(ParseError::InvalidConnectPoint)?;
        Ok(ParsedConnectPoint(de.try_into()?))
    }
}

/// A failure from [`ParsedConnectPoint::from_str()`].
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// The input was not valid toml, or was an invalid connect point.
    #[error("Invalid connect point")]
    InvalidConnectPoint(#[source] toml::de::Error),
    /// The input had sections or members
    /// that are not allowed to appear in the same connect point.
    #[error("Conflicting members in connect point")]
    ConflictingMembers,
    /// The input was valid toml, but did not have any recognized
    /// connect point section.
    #[error("Unrecognized format on connect point")]
    UnrecognizedFormat,
}
impl HasClientErrorAction for ParseError {
    fn client_action(&self) -> crate::ClientErrorAction {
        use crate::ClientErrorAction as A;
        match self {
            ParseError::InvalidConnectPoint(_) => A::Abort,
            ParseError::ConflictingMembers => A::Abort,
            ParseError::UnrecognizedFormat => A::Decline,
        }
    }
}

/// A failure from [`ParsedConnectPoint::resolve()`].
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ResolveError {
    /// There was a path in the connect point that we couldn't resolve.
    #[error("Unable to resolve variables in path")]
    InvalidPath(#[from] CfgPathError),
    /// There was an address in the connect point that we couldn't resolve.
    #[error("Unable to resolve variables in address")]
    InvalidAddr(#[from] CfgAddrError),
    /// After substitution, we couldn't expand the path to a string.
    #[error("Cannot represent expanded path as string")]
    PathNotString,
    /// Address is not a loopback address.
    #[error("Tried to bind or connect to a non-loopback TCP address")]
    AddressNotLoopback,
    /// Authorization mechanism not compatible with address family
    #[error("Authorization type not compatible with address family")]
    AuthNotCompatible,
    /// Authorization mechanism not recognized
    #[error("Authorization type not recognized as a supported type")]
    AuthNotRecognized,
}
impl HasClientErrorAction for ResolveError {
    fn client_action(&self) -> crate::ClientErrorAction {
        use crate::ClientErrorAction as A;
        match self {
            ResolveError::InvalidPath(e) => e.client_action(),
            ResolveError::InvalidAddr(e) => e.client_action(),
            ResolveError::PathNotString => A::Decline,
            ResolveError::AddressNotLoopback => A::Decline,
            ResolveError::AuthNotCompatible => A::Abort,
            ResolveError::AuthNotRecognized => A::Decline,
        }
    }
}

/// Implementation type for a connect point.
///
/// This type is hidden so that the enum fields remain private.
/// It is parameterized on a [`Reps`] trait,
/// to indicate whether it is in resolved or unresolved form.
#[derive(Clone, Debug)]
pub(crate) enum ConnectPointEnum<R: Reps> {
    /// Connect by opening a socket to a [`general::SocketAddr`]
    Connect(Connect<R>),
    /// Connect by some built-in mechanism.
    ///
    /// (Or, in the case of Abort, do not connect at all.)
    Builtin(Builtin),
}

/// Trait to hold types that vary depending on whether a connect point is resolved or not.
//
// Note: We could use instead separate `PATH` and `ADDR` parameters,
// but this approach makes specifying bounds significantly easier.
pub(crate) trait Reps {
    /// Type to represent addresses that we can open a socket to.
    type SocketAddr: Clone + std::fmt::Debug;
    /// Type to represent paths on the filesystem.
    type Path: Clone + std::fmt::Debug;
}

/// Representation of a connect point as deserialized.
///
/// We could instead deserialize [`ConnectPointEnum`] directly,
/// but that would restrict our error-handling:
/// the `toml` crate doesn't make it easy to distinguish
/// one kind of parse error from another.
///
/// TODO We should revisit this choice when we add more variants
/// or more auxiliary tables.
#[derive(Deserialize, Clone, Debug)]
struct ConnectPointDe {
    /// A "connect" table.
    connect: Option<Connect<Unresolved>>,
    /// A "builtin" table.
    builtin: Option<Builtin>,
}
impl TryFrom<ConnectPointDe> for ConnectPointEnum<Unresolved> {
    type Error = ParseError;

    fn try_from(value: ConnectPointDe) -> Result<Self, Self::Error> {
        match value {
            ConnectPointDe {
                connect: Some(c),
                builtin: None,
            } => Ok(ConnectPointEnum::Connect(c)),
            ConnectPointDe {
                connect: None,
                builtin: Some(b),
            } => Ok(ConnectPointEnum::Builtin(b)),
            ConnectPointDe {
                connect: Some(_),
                builtin: Some(_),
            } => Err(ParseError::ConflictingMembers),
            // This didn't have either recognized section,
            // so it is likely itn an unrecognized format.
            _ => Err(ParseError::UnrecognizedFormat),
        }
    }
}

/// A "builtin" connect point.
///
/// This represents an approach to connecting that is handled purely
/// within arti.  In the future, this might include "embedded" or "owned";
/// but for now, it only includes "abort".
#[derive(Deserialize, Clone, Debug)]
pub(crate) struct Builtin {
    /// Actual strategy of built-in behavior to implement.
    pub(crate) builtin: BuiltinVariant,
}

/// A particular built-in strategy.
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "lowercase")]
pub(crate) enum BuiltinVariant {
    /// This connect point must fail,
    /// and no subsequent connect points may be tried.
    Abort,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(bound = "R::Path : Deserialize<'de>, AddrWithStr<R::SocketAddr> : Deserialize<'de>")]
pub(crate) struct Connect<R: Reps> {
    /// The address of the socket at which the client should try to reach the RPC server,
    /// and which the RPC server should bind.
    pub(crate) socket: AddrWithStr<R::SocketAddr>,
    /// The address of the socket which the RPC server believes it is actually listening at.
    ///
    /// If absent, defaults to `socket`.
    ///
    /// This value is only needs to be different from `socket`
    /// in cases where cookie authentication is in use,
    /// and the client is sandboxed somehow (such as behind a NAT, or inside a container).
    pub(crate) socket_canonical: Option<AddrWithStr<R::SocketAddr>>,
    /// The authentication that the client should try to use,
    /// and which the server should require.
    pub(crate) auth: Auth<R>,
}

impl Connect<Unresolved> {
    /// Convert all symbolic paths within this Connect to their resolved forms.
    fn resolve(&self) -> Result<Connect<Resolved>, ResolveError> {
        let socket = self.socket.resolve()?;
        let socket_canonical = self
            .socket_canonical
            .as_ref()
            .map(|sc| sc.resolve())
            .transpose()?;
        let auth = self.auth.resolve()?;
        Connect {
            socket,
            socket_canonical,
            auth,
        }
        .validate()
    }
}

impl Connect<Resolved> {
    /// Return this `Connect` only if its parts are valid and compatible.
    fn validate(self) -> Result<Self, ResolveError> {
        use general::SocketAddr::Inet;
        match (self.socket.as_ref(), &self.auth) {
            (Inet(addr), _) if !addr.ip().is_loopback() => Err(ResolveError::AddressNotLoopback),
            (Inet(_), Auth::None) => Err(ResolveError::AuthNotCompatible),
            (_, Auth::Unrecognized) => Err(ResolveError::AuthNotRecognized),
            (_, _) => Ok(self),
        }
    }
}

/// An authentication method for RPC implementations to use,
/// along with its related parameters.
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Auth<R: Reps> {
    /// No authentication is needed or should be expected.
    None,
    /// Cookie-based authentication should be used.
    Cookie {
        /// Path to the cookie file.
        path: R::Path,
    },
    /// Unrecognized authentication method.
    #[serde(other)]
    Unrecognized,
}

impl Auth<Unresolved> {
    /// Convert all symbolic paths within this `Auth` to their resolved forms.
    fn resolve(&self) -> Result<Auth<Resolved>, ResolveError> {
        match self {
            Auth::None => Ok(Auth::None),
            Auth::Cookie { path } => Ok(Auth::Cookie { path: path.path()? }),
            Auth::Unrecognized => Ok(Auth::Unrecognized),
        }
    }
}

/// Type parameters for unresolved connect points
//
// This derive should be needless, but it permits derive(Clone,Debug) elsewhere.
#[derive(Clone, Debug)]
struct Unresolved;
impl Reps for Unresolved {
    type SocketAddr = CfgAddr;
    type Path = CfgPath;
}

/// Type parameters for resolved connect points
//
// This derive should be needless, but it permits derive(Clone,Debug) elsewhere.
#[derive(Clone, Debug)]
pub(crate) struct Resolved;
impl Reps for Resolved {
    type SocketAddr = general::SocketAddr;
    type Path = PathBuf;
}

/// Represent an address type along with the string it was decoded from.
///
/// We use this type in connect points because, for some kinds of authentication,
/// we need the literal input string that created the address.
#[derive(Clone, Debug, derive_more::AsRef, serde_with::DeserializeFromStr)]
pub(crate) struct AddrWithStr<A>
where
    A: Clone + Debug,
{
    /// The string representation of the address.
    ///
    /// For inet addresses, this is the value that appeared in the configuration.
    /// For unix addresses, this is the value that appeared in the configuration,
    /// after shell expansion.
    string: String,
    /// The address itself.
    #[as_ref]
    addr: A,
}
impl AddrWithStr<CfgAddr> {
    /// Convert an `AddrWithStr<CfgAddr>` into its substituted form.
    pub(crate) fn resolve(&self) -> Result<AddrWithStr<general::SocketAddr>, ResolveError> {
        let AddrWithStr { string, addr } = self;
        let substituted = addr.substitutions_will_apply();
        let addr = addr.address()?;
        let string = if substituted {
            addr.try_to_string().ok_or(ResolveError::PathNotString)?
        } else {
            string.clone()
        };
        Ok(AddrWithStr { string, addr })
    }
}
impl<A> FromStr for AddrWithStr<A>
where
    A: Clone + Debug + FromStr,
{
    type Err = <A as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let addr = s.parse()?;
        let string = s.to_owned();
        Ok(Self { string, addr })
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

    fn parse(s: &str) -> ParsedConnectPoint {
        s.parse().unwrap()
    }

    #[test]
    fn examples() {
        let _e1 = parse(
            r#"
[builtin]
builtin = "abort"
"#,
        );

        let _e2 = parse(
            r#"
[connect]
socket = "unix:/var/run/arti/rpc_socket"
auth = "none"
"#,
        );

        let _e3 = parse(
            r#"
[connect]
socket = "inet:[::1]:9191"
socket_canonical = "inet:[::1]:2020"

auth = { cookie = { path = "/home/user/.arti_rpc/cookie" } }
"#,
        );

        let _e4 = parse(
            r#"
[connect]
socket = "inet:[::1]:9191"
socket_canonical = "inet:[::1]:2020"

[connect.auth.cookie]
path = "/home/user/.arti_rpc/cookie"
"#,
        );
    }

    #[test]
    fn parse_errors() {
        let r: Result<ParsedConnectPoint, _> = "not a toml string".parse();
        assert_matches!(r, Err(ParseError::InvalidConnectPoint(_)));

        let r: Result<ParsedConnectPoint, _> = "[squidcakes]".parse();
        assert_matches!(r, Err(ParseError::UnrecognizedFormat));
    }
}
