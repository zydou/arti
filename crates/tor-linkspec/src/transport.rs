//! Support for identifying a particular transport.
//!
//! A "transport" is a mechanism to connect to a relay on the Tor network and
//! make a `Channel`. Currently, two types of transports exist: the "built-in"
//! transport, which uses TLS over TCP, and various anti-censorship "pluggable
//! transports", which use TLS over other protocols to avoid detection by
//! censors.

use std::fmt::{self, Display};
use std::net::SocketAddr;
use std::slice;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::HasAddrs;

/// Identify a type of Transport.
///
/// If this crate is compiled with the `pt-client` feature, this type can
/// support pluggable transports; otherwise, only the built-in transport type is
/// supported.
///
/// This can be displayed as, or parsed from, a string.
/// `"-"` is used to indicate the builtin transport,
/// and `""` and `"bridge"` and `"<none>"` are also recognised for that.
//
// We recognise "bridge" as pluggable; "BRIDGE" is rejected as invalid.
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
    Pluggable(PtTransportName),
}

/// Pluggable transport name
///
/// The name for a pluggable transport.
/// The name has been syntax checked.
#[derive(
    Debug,
    Clone,
    Default,
    Eq,
    PartialEq,
    Hash,
    serde_with::DeserializeFromStr,
    serde_with::SerializeDisplay,
)]

pub struct PtTransportName(String);

impl FromStr for PtTransportName {
    type Err = TransportIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_string().try_into()
    }
}

impl TryFrom<String> for PtTransportName {
    type Error = TransportIdError;

    fn try_from(s: String) -> Result<PtTransportName, Self::Error> {
        if is_well_formed_id(&s) {
            Ok(PtTransportName(s))
        } else {
            Err(TransportIdError::BadId(s))
        }
    }
}

impl AsRef<str> for PtTransportName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PtTransportName {
    /// Return the name as a `String`
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Display for PtTransportName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

/// These identifiers are used to indicate the built-in transport.
///
/// When outputting string representations, the first (`"-"`) is used.
//
// Actual pluggable transport names are restricted to the syntax of C identifiers.
// These strings are deliberately not in that syntax so as to avoid clashes.
// `"bridge"` is likewise prohibited by the spec.
const BUILT_IN_IDS: &[&str] = &["-", "", "bridge", "<none>"];

impl FromStr for TransportId {
    type Err = TransportIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if BUILT_IN_IDS.contains(&s) {
            return Ok(TransportId(Inner::BuiltIn));
        };

        #[cfg(feature = "pt-client")]
        {
            let name: PtTransportName = s.parse()?;
            Ok(TransportId(Inner::Pluggable(name)))
        }

        #[cfg(not(feature = "pt-client"))]
        Err(TransportIdError::NoSupport)
    }
}

impl Display for TransportId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Inner::BuiltIn => write!(f, "{}", BUILT_IN_IDS[0]),
            #[cfg(feature = "pt-client")]
            Inner::Pluggable(name) => write!(f, "{}", name),
        }
    }
}

#[cfg(feature = "pt-client")]
impl From<PtTransportName> for TransportId {
    fn from(name: PtTransportName) -> Self {
        TransportId(Inner::Pluggable(name))
    }
}

/// Return true if `s` is a well-formed transport ID.
///
/// According to the specification, a well-formed transport ID follows the same
/// rules as a C99 identifier: It must follow the regular expression
/// `[a-zA-Z_][a-zA-Z0-9_]*`.
fn is_well_formed_id(s: &str) -> bool {
    // It's okay to use a bytes iterator, since non-ascii strings are not
    // allowed.
    let mut bytes = s.bytes();

    if let Some(first) = bytes.next() {
        (first.is_ascii_alphabetic() || first == b'_')
            && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
            && !s.eq_ignore_ascii_case("bridge")
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
    #[error("{0:?} is not a valid pluggable transport ID")]
    BadId(String),
}

impl TransportId {
    /// Return a new `TransportId` referencing the builtin transport
    ///
    /// This is equivalent to the `Default` impl.
    pub fn new_builtin() -> Self {
        TransportId(Inner::BuiltIn)
    }

    /// Return a new `TransportId` referencing a pluggable transport
    ///
    /// This is equivalent to the `From<PtTransportName>` impl.
    #[cfg(feature = "pt-client")]
    pub fn new_pluggable(pt: PtTransportName) -> Self {
        pt.into()
    }

    /// Return true if this is the built-in transport.
    pub fn is_builtin(&self) -> bool {
        self.0 == Inner::BuiltIn
    }

    /// Returns the pluggable transport name
    ///
    /// Or `None` if `self` doesn't specify a pluggable transport
    /// (e.g. if it specifies the builtin transport).
    #[cfg(feature = "pt-client")]
    pub fn as_pluggable(&self) -> Option<&PtTransportName> {
        match &self.0 {
            Inner::BuiltIn => None,
            #[cfg(feature = "pt-client")]
            Inner::Pluggable(pt) => Some(pt),
        }
    }

    /// Consumes this `TransportId` and returns the pluggable transport name
    ///
    /// Or `None` if `self` doesn't specify a pluggable transport
    /// (e.g. if it specifies the builtin transport).
    #[cfg(feature = "pt-client")]
    pub fn into_pluggable(self) -> Option<PtTransportName> {
        match self.0 {
            Inner::BuiltIn => None,
            #[cfg(feature = "pt-client")]
            Inner::Pluggable(pt) => Some(pt),
        }
    }
}

/// This identifier is used to indicate no transport address.
const NONE_ADDR: &str = "-";

/// An address that an be passed to a pluggable transport to tell it where to
/// connect (typically, to a bridge).
///
/// Not every transport accepts all kinds of addresses.
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, serde_with::DeserializeFromStr, serde_with::SerializeDisplay,
)]
#[non_exhaustive]
pub enum BridgeAddr {
    /// An IP address and port for a Tor relay.
    ///
    /// This is the only address type supported by the BuiltIn transport.
    IpPort(std::net::SocketAddr),
    /// A hostname-and-port target address.  Some transports may support this.
    HostPort(String, u16),
    /// A completely absent target address.  Some transports support this.
    None,
}

/// An error from parsing a [`BridgeAddr`].
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BridgeAddrError {
    /// We were compiled without support for addresses of this type.
    #[error("Not compiled with pluggable transport support.")]
    NoSupport,
    /// We cannot parse this address.
    #[error("Cannot parse {0:?} as an address.")]
    BadAddress(String),
}

impl FromStr for BridgeAddr {
    type Err = BridgeAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = s.parse() {
            Ok(BridgeAddr::IpPort(addr))
        } else if let Some((name, port)) = s.rsplit_once(':') {
            let port = port
                .parse()
                .map_err(|_| BridgeAddrError::BadAddress(s.to_string()))?;

            Ok(Self::HostPort(name.to_string(), port))
        } else if s == NONE_ADDR {
            Ok(Self::None)
        } else {
            Err(BridgeAddrError::BadAddress(s.to_string()))
        }
    }
}

impl Display for BridgeAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BridgeAddr::IpPort(addr) => write!(f, "{}", addr),
            BridgeAddr::HostPort(host, port) => write!(f, "{}:{}", host, port),
            BridgeAddr::None => write!(f, "{}", NONE_ADDR),
        }
    }
}

/// A set of options to be passed along to a pluggable transport along with a
/// single target bridge relay.
///
/// These options typically describe aspects of the targeted bridge relay that
/// are not included in its address and Tor keys, such as additional
/// transport-specific keys or parameters.
///
/// This type is _not_ for settings that apply to _all_ of the connections over
/// a transport.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(into = "Vec<(String, String)>", try_from = "Vec<(String, String)>")]
pub struct PtTargetSettings {
    /// A list of (key,value) pairs
    settings: Vec<(String, String)>,
}

impl PtTargetSettings {
    /// Return an error if `k,v` is not a valid setting.
    fn check_setting(k: &str, v: &str) -> Result<(), PtTargetInvalidSetting> {
        // Unfortunately the spec is not very clear about the valid syntax.
        // https://gitlab.torproject.org/tpo/core/torspec/-/issues/173
        //
        // For now we reject things that cannot be represented in a bridge line
        if k.find(|c: char| c == '=' || c.is_whitespace()).is_some() {
            return Err(PtTargetInvalidSetting::Key(k.to_string()));
        }
        if v.find(|c: char| c.is_whitespace()).is_some() {
            return Err(PtTargetInvalidSetting::Value(v.to_string()));
        }
        Ok(())
    }

    /// Add `k,v` to this list of settings, if it is valid.
    fn push_setting(
        &mut self,
        k: impl Into<String>,
        v: impl Into<String>,
    ) -> Result<(), PtTargetInvalidSetting> {
        let k = k.into();
        let v = v.into();
        Self::check_setting(&k, &v)?;
        self.settings.push((k, v));
        Ok(())
    }

    /// Return the inner list of (key, value) pairs
    pub fn into_inner(self) -> Vec<(String, String)> {
        self.settings
    }
}

impl TryFrom<Vec<(String, String)>> for PtTargetSettings {
    type Error = PtTargetInvalidSetting;

    fn try_from(settings: Vec<(String, String)>) -> Result<Self, Self::Error> {
        for (k, v) in settings.iter() {
            Self::check_setting(k, v)?;
        }
        Ok(Self { settings })
    }
}

impl From<PtTargetSettings> for Vec<(String, String)> {
    fn from(settings: PtTargetSettings) -> Self {
        settings.settings
    }
}

/// The set of information passed to the  pluggable transport subsystem in order
/// to establish a connection to a bridge relay.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct PtTarget {
    /// The transport to be used.
    transport: PtTransportName,
    /// The address of the bridge relay, if any.
    addr: BridgeAddr,
    /// Any additional settings used by the transport.
    #[serde(default)]
    settings: PtTargetSettings,
}

/// Invalid PT parameter setting
#[derive(Error, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PtTargetInvalidSetting {
    /// Currently: the key contains whitespace or `=`
    ///
    /// Will probably be generated for a greater variety of values
    /// when the spec is more nailed down.
    #[error("key {0:?} has invalid or unsupported syntax")]
    Key(String),

    /// Currently: the value contains whitespace
    ///
    /// Will probably be generated for a greater variety of values
    /// when the spec is more nailed down.
    #[error("value {0:?} has invalid or unsupported syntax")]
    Value(String),
}

impl PtTarget {
    /// Create a new `PtTarget` (with no settings)
    pub fn new(transport: PtTransportName, addr: BridgeAddr) -> Self {
        PtTarget {
            transport,
            addr,
            settings: Default::default(),
        }
    }

    /// Add a setting (to be passed during the SOCKS handshake)
    pub fn push_setting(
        &mut self,
        k: impl Into<String>,
        v: impl Into<String>,
    ) -> Result<(), PtTargetInvalidSetting> {
        self.settings.push_setting(k, v)
    }

    /// Get the transport name
    pub fn transport(&self) -> &PtTransportName {
        &self.transport
    }

    /// Get the transport target address (or host and port)
    pub fn addr(&self) -> &BridgeAddr {
        &self.addr
    }

    /// Iterate over the PT setting strings
    pub fn settings(&self) -> impl Iterator<Item = (&str, &str)> {
        self.settings.settings.iter().map(|(k, v)| (&**k, &**v))
    }

    /// Return all the advertized socket addresses to which this target may
    /// connect.
    ///
    /// Returns `Some(&[])` if there is no way to connect to this target, and
    /// `None` if this target does not use `SocketAddr` to connect
    ///
    /// NOTE that these are not necessarily an address to which you can open a
    /// TCP connection! The address will be interpreted by the implementation of
    /// this pluggable transport.
    pub fn socket_addrs(&self) -> Option<&[std::net::SocketAddr]> {
        match self {
            PtTarget {
                addr: BridgeAddr::IpPort(addr),
                ..
            } => Some(std::slice::from_ref(addr)),

            _ => None,
        }
    }

    /// Consume the `PtTarget` and return the component parts
    pub fn into_parts(self) -> (PtTransportName, BridgeAddr, PtTargetSettings) {
        (self.transport, self.addr, self.settings)
    }
}

/// The way to approach a single relay in order to open a channel.
///
/// For direct connections, this is simply an address.  For connections via a
/// pluggable transport, this includes information about the transport, and any
/// address and settings information that transport requires.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[allow(clippy::exhaustive_enums)]
pub enum ChannelMethod {
    /// Connect to the relay directly at one of several addresses.
    Direct(Vec<std::net::SocketAddr>),

    /// Connect to a bridge relay via a pluggable transport.
    #[cfg(feature = "pt-client")]
    Pluggable(PtTarget),
}

impl ChannelMethod {
    /// Return all the advertized socket addresses to which this method may connect.
    ///
    /// Returns `Some(&[])` if there is no way to connect to this target, and
    /// `None` if this target does not use `SocketAddr` to connect
    ///
    /// NOTE that these are not necessarily an address to which you can open a
    /// TCP connection! If this `ChannelMethod` is using a non-`Direct`
    /// transport, then this address will be interpreted by that transport's
    /// implementation.
    pub fn socket_addrs(&self) -> Option<&[std::net::SocketAddr]> {
        match self {
            ChannelMethod::Direct(addr) => Some(addr.as_ref()),

            #[cfg(feature = "pt-client")]
            ChannelMethod::Pluggable(t) => t.socket_addrs(),
        }
    }

    /// Return a BridgeAddr that this ChannelMethod uses.
    pub fn target_addr(&self) -> Option<BridgeAddr> {
        match self {
            ChannelMethod::Direct(addr) if !addr.is_empty() => Some(BridgeAddr::IpPort(addr[0])),

            #[cfg(feature = "pt-client")]
            ChannelMethod::Pluggable(PtTarget { addr, .. }) => Some(addr.clone()),

            _ => None,
        }
    }

    /// Return true if this is a method for a direct connection.
    pub fn is_direct(&self) -> bool {
        matches!(self, ChannelMethod::Direct(_))
    }

    /// Return an identifier for the Transport to be used by this `ChannelMethod`.
    pub fn transport_id(&self) -> TransportId {
        match self {
            ChannelMethod::Direct(_) => TransportId::default(),
            #[cfg(feature = "pt-client")]
            ChannelMethod::Pluggable(target) => target.transport().clone().into(),
        }
    }

    ///
    /// Change this `ChannelMethod` by removing every socket address that
    /// does not satisfy `pred`.
    ///
    /// `Hostname` and `None` addresses are never removed.
    ///
    /// Return an error if we have removed every address.
    pub fn retain_addrs<P>(&mut self, pred: P) -> Result<(), RetainAddrsError>
    where
        P: Fn(&std::net::SocketAddr) -> bool,
    {
        #[cfg(feature = "pt-client")]
        use BridgeAddr as Pt;

        match self {
            ChannelMethod::Direct(d) if d.is_empty() => {}
            ChannelMethod::Direct(d) => {
                d.retain(pred);
                if d.is_empty() {
                    return Err(RetainAddrsError::NoAddrsLeft);
                }
            }
            #[cfg(feature = "pt-client")]
            ChannelMethod::Pluggable(PtTarget { addr, .. }) => match addr {
                Pt::IpPort(a) => {
                    if !pred(a) {
                        *addr = Pt::None;
                        return Err(RetainAddrsError::NoAddrsLeft);
                    }
                }
                Pt::HostPort(_, _) => {}
                Pt::None => {}
            },
        }
        Ok(())
    }

    /// Return true if every method to contact `self` is also a method to
    /// contact `other`.
    pub fn contained_by(&self, other: &ChannelMethod) -> bool {
        use ChannelMethod as CM;
        match (self, other) {
            (CM::Direct(our_addrs), CM::Direct(their_addrs)) => {
                our_addrs.iter().all(|a| their_addrs.contains(a))
            }
            #[cfg(feature = "pt-client")]
            (CM::Pluggable(our_target), CM::Pluggable(their_target)) => our_target == their_target,
            #[cfg(feature = "pt-client")]
            (_, _) => false,
        }
    }
}

/// An error that occurred while filtering addresses from a ChanMethod.
#[derive(Clone, Debug, thiserror::Error)]
pub enum RetainAddrsError {
    /// We removed all of the addresses from this method.
    #[error("All addresses were removed.")]
    NoAddrsLeft,
}

impl HasAddrs for BridgeAddr {
    fn addrs(&self) -> &[SocketAddr] {
        match self {
            BridgeAddr::IpPort(sockaddr) => slice::from_ref(sockaddr),
            BridgeAddr::HostPort(..) | BridgeAddr::None => &[],
        }
    }
}

impl HasAddrs for ChannelMethod {
    fn addrs(&self) -> &[SocketAddr] {
        match self {
            ChannelMethod::Direct(addrs) => addrs,
            #[cfg(feature = "pt-client")]
            ChannelMethod::Pluggable(pt) => pt.addr.addrs(),
        }
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;

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
        let dflt3 = TransportId::from_str("-").unwrap();
        let dflt4 = TransportId::from_str("").unwrap();
        let dflt5 = TransportId::from_str("bridge").unwrap();
        let snow = TransportId::from_str("snowflake").unwrap();
        let obfs_again = TransportId::from_str("obfs4").unwrap();

        assert_eq!(obfs, obfs_again);
        assert_eq!(dflt, dflt2);
        assert_eq!(dflt, dflt3);
        assert_eq!(dflt, dflt4);
        assert_eq!(dflt, dflt5);
        assert_ne!(snow, obfs);
        assert_ne!(snow, dflt);

        assert_eq!(dflt.to_string(), "-");

        assert!(matches!(
            TransportId::from_str("12345"),
            Err(TransportIdError::BadId(_))
        ));
        assert!(matches!(
            TransportId::from_str("Bridge"),
            Err(TransportIdError::BadId(_))
        ));
    }

    #[test]
    fn addr() {
        for addr in &["1.2.3.4:555", "[::1]:9999"] {
            let a: BridgeAddr = addr.parse().unwrap();
            assert_eq!(&a.to_string(), addr);

            let sa: SocketAddr = addr.parse().unwrap();
            assert_eq!(a.addrs(), &[sa]);
        }

        for addr in &["www.example.com:9100", "-"] {
            let a: BridgeAddr = addr.parse().unwrap();
            assert_eq!(&a.to_string(), addr);
            assert_eq!(a.addrs(), &[]);
        }

        for addr in &["foobar", "<<<>>>"] {
            let e = BridgeAddr::from_str(addr).unwrap_err();
            assert!(matches!(e, BridgeAddrError::BadAddress(_)));
        }
    }
}
