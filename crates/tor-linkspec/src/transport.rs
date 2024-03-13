//! Support for identifying a particular transport.
//!
//! A "transport" is a mechanism to connect to a relay on the Tor network and
//! make a `Channel`. Currently, two types of transports exist: the "built-in"
//! transport, which uses TLS over TCP, and various anti-censorship "pluggable
//! transports", which use TLS over other protocols to avoid detection by
//! censors.

use std::fmt::{self, Debug, Display};
use std::net::SocketAddr;
use std::slice;
use std::str::FromStr;

use safelog::Redactable;
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
#[derive(Debug, Default, Clone, Eq, PartialEq, Hash)]
enum Inner {
    /// The built-in transport type.
    #[default]
    BuiltIn,

    /// A pluggable transport type, specified by its name.
    #[cfg(feature = "pt-client")]
    Pluggable(PtTransportName),
}

/// The name of a Pluggable Transport protocol.
///
/// The name has been syntax-checked.
///
/// These names are used to identify the particular transport protocol, such as
/// "obfs4" or "snowflake".  They match a name of a protocol that the transport
/// binary knows how to provide to the name of a protocol that a bridge is
/// configured to use.
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

impl Display for PtTransportName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl AsRef<str> for PtTransportName {
    fn as_ref(&self) -> &str {
        &self.0
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
///
/// This is semantically very similar to `Option<BridgeAddr>`,
/// but it has some of its own conversion methods and bespoke `FromStr` and `Display`.
//
// Implementations for `PtTargetAddr` are in terms of those for `BridgeAddr`
// wheresoever possible, to ensure that they do not diverge in semantics.
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, serde_with::DeserializeFromStr, serde_with::SerializeDisplay,
)]
#[non_exhaustive]
pub enum PtTargetAddr {
    /// An IP address and port for a Tor relay.
    ///
    /// This is the only address type supported by the BuiltIn transport.
    IpPort(SocketAddr),
    /// A hostname-and-port target address.  Some transports may support this.
    HostPort(String, u16),
    /// A completely absent target address.  Some transports support this.
    None,
}

/// An address of a bridge, for use in configuration.
///
/// Contains precisely, either:
///  * A hostname (as a string), plus a `u16` port; or
///  * An (IPv4 or IPv6) socket address including port - i.e., a `SocketAddr`,
///    or to put it another way, an IP address (v4 or v6) plus a `u16` port.
///
/// Hostnames which are not syntactically invalid Internet hostnames,
/// and a port value of zero,
/// *can* be represented within a `BridgeAddr`.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    serde_with::DeserializeFromStr,
    serde_with::SerializeDisplay,
    derive_more::Display,
)]
pub struct BridgeAddr(BridgeAddrInner<SocketAddr, String>);

/// `BridgeAddr` contents; type parameters allow use with references to avoid some copying
///
/// `SA` is always `SocketAddr` or `&SocketAddr`.
///
/// `HN` is always `String` or `&str`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum BridgeAddrInner<SA, HN> {
    /// An IP address and port for a bridge
    IpPort(SA),
    /// A hostname-and-port target address
    HostPort(HN, u16),
}

// These methods have long slightly awkward names because we think
// we may want to change their names and types later, and/or deprecate them.
// So let's not use up the nice names now.
//
// TODO: decide on, and implement, a nicer API, or functions with nicer names.
// TODO: add From/Into conversions for SocketAddr and maybe (String, u16).
// TODO: consider providing constructor/accessor/deconstructor to/from Either.
impl BridgeAddr {
    /// Create a new `BridgeAddr` referring to a numeric address and port
    pub fn new_addr_from_sockaddr(sa: SocketAddr) -> Self {
        BridgeAddr(BridgeAddrInner::IpPort(sa))
    }

    /// If this is a numeric address, return it as a `SocketAddr`
    pub fn as_socketaddr(&self) -> Option<&SocketAddr> {
        match &self.0 {
            BridgeAddrInner::IpPort(sa) => Some(sa),
            BridgeAddrInner::HostPort(..) => None,
        }
    }

    /// Create a new `BridgeAddr` referring to a numeric address and port
    pub fn new_named_host_port(hostname: impl Into<String>, port: u16) -> Self {
        BridgeAddr(BridgeAddrInner::HostPort(hostname.into(), port))
    }

    /// If this is a named host and port, return it as hostname string and port
    pub fn as_host_port(&self) -> Option<(&str, u16)> {
        match &self.0 {
            BridgeAddrInner::IpPort(..) => None,
            BridgeAddrInner::HostPort(hn, port) => Some((hn, *port)),
        }
    }
}

impl From<PtTargetAddr> for Option<BridgeAddr> {
    fn from(pt: PtTargetAddr) -> Option<BridgeAddr> {
        match pt {
            PtTargetAddr::IpPort(sa) => Some(BridgeAddrInner::IpPort(sa)),
            PtTargetAddr::HostPort(hn, p) => Some(BridgeAddrInner::HostPort(hn, p)),
            PtTargetAddr::None => None,
        }
        .map(BridgeAddr)
    }
}
impl From<Option<BridgeAddr>> for PtTargetAddr {
    fn from(pt: Option<BridgeAddr>) -> PtTargetAddr {
        match pt.map(|ba| ba.0) {
            Some(BridgeAddrInner::IpPort(sa)) => PtTargetAddr::IpPort(sa),
            Some(BridgeAddrInner::HostPort(hn, p)) => PtTargetAddr::HostPort(hn, p),
            None => PtTargetAddr::None,
        }
    }
}

/// An error from parsing a [`BridgeAddr`] or [`PtTargetAddr`].
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
        Ok(BridgeAddr(if let Ok(addr) = s.parse() {
            BridgeAddrInner::IpPort(addr)
        } else if let Some((name, port)) = s.rsplit_once(':') {
            let port = port
                .parse()
                .map_err(|_| BridgeAddrError::BadAddress(s.to_string()))?;

            BridgeAddrInner::HostPort(name.to_string(), port)
        } else {
            return Err(BridgeAddrError::BadAddress(s.to_string()));
        }))
    }
}

impl FromStr for PtTargetAddr {
    type Err = BridgeAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(if s == NONE_ADDR {
            PtTargetAddr::None
        } else {
            Some(BridgeAddr::from_str(s)?).into()
        })
    }
}

impl PtTargetAddr {
    /// Obtain an `Option<BridgeAddrInner>` containing references
    ///
    /// This is a useful helper for display-like implementations,
    /// which can then implement for `PtTargetAddr` in terms of the impls for `BridgeAddrInner`.
    ///
    /// (See the code comment for `PtTargetAddr`.)
    fn as_bridge_ref(&self) -> Option<BridgeAddrInner<&SocketAddr, &str>> {
        match self {
            PtTargetAddr::IpPort(addr) => Some(BridgeAddrInner::IpPort(addr)),
            PtTargetAddr::HostPort(host, port) => Some(BridgeAddrInner::HostPort(host, *port)),
            PtTargetAddr::None => None,
        }
    }
}

impl<SA: Display, HN: Display> Display for BridgeAddrInner<SA, HN> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BridgeAddrInner::IpPort(addr) => write!(f, "{}", addr),
            BridgeAddrInner::HostPort(host, port) => write!(f, "{}:{}", host, port),
        }
    }
}

// impl Display for BridgeAddr is done with derive_more, on the struct definition.

impl Display for PtTargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_bridge_ref() {
            Some(b) => write!(f, "{}", b),
            None => write!(f, "{}", NONE_ADDR),
        }
    }
}

impl<SA: Debug + Redactable, HN: Debug + Display + AsRef<str>> Redactable
    for BridgeAddrInner<SA, HN>
{
    fn display_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeAddrInner::IpPort(a) => a.display_redacted(f),
            BridgeAddrInner::HostPort(host, port) => write!(f, "{}…:{}", &host.as_ref()[..2], port),
        }
    }
}

impl Redactable for BridgeAddr {
    fn display_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.display_redacted(f)
    }
}

impl Redactable for PtTargetAddr {
    fn display_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.as_bridge_ref() {
            Some(b) => b.display_redacted(f),
            None => write!(f, "{}", NONE_ADDR),
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
    addr: PtTargetAddr,
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
    pub fn new(transport: PtTransportName, addr: PtTargetAddr) -> Self {
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
    pub fn addr(&self) -> &PtTargetAddr {
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
                addr: PtTargetAddr::IpPort(addr),
                ..
            } => Some(std::slice::from_ref(addr)),

            _ => None,
        }
    }

    /// Consume the `PtTarget` and return the component parts
    pub fn into_parts(self) -> (PtTransportName, PtTargetAddr, PtTargetSettings) {
        (self.transport, self.addr, self.settings)
    }
}

/// The way to approach a single relay in order to open a channel.
///
/// For direct connections, this is simply an address.  For connections via a
/// pluggable transport, this includes information about the transport, and any
/// address and settings information that transport requires.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
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
    //
    // TODO this is kind of weird, what does Some(PtTargetAddr::None) mean?
    pub fn target_addr(&self) -> Option<PtTargetAddr> {
        match self {
            ChannelMethod::Direct(addr) if !addr.is_empty() => Some(PtTargetAddr::IpPort(addr[0])),

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
        use PtTargetAddr as Pt;

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

impl HasAddrs for PtTargetAddr {
    fn addrs(&self) -> &[SocketAddr] {
        match self {
            PtTargetAddr::IpPort(sockaddr) => slice::from_ref(sockaddr),
            PtTargetAddr::HostPort(..) | PtTargetAddr::None => &[],
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
        let chk_bridge_addr = |a: &PtTargetAddr, addr: &str| {
            let ba: BridgeAddr = addr.parse().unwrap();
            assert_eq!(&ba.to_string(), addr);

            assert_eq!(&PtTargetAddr::from(Some(ba.clone())), a);
            let reba: Option<BridgeAddr> = a.clone().into();
            assert_eq!(reba.as_ref(), Some(&ba));
        };

        for addr in &["1.2.3.4:555", "[::1]:9999"] {
            let a: PtTargetAddr = addr.parse().unwrap();
            assert_eq!(&a.to_string(), addr);

            let sa: SocketAddr = addr.parse().unwrap();
            assert_eq!(a.addrs(), &[sa]);

            chk_bridge_addr(&a, addr);
        }

        for addr in &["www.example.com:9100", "-"] {
            let a: PtTargetAddr = addr.parse().unwrap();
            assert_eq!(&a.to_string(), addr);
            assert_eq!(a.addrs(), &[]);

            if a == PtTargetAddr::None {
                let e = BridgeAddr::from_str(addr).unwrap_err();
                assert!(matches!(e, BridgeAddrError::BadAddress(_)));
            } else {
                chk_bridge_addr(&a, addr);
            }
        }

        for addr in &["foobar", "<<<>>>"] {
            let e = PtTargetAddr::from_str(addr).unwrap_err();
            assert!(matches!(e, BridgeAddrError::BadAddress(_)));

            let e = BridgeAddr::from_str(addr).unwrap_err();
            assert!(matches!(e, BridgeAddrError::BadAddress(_)));
        }
    }

    #[test]
    fn transport_id() {
        let id1: TransportId = "<none>".parse().unwrap();
        assert!(id1.is_builtin());
        assert_eq!(id1.to_string(), "-".to_string());

        #[cfg(feature = "pt-client")]
        {
            let id2: TransportId = "obfs4".parse().unwrap();
            assert_ne!(id2, id1);
            assert!(!id2.is_builtin());
            assert_eq!(id2.to_string(), "obfs4");

            assert!(matches!(
                TransportId::from_str("==="),
                Err(TransportIdError::BadId(_))
            ));
        }

        #[cfg(not(feature = "pt-client"))]
        {
            assert!(matches!(
                TransportId::from_str("obfs4"),
                Err(TransportIdError::NoSupport)
            ));
        }
    }

    #[test]
    fn settings() {
        let s = PtTargetSettings::try_from(vec![]).unwrap();
        assert_eq!(Vec::<_>::from(s), vec![]);

        let v = vec![("abc".into(), "def".into()), ("ghi".into(), "jkl".into())];
        let s = PtTargetSettings::try_from(v.clone()).unwrap();
        assert_eq!(Vec::<_>::from(s), v);

        let v = vec![("a=b".into(), "def".into())];
        let s = PtTargetSettings::try_from(v);
        assert!(matches!(s, Err(PtTargetInvalidSetting::Key(_))));

        let v = vec![("abc".into(), "d ef".into())];
        let s = PtTargetSettings::try_from(v);
        assert!(matches!(s, Err(PtTargetInvalidSetting::Value(_))));
    }

    #[test]
    fn chanmethod_direct() {
        let a1 = "127.0.0.1:8080".parse().unwrap();
        let a2 = "127.0.0.2:8181".parse().unwrap();
        let a3 = "127.0.0.3:8282".parse().unwrap();

        let m = ChannelMethod::Direct(vec![a1, a2]);
        assert_eq!(m.socket_addrs(), Some(&[a1, a2][..]));
        assert_eq!((m.target_addr()), Some(PtTargetAddr::IpPort(a1)));
        assert!(m.is_direct());
        assert_eq!(m.transport_id(), TransportId::default());

        let m2 = ChannelMethod::Direct(vec![a1, a2, a3]);
        assert!(m.contained_by(&m));
        assert!(m.contained_by(&m2));
        assert!(!m2.contained_by(&m));

        let mut m3 = m2.clone();
        m3.retain_addrs(|a| a.port() != 8282).unwrap();
        assert_eq!(m3, m);
        assert_ne!(m3, m2);
    }

    #[test]
    #[cfg(feature = "pt-client")]
    fn chanmethod_pt() {
        use itertools::Itertools;

        let transport = "giraffe".parse().unwrap();
        let addr1 = PtTargetAddr::HostPort("pt.example.com".into(), 1234);
        let target1 = PtTarget::new("giraffe".parse().unwrap(), addr1.clone());
        let m1 = ChannelMethod::Pluggable(target1);

        let addr2 = PtTargetAddr::IpPort("127.0.0.1:567".parse().unwrap());
        let target2 = PtTarget::new("giraffe".parse().unwrap(), addr2.clone());
        let m2 = ChannelMethod::Pluggable(target2);

        let addr3 = PtTargetAddr::None;
        let target3 = PtTarget::new("giraffe".parse().unwrap(), addr3.clone());
        let m3 = ChannelMethod::Pluggable(target3);

        assert_eq!(m1.socket_addrs(), None);
        assert_eq!(
            m2.socket_addrs(),
            Some(&["127.0.0.1:567".parse().unwrap()][..])
        );
        assert_eq!(m3.socket_addrs(), None);

        assert_eq!(m1.target_addr(), Some(addr1));
        assert_eq!(m2.target_addr(), Some(addr2));
        assert_eq!(m3.target_addr(), Some(addr3));

        assert!(!m1.is_direct());
        assert!(!m2.is_direct());
        assert!(!m3.is_direct());

        assert_eq!(m1.transport_id(), transport);
        assert_eq!(m2.transport_id(), transport);
        assert_eq!(m3.transport_id(), transport);

        for v in [&m1, &m2, &m3].iter().combinations(2) {
            let first = v[0];
            let second = v[1];
            assert_eq!(first.contained_by(second), first == second);
        }

        let mut m1new = m1.clone();
        let mut m2new = m2.clone();
        let mut m3new = m3.clone();
        // this will retain the IpPort target, and ignore the other targets.
        m1new.retain_addrs(|a| a.port() == 567).unwrap();
        m2new.retain_addrs(|a| a.port() == 567).unwrap();
        m3new.retain_addrs(|a| a.port() == 567).unwrap();
        assert_eq!(m1new, m1);
        assert_eq!(m2new, m2);
        assert_eq!(m3new, m3);

        // But if we try to remove the ipport target, we get an error.
        assert!(matches!(
            m2new.retain_addrs(|a| a.port() == 999),
            Err(RetainAddrsError::NoAddrsLeft)
        ));
    }
}
