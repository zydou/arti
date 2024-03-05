//! Types and traits for converting objects to addresses which
//! Tor can connect to.

use crate::err::ErrorDetail;
use crate::StreamPrefs;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;
use thiserror::Error;
use tor_basic_utils::StrExt;

#[cfg(feature = "onion-service-client")]
use tor_hscrypto::pk::{HsId, HSID_ONION_SUFFIX};

/// Fake plastic imitation of some of the `tor-hs*` functionality
#[cfg(not(feature = "onion-service-client"))]
pub(crate) mod hs_dummy {
    use super::*;
    use tor_error::internal;
    use void::Void;

    /// Parsed hidden service identity - uninhabited, since not supported
    #[derive(Debug, Clone)]
    pub(crate) struct HsId(pub(crate) Void);

    impl PartialEq for HsId {
        fn eq(&self, _other: &Self) -> bool {
            void::unreachable(self.0)
        }
    }
    impl Eq for HsId {}

    /// Duplicates `tor-hscrypto::pk::HSID_ONION_SUFFIX`, ah well
    pub(crate) const HSID_ONION_SUFFIX: &str = ".onion";

    /// Must not be used other than for actual `.onion` addresses
    impl FromStr for HsId {
        type Err = ErrorDetail;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            if !s.ends_with(HSID_ONION_SUFFIX) {
                return Err(internal!("non-.onion passed to dummy HsId::from_str").into());
            }

            Err(ErrorDetail::OnionAddressNotSupported)
        }
    }
}
#[cfg(not(feature = "onion-service-client"))]
use hs_dummy::*;

// ----------------------------------------------------------------------

/// An object that can be converted to a [`TorAddr`] with a minimum of risk.
///
/// Typically, this trait will be implemented for a hostname or service name.
///
/// Don't implement this trait for IP addresses and similar types; instead,
/// implement [`DangerouslyIntoTorAddr`] for those.  (The trouble with accepting
/// IP addresses is that, in order to get an IP address, most programs will do a
/// local hostname lookup, which will leak the target address to the DNS
/// resolver. The `DangerouslyIntoTorAddr` trait provides a contract for careful
/// programs to say, "I have gotten this IP address from somewhere safe."  This
/// trait is for name-based addressing and similar, which _usually_ gets its
/// addresses from a safer source.)
///
/// [*See also: the `TorAddr` documentation.*](TorAddr)
///
/// # Design note
///
/// We use a separate trait here, instead of using `Into<TorAddr>` or
/// `TryInto<TorAddr>`, because `IntoTorAddr` implies additional guarantees
/// relating to privacy risk.  The separate trait alerts users that something
/// tricky is going on here, and encourages them to think twice before
/// implementing `IntoTorAddr` for their own types.
pub trait IntoTorAddr {
    /// Try to make a [`TorAddr`] to represent connecting to this
    /// address.
    fn into_tor_addr(self) -> Result<TorAddr, TorAddrError>;
}

/// An object that can be converted to a [`TorAddr`], but which it
/// might be risky to get in the first place if you're hoping for
/// anonymity.
///
/// For example, you can use this trait to convert a [`SocketAddr`]
/// into a [`TorAddr`], and it's safe to do that conversion.  But
/// where did you get the [`SocketAddr`] in the first place?  If it
/// comes from a local DNS lookup, then you have leaked the address
/// you were resolving to your DNS resolver, and probably your ISP.
///
/// [*See also: the `TorAddr` documentation.*](TorAddr)
pub trait DangerouslyIntoTorAddr {
    /// Try to make a [`TorAddr`] to represent connecting to `self`.
    ///
    /// By calling this function, the caller asserts that `self` was
    /// obtained from some secure, private mechanism, and **not** from a local
    /// DNS lookup or something similar.
    fn into_tor_addr_dangerously(self) -> Result<TorAddr, TorAddrError>;
}

/// An address object that you can connect to over the Tor network.
///
/// When you're making a connection with Tor, you shouldn't do your DNS
/// lookups locally: that would leak your target address to your DNS server.
/// Instead, it's better to use a combination of a hostname and a port
/// directly.
///
/// The preferred way to create a `TorAddr` is via the [`IntoTorAddr`] trait,
/// using a hostname and a port (or a string containing a hostname and a
/// port).  It's also okay to use an IP and Port there, but only if they come
/// from some source _other than_ a local DNS lookup.
///
/// In order to discourage local hostname lookups, the functions that
/// construct a [`TorAddr`] from [`IpAddr`], [`SocketAddr`], and so
/// forth are labeled as "dangerous".
///
/// # Examples
///
/// Making a `TorAddr` from various "safe" sources:
///
/// ```rust
/// # use anyhow::Result;
/// # fn main() -> Result<()> {
/// use arti_client::IntoTorAddr;
///
/// let example_from_tuple = ("example.com", 80).into_tor_addr()?;
/// let example_from_string = "example.com:80".into_tor_addr()?;
///
/// assert_eq!(example_from_tuple, example_from_string);
/// # Ok(())
/// # }
/// ```
///
/// Making a `TorAddr` from an IP address and port:
///
/// > **Warning:** This example is only safe because we're not doing a DNS lookup; rather, the
/// > intent is to connect to a hardcoded IP address.
/// > If you're using [`DangerouslyIntoTorAddr`], pay careful attention to where your IP addresses
/// > are coming from, and whether there's a risk of information leakage.
///
/// ```rust
/// # use anyhow::Result;
/// # fn main() -> Result<()> {
/// use arti_client::DangerouslyIntoTorAddr;
/// use std::net::{IpAddr, SocketAddr};
///
/// let quad_one_dns: SocketAddr = "1.1.1.1:53".parse()?;
/// let addr_from_socketaddr = quad_one_dns.into_tor_addr_dangerously()?;
///
/// let quad_one_ip: IpAddr = "1.1.1.1".parse()?;
/// let addr_from_tuple = (quad_one_ip, 53).into_tor_addr_dangerously()?;
///
/// assert_eq!(addr_from_socketaddr, addr_from_tuple);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TorAddr {
    /// The target host.
    host: Host,
    /// The target port number.
    port: u16,
}

/// How to make a stream to this `TorAddr`?
///
/// This is a separate type, returned from `address.rs` to `client.rs`,
/// so that we can test our "how to make a connection" logic and policy,
/// in isolation, without a whole Tor client.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StreamInstructions {
    /// Create an exit circuit suitable for port, and then make a stream to `hostname`
    Exit {
        /// Hostname
        hostname: String,
        /// Port
        port: u16,
    },
    /// Create a hidden service connection to hsid, and then make a stream to `hostname`
    ///
    /// `HsId`, and therefore this variant, is uninhabited, unless the feature is enabled
    Hs {
        /// The target hidden service
        hsid: HsId,
        /// The hostname (used for subdomains, sent to the peer)
        hostname: String,
        /// Port
        port: u16,
    },
}

/// How to resolve this Tor host address into IP address(es)
#[derive(PartialEq, Eq, Debug)]
pub(crate) enum ResolveInstructions {
    /// Create an exit circuit without port restrictions, and ask the exit
    Exit(String),
    /// Simply return this
    Return(Vec<IpAddr>),
}

impl TorAddr {
    /// Construct a TorAddr from its constituent parts, rejecting it if the
    /// port is zero.
    fn new(host: Host, port: u16) -> Result<Self, TorAddrError> {
        if port == 0 {
            Err(TorAddrError::BadPort)
        } else {
            Ok(TorAddr { host, port })
        }
    }

    /// Construct a `TorAddr` from any object that implements
    /// [`IntoTorAddr`].
    pub fn from<A: IntoTorAddr>(addr: A) -> Result<Self, TorAddrError> {
        addr.into_tor_addr()
    }
    /// Construct a `TorAddr` from any object that implements
    /// [`DangerouslyIntoTorAddr`].
    ///
    /// See [`DangerouslyIntoTorAddr`] for an explanation of why the
    /// style of programming supported by this function is dangerous
    /// to use.
    pub fn dangerously_from<A: DangerouslyIntoTorAddr>(addr: A) -> Result<Self, TorAddrError> {
        addr.into_tor_addr_dangerously()
    }

    /// Return true if this is an IP address (rather than a hostname).
    pub fn is_ip_address(&self) -> bool {
        matches!(&self.host, Host::Ip(_))
    }

    /// Get instructions for how to make a stream to this address
    pub(crate) fn into_stream_instructions(
        self,
        cfg: &crate::config::ClientAddrConfig,
        prefs: &StreamPrefs,
    ) -> Result<StreamInstructions, ErrorDetail> {
        self.enforce_config(cfg, prefs)?;

        let port = self.port;
        Ok(match self.host {
            Host::Hostname(hostname) => StreamInstructions::Exit { hostname, port },
            Host::Ip(ip) => StreamInstructions::Exit {
                hostname: ip.to_string(),
                port,
            },
            Host::Onion(onion) => {
                // The HS is identified by the last two domain name components
                let rhs = onion
                    .rmatch_indices('.')
                    .nth(1)
                    .map(|(i, _)| i + 1)
                    .unwrap_or(0);
                let rhs = &onion[rhs..];
                let hsid = rhs.parse()?;
                StreamInstructions::Hs {
                    hsid,
                    port,
                    hostname: onion,
                }
            }
        })
    }

    /// Get instructions for how to make a stream to this address
    pub(crate) fn into_resolve_instructions(
        self,
        cfg: &crate::config::ClientAddrConfig,
        prefs: &StreamPrefs,
    ) -> Result<ResolveInstructions, ErrorDetail> {
        // We defer enforcing the config until we see if this is a .onion,
        // in which case it's always doomed and we want to return *our* error,
        // not any problem with the configuration or preferences.
        // But we must *calculate* the error now because instructions consumes self.
        let enforce_config_result = self.enforce_config(cfg, prefs);

        // This IEFE is so that any use of `return` doesn't bypass
        // checking the the enforce_config result
        let instructions = (move || {
            Ok(match self.host {
                Host::Hostname(hostname) => ResolveInstructions::Exit(hostname),
                Host::Ip(ip) => ResolveInstructions::Return(vec![ip]),
                Host::Onion(_) => return Err(ErrorDetail::OnionAddressResolveRequest),
            })
        })()?;

        let () = enforce_config_result?;

        Ok(instructions)
    }

    /// Return true if the `host` in this address is local.
    fn is_local(&self) -> bool {
        self.host.is_local()
    }

    /// Give an error if this address doesn't conform to the rules set in
    /// `cfg`.
    fn enforce_config(
        &self,
        cfg: &crate::config::ClientAddrConfig,
        #[allow(unused_variables)] // will only be used in certain configurations
        prefs: &StreamPrefs,
    ) -> Result<(), ErrorDetail> {
        if !cfg.allow_local_addrs && self.is_local() {
            return Err(ErrorDetail::LocalAddress);
        }

        if let Host::Hostname(addr) = &self.host {
            if !is_valid_hostname(addr) {
                // This ought not to occur, because it violates Host's invariant
                return Err(ErrorDetail::InvalidHostname);
            }
            if addr.ends_with_ignore_ascii_case(HSID_ONION_SUFFIX) {
                // This ought not to occur, because it violates Host's invariant
                return Err(ErrorDetail::OnionAddressNotSupported);
            }
        }

        if let Host::Onion(_name) = &self.host {
            cfg_if::cfg_if! {
                if #[cfg(feature = "onion-service-client")] {
                    if !prefs.connect_to_onion_services.as_bool().unwrap_or(cfg.allow_onion_addrs) {
                        return Err(ErrorDetail::OnionAddressDisabled);
                    }
                } else {
                    return Err(ErrorDetail::OnionAddressNotSupported);
                }
            }
        }

        Ok(())
    }
}

impl std::fmt::Display for TorAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.host {
            Host::Ip(IpAddr::V6(addr)) => write!(f, "[{}]:{}", addr, self.port),
            _ => write!(f, "{}:{}", self.host, self.port),
        }
    }
}

/// An error created while making or using a [`TorAddr`].
//
// NOTE: Unlike ErrorDetail, this is a `pub` enum: Do not make breaking changes
// to it, or expose lower-level errors in it, without careful consideration!
#[derive(Debug, Error, Clone, Eq, PartialEq)]
#[non_exhaustive]
// TODO Should implement ErrorKind
pub enum TorAddrError {
    /// Tried to parse a string that can never be interpreted as a valid host.
    #[error("String can never be a valid hostname")]
    InvalidHostname,
    /// Tried to parse a string as an `address:port`, but it had no port.
    #[error("No port found in string")]
    NoPort,
    /// Tried to parse a port that wasn't a valid nonzero `u16`.
    #[error("Could not parse port")]
    BadPort,
}

/// A host that Tor can connect to: either a hostname or an IP address.
//
// We use `String` in here, and pass that directly to (for example)
// `HsId::from_str`, or `begin_stream`.
// In theory we could use a couple of newtypes or something, but
//  * The stringly-typed `HsId::from_str` call (on a string known to end `.onion`)
//    appears precisely in `into_stream_instructions` which knows what it's doing;
//  * The stringly-typed .onion domain name must be passed in the
//    StreamInstructions so that we can send it to the HS for its vhosting.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Host {
    /// A hostname.
    ///
    /// This variant should never be used if the `Ip`
    /// variant could be used instead.
    /// Ie, it must not be a stringified IP address.
    ///
    /// Likewise, this variant must *not* be used for a `.onion` address.
    /// Even if we have `.onion` support compiled out, we use the `Onion` variant for that.
    ///
    /// But, this variant might *not* be on the public internet.
    /// For example, it might be `localhost`.
    Hostname(String),
    /// An IP address.
    Ip(IpAddr),
    /// The address of a hidden service (`.onion` service).
    ///
    /// We haven't validated that the base32 makes any kind of sense, yet.
    /// We do that when we try to connect.
    Onion(String),
}

impl FromStr for Host {
    type Err = TorAddrError;
    fn from_str(s: &str) -> Result<Host, TorAddrError> {
        if s.ends_with_ignore_ascii_case(".onion") && is_valid_hostname(s) {
            Ok(Host::Onion(s.to_owned()))
        } else if let Ok(ip_addr) = s.parse() {
            Ok(Host::Ip(ip_addr))
        } else if is_valid_hostname(s) {
            // TODO(nickm): we might someday want to reject some kinds of bad
            // hostnames here, rather than when we're about to connect to them.
            // But that would be an API break, and maybe not what people want.
            // Maybe instead we should have a method to check whether a hostname
            // is "bad"? Not sure; we'll need to decide the right behavior here.
            Ok(Host::Hostname(s.to_owned()))
        } else {
            Err(TorAddrError::InvalidHostname)
        }
    }
}

impl Host {
    /// Return true if this address is one that is "internal": that is,
    /// relative to the particular host that is resolving it.
    fn is_local(&self) -> bool {
        match self {
            Host::Hostname(name) => name.eq_ignore_ascii_case("localhost"),
            // TODO: use is_global once it's stable, perhaps.
            // NOTE: Contrast this with is_sufficiently_private in tor-hsproxy,
            // which has a different purpose. Also see #1159.
            // The purpose of _this_ test is to find addresses that cannot
            // meaningfully be connected to over Tor, and that the exit
            // will not accept.
            Host::Ip(IpAddr::V4(ip)) => ip.is_loopback() || ip.is_private(),
            Host::Ip(IpAddr::V6(ip)) => ip.is_loopback(),
            Host::Onion(_) => false,
        }
    }
}

impl std::fmt::Display for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Host::Hostname(s) => Display::fmt(s, f),
            Host::Ip(ip) => Display::fmt(ip, f),
            Host::Onion(onion) => Display::fmt(onion, f),
        }
    }
}

impl IntoTorAddr for TorAddr {
    fn into_tor_addr(self) -> Result<TorAddr, TorAddrError> {
        Ok(self)
    }
}

impl<A: IntoTorAddr + Clone> IntoTorAddr for &A {
    fn into_tor_addr(self) -> Result<TorAddr, TorAddrError> {
        self.clone().into_tor_addr()
    }
}

impl IntoTorAddr for &str {
    fn into_tor_addr(self) -> Result<TorAddr, TorAddrError> {
        if let Ok(sa) = SocketAddr::from_str(self) {
            TorAddr::new(Host::Ip(sa.ip()), sa.port())
        } else {
            let (host, port) = self.rsplit_once(':').ok_or(TorAddrError::NoPort)?;
            let host = host.parse()?;
            let port = port.parse().map_err(|_| TorAddrError::BadPort)?;
            TorAddr::new(host, port)
        }
    }
}

impl IntoTorAddr for String {
    fn into_tor_addr(self) -> Result<TorAddr, TorAddrError> {
        self[..].into_tor_addr()
    }
}

impl FromStr for TorAddr {
    type Err = TorAddrError;
    fn from_str(s: &str) -> Result<Self, TorAddrError> {
        s.into_tor_addr()
    }
}

impl IntoTorAddr for (&str, u16) {
    fn into_tor_addr(self) -> Result<TorAddr, TorAddrError> {
        let (host, port) = self;
        let host = host.parse()?;
        TorAddr::new(host, port)
    }
}

impl IntoTorAddr for (String, u16) {
    fn into_tor_addr(self) -> Result<TorAddr, TorAddrError> {
        let (host, port) = self;
        (&host[..], port).into_tor_addr()
    }
}

impl<T: DangerouslyIntoTorAddr + Clone> DangerouslyIntoTorAddr for &T {
    fn into_tor_addr_dangerously(self) -> Result<TorAddr, TorAddrError> {
        self.clone().into_tor_addr_dangerously()
    }
}

impl DangerouslyIntoTorAddr for (IpAddr, u16) {
    fn into_tor_addr_dangerously(self) -> Result<TorAddr, TorAddrError> {
        let (addr, port) = self;
        TorAddr::new(Host::Ip(addr), port)
    }
}

impl DangerouslyIntoTorAddr for (Ipv4Addr, u16) {
    fn into_tor_addr_dangerously(self) -> Result<TorAddr, TorAddrError> {
        let (addr, port) = self;
        TorAddr::new(Host::Ip(addr.into()), port)
    }
}

impl DangerouslyIntoTorAddr for (Ipv6Addr, u16) {
    fn into_tor_addr_dangerously(self) -> Result<TorAddr, TorAddrError> {
        let (addr, port) = self;
        TorAddr::new(Host::Ip(addr.into()), port)
    }
}

impl DangerouslyIntoTorAddr for SocketAddr {
    fn into_tor_addr_dangerously(self) -> Result<TorAddr, TorAddrError> {
        let (addr, port) = (self.ip(), self.port());
        (addr, port).into_tor_addr_dangerously()
    }
}

impl DangerouslyIntoTorAddr for SocketAddrV4 {
    fn into_tor_addr_dangerously(self) -> Result<TorAddr, TorAddrError> {
        let (addr, port) = (self.ip(), self.port());
        (*addr, port).into_tor_addr_dangerously()
    }
}

impl DangerouslyIntoTorAddr for SocketAddrV6 {
    fn into_tor_addr_dangerously(self) -> Result<TorAddr, TorAddrError> {
        let (addr, port) = (self.ip(), self.port());
        (*addr, port).into_tor_addr_dangerously()
    }
}

/// Check whether `hostname` is a valid hostname or not.
///
/// (Note that IPv6 addresses don't follow these rules.)
fn is_valid_hostname(hostname: &str) -> bool {
    hostname_validator::is_valid(hostname)
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    /// Make a `StreamPrefs` with `.onion` enabled, if cfg-enabled
    fn mk_stream_prefs() -> StreamPrefs {
        let prefs = crate::StreamPrefs::default();

        #[cfg(feature = "onion-service-client")]
        let prefs = {
            let mut prefs = prefs;
            prefs.connect_to_onion_services(tor_config::BoolOrAuto::Explicit(true));
            prefs
        };

        prefs
    }

    #[test]
    fn validate_hostname() {
        // Valid hostname tests
        assert!(is_valid_hostname("torproject.org"));
        assert!(is_valid_hostname("Tor-Project.org"));
        assert!(is_valid_hostname("example.onion"));
        assert!(is_valid_hostname("some.example.onion"));

        // Invalid hostname tests
        assert!(!is_valid_hostname("-torproject.org"));
        assert!(!is_valid_hostname("_torproject.org"));
        assert!(!is_valid_hostname("tor_project1.org"));
        assert!(!is_valid_hostname("iwanna$money.org"));
    }

    #[test]
    fn validate_addr() {
        use crate::err::ErrorDetail;
        fn val<A: IntoTorAddr>(addr: A) -> Result<TorAddr, ErrorDetail> {
            let toraddr = addr.into_tor_addr()?;
            toraddr.enforce_config(&Default::default(), &mk_stream_prefs())?;
            Ok(toraddr)
        }

        assert!(val("[2001:db8::42]:20").is_ok());
        assert!(val(("2001:db8::42", 20)).is_ok());
        assert!(val(("198.151.100.42", 443)).is_ok());
        assert!(val("198.151.100.42:443").is_ok());
        assert!(val("www.torproject.org:443").is_ok());
        assert!(val(("www.torproject.org", 443)).is_ok());

        // When HS disabled, tested elsewhere, see: stream_instructions, prefs_onion_services
        #[cfg(feature = "onion-service-client")]
        {
            assert!(val("example.onion:80").is_ok());
            assert!(val(("example.onion", 80)).is_ok());

            match val("eweiibe6tdjsdprb4px6rqrzzcsi22m4koia44kc5pcjr7nec2rlxyad.onion:443") {
                Ok(TorAddr {
                    host: Host::Onion(_),
                    ..
                }) => {}
                x => panic!("{x:?}"),
            }
        }

        assert!(matches!(
            val("-foobar.net:443"),
            Err(ErrorDetail::InvalidHostname)
        ));
        assert!(matches!(
            val("www.torproject.org"),
            Err(ErrorDetail::Address(TorAddrError::NoPort))
        ));

        assert!(matches!(
            val("192.168.0.1:80"),
            Err(ErrorDetail::LocalAddress)
        ));
        assert!(matches!(
            val(TorAddr::new(Host::Hostname("foo@bar".to_owned()), 553).unwrap()),
            Err(ErrorDetail::InvalidHostname)
        ));
        assert!(matches!(
            val(TorAddr::new(Host::Hostname("foo.onion".to_owned()), 80).unwrap()),
            Err(ErrorDetail::OnionAddressNotSupported)
        ));
    }

    #[test]
    fn local_addrs() {
        fn is_local_hostname(s: &str) -> bool {
            let h: Host = s.parse().unwrap();
            h.is_local()
        }

        assert!(is_local_hostname("localhost"));
        assert!(is_local_hostname("loCALHOST"));
        assert!(is_local_hostname("127.0.0.1"));
        assert!(is_local_hostname("::1"));
        assert!(is_local_hostname("192.168.0.1"));

        assert!(!is_local_hostname("www.example.com"));
    }

    #[test]
    fn is_ip_address() {
        fn ip(s: &str) -> bool {
            TorAddr::from(s).unwrap().is_ip_address()
        }

        assert!(ip("192.168.0.1:80"));
        assert!(ip("[::1]:80"));
        assert!(ip("[2001:db8::42]:65535"));
        assert!(!ip("example.com:80"));
        assert!(!ip("example.onion:80"));
    }

    #[test]
    fn stream_instructions() {
        use StreamInstructions as SI;

        fn sap(s: &str) -> Result<StreamInstructions, ErrorDetail> {
            TorAddr::from(s)
                .unwrap()
                .into_stream_instructions(&Default::default(), &mk_stream_prefs())
        }

        assert_eq!(
            sap("[2001:db8::42]:9001").unwrap(),
            SI::Exit {
                hostname: "2001:db8::42".to_owned(),
                port: 9001
            },
        );
        assert_eq!(
            sap("example.com:80").unwrap(),
            SI::Exit {
                hostname: "example.com".to_owned(),
                port: 80
            },
        );

        {
            let b32 = "eweiibe6tdjsdprb4px6rqrzzcsi22m4koia44kc5pcjr7nec2rlxyad";
            let onion = format!("sss1234.www.{}.onion", b32);
            let got = sap(&format!("{}:443", onion));

            #[cfg(feature = "onion-service-client")]
            assert_eq!(
                got.unwrap(),
                SI::Hs {
                    hsid: format!("{}.onion", b32).parse().unwrap(),
                    hostname: onion,
                    port: 443,
                }
            );

            #[cfg(not(feature = "onion-service-client"))]
            assert!(matches!(got, Err(ErrorDetail::OnionAddressNotSupported)));
        }
    }

    #[test]
    fn resolve_instructions() {
        use ResolveInstructions as RI;

        fn sap(s: &str) -> Result<ResolveInstructions, ErrorDetail> {
            TorAddr::from(s)
                .unwrap()
                .into_resolve_instructions(&Default::default(), &Default::default())
        }

        assert_eq!(
            sap("[2001:db8::42]:9001").unwrap(),
            RI::Return(vec!["2001:db8::42".parse().unwrap()]),
        );
        assert_eq!(
            sap("example.com:80").unwrap(),
            RI::Exit("example.com".to_owned()),
        );
        assert!(matches!(
            sap("example.onion:80"),
            Err(ErrorDetail::OnionAddressResolveRequest),
        ));
    }

    #[test]
    fn bad_ports() {
        assert_eq!(
            TorAddr::from("www.example.com:squirrel"),
            Err(TorAddrError::BadPort)
        );
        assert_eq!(
            TorAddr::from("www.example.com:0"),
            Err(TorAddrError::BadPort)
        );
    }

    #[test]
    fn prefs_onion_services() {
        use crate::err::ErrorDetailDiscriminants;
        use tor_error::{ErrorKind, HasKind as _};
        use ErrorDetailDiscriminants as EDD;
        use ErrorKind as EK;

        #[allow(clippy::redundant_closure)] // for symmetry with prefs_of, below, and clarity
        let prefs_def = || StreamPrefs::default();

        let addr: TorAddr = "eweiibe6tdjsdprb4px6rqrzzcsi22m4koia44kc5pcjr7nec2rlxyad.onion:443"
            .parse()
            .unwrap();

        fn map(
            got: Result<impl Sized, ErrorDetail>,
        ) -> Result<(), (ErrorDetailDiscriminants, ErrorKind)> {
            got.map(|_| ())
                .map_err(|e| (ErrorDetailDiscriminants::from(&e), e.kind()))
        }

        let check_stream = |prefs, expected| {
            let got = addr
                .clone()
                .into_stream_instructions(&Default::default(), &prefs);
            assert_eq!(map(got), expected, "{prefs:?}");
        };
        let check_resolve = |prefs| {
            let got = addr
                .clone()
                .into_resolve_instructions(&Default::default(), &prefs);
            // This should be OnionAddressResolveRequest no matter if .onion is compiled in or enabled.
            // Since compiling it in, or enabling it, won't help.
            let expected = Err((EDD::OnionAddressResolveRequest, EK::NotImplemented));
            assert_eq!(map(got), expected, "{prefs:?}");
        };

        cfg_if::cfg_if! {
            if #[cfg(feature = "onion-service-client")] {
                use tor_config::BoolOrAuto as B;
                let prefs_of = |yn| {
                    let mut prefs = StreamPrefs::default();
                    prefs.connect_to_onion_services(yn);
                    prefs
                };
                check_stream(prefs_def(), Err((EDD::OnionAddressDisabled, EK::ForbiddenStreamTarget)));
                check_stream(prefs_of(B::Auto), Err((EDD::OnionAddressDisabled, EK::ForbiddenStreamTarget)));
                check_stream(prefs_of(B::Explicit(true)), Ok(()));
                check_stream(prefs_of(B::Explicit(false)), Err((EDD::OnionAddressDisabled, EK::ForbiddenStreamTarget)));

                check_resolve(prefs_def());
                check_resolve(prefs_of(B::Auto));
                check_resolve(prefs_of(B::Explicit(true)));
                check_resolve(prefs_of(B::Explicit(false)));
            } else {
                check_stream(prefs_def(), Err((EDD::OnionAddressNotSupported, EK::FeatureDisabled)));

                check_resolve(prefs_def());
            }
        }
    }

    #[test]
    fn convert_safe() {
        fn check<A: IntoTorAddr>(a: A, s: &str) {
            let a1 = TorAddr::from(a).unwrap();
            let a2 = s.parse().unwrap();
            assert_eq!(a1, a2);
            assert_eq!(&a1.to_string(), s);
        }

        check(("www.example.com", 8000), "www.example.com:8000");
        check(
            TorAddr::from(("www.example.com", 8000)).unwrap(),
            "www.example.com:8000",
        );
        check(
            TorAddr::from(("www.example.com", 8000)).unwrap(),
            "www.example.com:8000",
        );
        let addr = "[2001:db8::0042]:9001".to_owned();
        check(&addr, "[2001:db8::42]:9001");
        check(addr, "[2001:db8::42]:9001");
        check(("2001:db8::0042".to_owned(), 9001), "[2001:db8::42]:9001");
        check(("example.onion", 80), "example.onion:80");
    }

    #[test]
    fn convert_dangerous() {
        fn check<A: DangerouslyIntoTorAddr>(a: A, s: &str) {
            let a1 = TorAddr::dangerously_from(a).unwrap();
            let a2 = TorAddr::from(s).unwrap();
            assert_eq!(a1, a2);
            assert_eq!(&a1.to_string(), s);
        }

        let ip: IpAddr = "203.0.133.6".parse().unwrap();
        let ip4: Ipv4Addr = "203.0.133.7".parse().unwrap();
        let ip6: Ipv6Addr = "2001:db8::42".parse().unwrap();
        let sa: SocketAddr = "203.0.133.8:80".parse().unwrap();
        let sa4: SocketAddrV4 = "203.0.133.8:81".parse().unwrap();
        let sa6: SocketAddrV6 = "[2001:db8::43]:82".parse().unwrap();

        // This tests impl DangerouslyIntoTorAddr for &T
        #[allow(clippy::needless_borrow)]
        #[allow(clippy::needless_borrows_for_generic_args)]
        check(&(ip, 443), "203.0.133.6:443");
        check((ip, 443), "203.0.133.6:443");
        check((ip4, 444), "203.0.133.7:444");
        check((ip6, 445), "[2001:db8::42]:445");
        check(sa, "203.0.133.8:80");
        check(sa4, "203.0.133.8:81");
        check(sa6, "[2001:db8::43]:82");
    }
}
