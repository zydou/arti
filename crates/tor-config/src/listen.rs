//! Configuration for ports and addresses to listen on.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::{fmt::Display, iter};

use either::Either;
use itertools::Itertools as _;
use serde::{Deserialize, Serialize};

/// Specification of (possibly) something to listen on (eg, a port, or some addresses/ports)
///
/// Can represent, at least:
///  * "do not listen"
///  * Listen on the following port on localhost (IPv6 and IPv4)
///  * Listen on precisely the following address and port
///  * Listen on several addresses/ports
///
/// Currently only IP (v6 and v4) is supported.
//
// NOTE: If you're adding or changing functionality for this type,
// make sure that all existing users of this type (for example all config options in arti and
// arti-relay which use this) want that functionality.
#[derive(Clone, Hash, Debug, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "CustomizableListen", into = "CustomizableListen")]
pub struct Listen(CustomizableListen);

impl Listen {
    /// Create a new `Listen` specifying no addresses (no listening)
    pub fn new_none() -> Listen {
        CustomizableListen::Disabled
            .try_into()
            .expect("'disabled' should be valid")
    }

    /// Create a new `Listen` specifying listening on a port on localhost
    ///
    /// Special case: if `port` is zero, specifies no listening.
    pub fn new_localhost(port: u16) -> Listen {
        CustomizableListen::One(ListenItem::Port(port))
            .try_into()
            .expect("a standalone port (including 0) should be valid")
    }

    /// Create a new `Listen`, possibly specifying listening on a port on localhost
    ///
    /// Special case: if `port` is `Some(0)`, also specifies no listening.
    pub fn new_localhost_optional(port: Option<u16>) -> Listen {
        Self::new_localhost(port.unwrap_or_default())
    }

    /// Return true if no listening addresses have been configured
    pub fn is_empty(&self) -> bool {
        self.ip_addrs_internal().count() == 0
    }

    /// Return true if there are any "auto" addresses in this Listen.
    ///
    /// See also [`using_port_zero()`](Self::using_port_zero).
    pub fn using_auto(&self) -> bool {
        self.0.items().any(ListenItem::is_auto)
    }

    /// Return true if there are any port-zero addresses in this Listen.
    ///
    /// See also [`using_auto()`](Self::using_auto).
    pub fn using_port_zero(&self) -> bool {
        self.0.items().any(ListenItem::is_port_zero)
    }

    /// List the network socket addresses to listen on
    ///
    /// Each returned item is a list of `SocketAddr`,
    /// of which *at least one* must be successfully bound.
    /// It is OK if the others (up to all but one of them)
    /// fail with `EAFNOSUPPORT` ("Address family not supported").
    /// This allows handling of support, or non-support,
    /// for particular address families, eg IPv6 vs IPv4 localhost.
    /// Other errors (eg, `EADDRINUSE`) should always be treated as serious problems.
    ///
    /// Fails if the listen spec involves listening on things other than IP addresses.
    /// (Currently that is not possible.)
    pub fn ip_addrs(
        &self,
    ) -> Result<impl Iterator<Item = impl Iterator<Item = SocketAddr> + '_> + '_, ListenUnsupported>
    {
        Ok(self.ip_addrs_internal())
    }

    /// List the network socket addresses to listen on.
    ///
    /// See [`Self::ip_addrs`], which wraps this result in an `Ok`.
    fn ip_addrs_internal(
        &self,
    ) -> impl Iterator<Item = impl Iterator<Item = SocketAddr> + '_> + '_ {
        // We interpret standalone ports to be localhost addresses.
        let ips = [Ipv6Addr::LOCALHOST.into(), Ipv4Addr::LOCALHOST.into()];
        self.0.items().map(move |item| item.iter(ips))
    }

    /// Get the localhost port to listen on
    ///
    /// Returns `None` if listening is configured to be disabled.
    ///
    /// Fails, giving an unsupported error, if the configuration
    /// isn't just "listen on a single localhost port in all address families"
    #[deprecated(since = "0.38.0")]
    pub fn localhost_port_legacy(&self) -> Result<Option<u16>, ListenUnsupported> {
        Ok(match self.to_singleton_legacy()? {
            None => None,
            Some(ListenItem::Port(port)) => Some(*port),
            Some(ListenItem::Auto) => return Err(ListenUnsupported {}),
            Some(ListenItem::AutoPort(_)) => return Err(ListenUnsupported {}),
            Some(ListenItem::General(_)) => return Err(ListenUnsupported {}),
        })
    }

    /// Get a single address to listen on
    ///
    /// Returns `None` if listening is configured to be disabled.
    ///
    /// If the configuration is "listen on a single port",
    /// treats this as a request to listening on IPv4 only.
    /// Use of this function implies a bug:
    /// lack of proper support for the current internet protocol IPv6.
    /// It should only be used if an underlying library or facility is likewise buggy.
    ///
    /// Fails, giving an unsupported error, if the configuration
    /// isn't just "listen on a single port on one address family".
    pub fn single_address_legacy(&self) -> Result<Option<SocketAddr>, ListenUnsupported> {
        Ok(match self.to_singleton_legacy()? {
            None => None,
            Some(ListenItem::Port(port)) => Some((Ipv4Addr::LOCALHOST, *port).into()),
            Some(ListenItem::Auto) => Some((Ipv4Addr::LOCALHOST, 0).into()),
            Some(ListenItem::AutoPort(addr)) => Some((*addr, 0).into()),
            Some(ListenItem::General(addr)) => Some(*addr),
        })
    }

    /// Helper: return a ListenItem if this Listen has exactly one.
    ///
    /// Return None if there are multiple items, or an error if there are multiple items.
    ///
    /// (Note that all users of this function are, or should be, deprecated.)
    fn to_singleton_legacy(&self) -> Result<Option<&ListenItem>, ListenUnsupported> {
        use CustomizableListen as CL;
        match &self.0 {
            CL::Disabled => Ok(None),
            CL::One(li) => Ok(Some(li)),
            CL::List(lst) => match lst.as_slice() {
                [] => Ok(None),
                [li] => Ok(Some(li)),
                [_, _, ..] => Err(ListenUnsupported {}),
            },
        }
    }

    /// Return true if this `Listen` only configures listening on loopback addresses (`127.0.0.0/8`
    /// and `::1`).
    ///
    /// Returns true if there are no addresses configured.
    pub fn is_loopback_only(&self) -> bool {
        self.ip_addrs_internal()
            .flatten()
            .all(|a| a.ip().is_loopback())
    }

    /// Deprecated.
    /// Use [`Self::is_loopback_only`] instead,
    /// which behaves the same but has the correct method name.
    #[deprecated(since = "0.37.0", note = "please use `is_loopback_only` instead")]
    pub fn is_localhost_only(&self) -> bool {
        self.is_loopback_only()
    }
}

impl Default for Listen {
    fn default() -> Self {
        Self::new_none()
    }
}

impl Display for Listen {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut sep = "";
        for item in self.0.items() {
            match item {
                ListenItem::Port(_) => {
                    write!(f, "{sep}localhost {item}")?;
                    sep = ", ";
                }
                _other => {
                    write!(f, "{sep}{item}")?;
                    sep = ", ";
                }
            }
        }
        Ok(())
    }
}

impl TryFrom<CustomizableListen> for Listen {
    type Error = InvalidListen;

    fn try_from(l: CustomizableListen) -> Result<Self, Self::Error> {
        match &l {
            CustomizableListen::Disabled | CustomizableListen::One(ListenItem::Port(0)) => {
                // A non-list standalone 0 means "none".
                Ok(Self(CustomizableListen::Disabled))
            }
            CustomizableListen::One(li) => {
                if li.is_port_zero() {
                    tracing::warn!(
                        "Configured to listen on port zero via {li}. \
                         This is deprecated. Instead, replace '0' with 'auto'."
                    );
                }
                Ok(Self(l))
            }
            CustomizableListen::List(list) => {
                // We don't support a standalone 0 port in a list item.
                if list.iter().any(|item| matches!(item, ListenItem::Port(0))) {
                    return Err(InvalidListen::ZeroPortInList);
                }
                // We warn on e.g. "127.0.0.1:0"
                if let Some(zero_li) = list.iter().find(|li| li.is_port_zero()) {
                    tracing::warn!(
                        "Configured to listen on port zero via {zero_li}. \
                         This is deprecated. Instead, replace '0' with 'auto'."
                    );
                }
                Ok(Self(l))
            }
        }
    }
}

impl From<Listen> for CustomizableListen {
    fn from(l: Listen) -> Self {
        l.0
    }
}

/// [`Listen`] configuration specified something not supported by application code
#[derive(thiserror::Error, Debug, Clone)]
#[non_exhaustive]
#[error("Unsupported listening configuration")]
pub struct ListenUnsupported {}

/// Listen configuration is invalid
#[derive(thiserror::Error, Debug, Clone)]
#[non_exhaustive]
enum InvalidListen {
    /// Specified listen was a list containing a zero integer
    #[error("Invalid listen specification: zero (for no port) not permitted in list")]
    ZeroPortInList,
}

/// A general structure for configuring listening ports.
///
/// This is meant to provide some basic parsing without being too opinionated.
/// If you have further requirements, you should wrap this in a new type.
/// For example if `CustomizableListen` supports keywords or flags in the future such as "auto",
/// any config options that don't want to support them should use a wrapper type that handles them
/// and returns an error.
#[derive(Clone, Hash, Debug, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "ListenSerde", into = "ListenSerde")]
enum CustomizableListen {
    /// Explicitly disabled with `false`.
    Disabled,
    /// A single item not in a list.
    One(ListenItem),
    /// A list of items.
    List(Vec<ListenItem>),
}

impl CustomizableListen {
    /// All configured listen options.
    fn items(&self) -> impl Iterator<Item = &ListenItem> {
        match self {
            Self::Disabled => Either::Right(std::slice::Iter::default()),
            Self::One(one) => Either::Left(iter::once(one)),
            Self::List(many) => Either::Right(many.iter()),
        }
    }
}

/// One item in the [`CustomizableListen`].
///
/// This type defines a common format for parsing.
/// We don't assign any particular meaning to the variants.
/// For example a standalone port doesn't imply anything about what IP address should be used.
/// Similarly, a port of 0 doesn't have any inherent meaning.
/// For example a port of 0 might mean "don't listen" (when network addresses are optional)
/// or might mean "raise an error" (when network addresses are required).
/// It's up to the user of this type to assign meaning to the values given.
///
/// We distinguish a standalone port,
/// rather than just storing two `net:SocketAddr`,
/// so that we can handle localhost (which means two address families) specially
/// in order to implement `localhost_port_legacy()`.
#[derive(Clone, Hash, Debug, Ord, PartialOrd, Eq, PartialEq)]
// If we add new variants, it *is* a breaking change.
// We want a compile-time error, not a runtime error.
#[allow(clippy::exhaustive_enums)]
enum ListenItem {
    /// One port, both IPv6 and IPv4
    Port(u16),

    /// IPv6 and/or IPv4, arbitrarily chosen ports.
    Auto,

    /// Specific address, arbitrarily chosen port.
    AutoPort(IpAddr),

    /// Any other single socket address
    General(SocketAddr),
}

impl ListenItem {
    /// Return the `SocketAddr`s implied by this item
    ///
    /// If the item is a standalone port, then the returned iterator will return a socket address
    /// using that port for each IP address in `ips_for_port`.
    fn iter<'a>(
        &'a self,
        ips_for_port: impl IntoIterator<Item = IpAddr> + 'a,
    ) -> impl Iterator<Item = SocketAddr> + 'a {
        use ListenItem as LI;
        let with_ips = |portnum| {
            Either::Left({
                ips_for_port
                    .into_iter()
                    .map(move |ip| SocketAddr::new(ip, portnum))
            })
        };

        match self {
            &LI::Port(port) => with_ips(port),
            LI::Auto => with_ips(0),
            LI::AutoPort(addr) => Either::Right(iter::once((*addr, 0).into())),
            LI::General(addr) => Either::Right(iter::once(*addr)),
        }
    }

    /// Return true if this ListenItem is "addr:auto" or "auto"
    fn is_auto(&self) -> bool {
        use ListenItem as LI;
        match self {
            LI::Port(_) => false,
            LI::Auto => true,
            LI::AutoPort(_) => true,
            LI::General(_) => false,
        }
    }

    /// Return true if this ListenItem is using an explicit (deprecated) port value of 0.
    fn is_port_zero(&self) -> bool {
        use ListenItem as LI;

        match self {
            LI::Port(port) => *port == 0,
            LI::Auto => false,
            LI::AutoPort(_) => false,
            LI::General(addr) => addr.port() == 0,
        }
    }
}

impl Display for ListenItem {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ListenItem::Port(port) => write!(f, "port {}", port)?,
            ListenItem::Auto => write!(f, "auto")?,
            ListenItem::AutoPort(addr) => write!(f, "{addr}:auto")?,
            ListenItem::General(addr) => write!(f, "{}", addr)?,
        }
        Ok(())
    }
}
/// How we (de) serialize a [`Listen`]
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
// the default error message from serde's "untagged" is useless for users, so we provide our own
#[serde(expecting = "value was not a bool, `u16` integer, string, or list of integers/strings")]
enum ListenSerde {
    /// for `listen = false` (in TOML syntax)
    Bool(bool),

    /// A bare item
    One(ListenItemSerde),

    /// An item in a list
    List(Vec<ListenItemSerde>),
}

/// One item in the list of a list-ish `Listen`, or the plain value
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
// the default error message from serde's "untagged" is useless for users, so we provide our own
#[serde(expecting = "item was not a `u16` integer or string")]
enum ListenItemSerde {
    /// An integer.
    Port(u16),

    /// A string.
    String(String),
}

impl From<CustomizableListen> for ListenSerde {
    fn from(l: CustomizableListen) -> Self {
        match l {
            CustomizableListen::Disabled => ListenSerde::Bool(false),
            CustomizableListen::One(item) => ListenSerde::One(item.into()),
            CustomizableListen::List(list) => match list.as_slice() {
                [] => ListenSerde::List(Vec::new()),
                [one] => ListenSerde::List(vec![one.clone().into()]),
                list => ListenSerde::List(list.iter().cloned().map(Into::into).collect()),
            },
        }
    }
}
impl From<ListenItem> for ListenItemSerde {
    fn from(i: ListenItem) -> Self {
        use ListenItem as LI;
        match i {
            LI::Port(port) => Self::Port(port),
            LI::Auto => Self::String("auto".to_string()),
            LI::AutoPort(addr) => Self::String(format!("{addr}:auto")),
            LI::General(addr) => Self::String(addr.to_string()),
        }
    }
}

/// Listen configuration is invalid
#[derive(thiserror::Error, Debug, Clone)]
#[non_exhaustive]
enum InvalidCustomizableListen {
    /// Bool was `true` but that's not an address.
    #[error("Invalid listen specification: need actual addr/port, or `false`; not `true`")]
    InvalidBool,

    /// Specified listen was a string but couldn't parse to a [`SocketAddr`].
    #[error("Invalid listen specification: failed to parse string: {0}")]
    InvalidString(#[from] std::net::AddrParseError),
}
impl TryFrom<ListenSerde> for CustomizableListen {
    type Error = InvalidCustomizableListen;

    fn try_from(l: ListenSerde) -> Result<CustomizableListen, Self::Error> {
        use ListenSerde as LS;
        Ok(match l {
            // A false value not in a list is interpreted as "none".
            LS::Bool(false) => CustomizableListen::Disabled,
            LS::Bool(true) => return Err(InvalidCustomizableListen::InvalidBool),
            // An empty string not in a list is interpreted as "none".
            LS::One(ListenItemSerde::String(s)) if s.is_empty() => CustomizableListen::List(vec![]),
            LS::One(i) => CustomizableListen::One(i.try_into()?),
            LS::List(l) => {
                CustomizableListen::List(l.into_iter().map(|i| i.try_into()).try_collect()?)
            }
        })
    }
}
impl ListenItemSerde {}
impl TryFrom<ListenItemSerde> for ListenItem {
    type Error = InvalidCustomizableListen;

    fn try_from(i: ListenItemSerde) -> Result<ListenItem, Self::Error> {
        use ListenItem as LI;
        use ListenItemSerde as LIS;
        Ok(match i {
            LIS::String(a) => {
                if a == "auto" {
                    LI::Auto
                } else if let Some(ip_addr) = a.strip_suffix(":auto") {
                    LI::AutoPort(ip_addr.parse()?)
                } else {
                    LI::General(a.parse()?)
                }
            }
            LIS::Port(p) => LI::Port(p),
        })
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    #[derive(Debug, Default, Deserialize, Serialize)]
    struct TestConfigFile {
        #[serde(default)]
        listen: Option<Listen>,
    }

    #[test]
    fn listen_parse() {
        use ListenItem as LI;

        let localhost6 = |p| SocketAddr::new(Ipv6Addr::LOCALHOST.into(), p);
        let localhost4 = |p| SocketAddr::new(Ipv4Addr::LOCALHOST.into(), p);
        let unspec6 = |p| SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), p);

        #[allow(clippy::needless_pass_by_value)] // we do this for consistency
        fn chk(
            exp_i: Vec<ListenItem>,
            exp_addrs: Result<Vec<Vec<SocketAddr>>, ()>,
            exp_lpd: Result<Option<u16>, ()>,
            s: &str,
        ) {
            let tc: TestConfigFile = toml::from_str(s).expect(s);
            let ll = tc.listen.unwrap();
            eprintln!("s={:?} ll={:?}", &s, &ll);
            assert_eq!(ll.0.items().cloned().collect::<Vec<_>>(), exp_i);
            assert_eq!(
                ll.ip_addrs()
                    .map(|a| a.map(|l| l.collect_vec()).collect_vec())
                    .map_err(|_| ()),
                exp_addrs
            );
            #[allow(deprecated)]
            {
                assert_eq!(ll.localhost_port_legacy().map_err(|_| ()), exp_lpd);
            }
        }

        let chk_err = |exp, s: &str| {
            let got: Result<TestConfigFile, _> = toml::from_str(s);
            let got = got.expect_err(s).to_string();
            assert!(got.contains(exp), "s={:?} got={:?} exp={:?}", s, got, exp);
        };

        let chk_none = |s: &str| {
            chk(vec![], Ok(vec![]), Ok(None), &format!("listen = {}", s));
            chk_err(
                "", /* any error will do */
                &format!("listen = [ {} ]", s),
            );
        };

        let chk_1 = |v: ListenItem, addrs: Vec<Vec<SocketAddr>>, port, s| {
            chk(
                vec![v.clone()],
                Ok(addrs.clone()),
                port,
                &format!("listen = {}", s),
            );
            chk(
                vec![v.clone()],
                Ok(addrs.clone()),
                port,
                &format!("listen = [ {} ]", s),
            );
            chk(
                vec![v, LI::Port(23.try_into().unwrap())],
                Ok([addrs, vec![vec![localhost6(23), localhost4(23)]]]
                    .into_iter()
                    .flatten()
                    .collect()),
                Err(()),
                &format!("listen = [ {}, 23 ]", s),
            );
        };

        chk_none(r#""""#);
        chk_none(r#"0"#);
        chk_none(r#"false"#);
        chk(vec![], Ok(vec![]), Ok(None), r#"listen = []"#);

        chk_1(
            LI::Port(42.try_into().unwrap()),
            vec![vec![localhost6(42), localhost4(42)]],
            Ok(Some(42)),
            "42",
        );
        chk_1(
            LI::General(unspec6(56)),
            vec![vec![unspec6(56)]],
            Err(()),
            r#""[::]:56""#,
        );

        let chk_err_1 = |e, el, s| {
            chk_err(e, &format!("listen = {}", s));
            chk_err(el, &format!("listen = [ {} ]", s));
            chk_err(el, &format!("listen = [ 23, {}, 77 ]", s));
        };

        chk_err_1(
            "need actual addr/port",
            "value was not a bool, `u16` integer, string, or list of integers/strings",
            "true",
        );
        chk_err(
            "value was not a bool, `u16` integer, string, or list of integers/strings",
            r#"listen = [ [] ]"#,
        );

        chk_1(
            LI::Auto,
            vec![vec![localhost6(0), localhost4(0)]],
            Err(()),
            r#" "auto" "#,
        );

        chk_1(
            LI::AutoPort("1.2.3.4".parse().unwrap()),
            vec![vec!["1.2.3.4:0".parse().unwrap()]],
            Err(()),
            r#" "1.2.3.4:auto" "#,
        );
    }

    #[test]
    fn more_parsing_checks() {
        let config: TestConfigFile = toml::from_str(r#"listen = false"#).unwrap();
        assert!(config.listen.unwrap().is_empty());

        let config: TestConfigFile = toml::from_str(r#"listen = 0"#).unwrap();
        assert!(config.listen.unwrap().is_empty());

        let config: TestConfigFile = toml::from_str(r#"listen = 1"#).unwrap();
        #[rustfmt::skip]
        assert_eq!(config.listen.unwrap().ip_addrs().unwrap().flatten().count(), 2);

        let config: TestConfigFile = toml::from_str(r#"listen = """#).unwrap();
        assert!(config.listen.unwrap().is_empty());

        let config: TestConfigFile = toml::from_str(r#"listen = "127.0.0.1:8080""#).unwrap();
        #[rustfmt::skip]
        assert_eq!(config.listen.unwrap().ip_addrs().unwrap().flatten().count(), 1);

        let config: TestConfigFile = toml::from_str(r#"listen = ["127.0.0.1:8080"]"#).unwrap();
        #[rustfmt::skip]
        assert_eq!(config.listen.unwrap().ip_addrs().unwrap().flatten().count(), 1);

        let config: TestConfigFile = toml::from_str(r#"listen = "127.0.0.1:0""#).unwrap();
        #[rustfmt::skip]
        assert_eq!(config.listen.unwrap().ip_addrs().unwrap().flatten().count(), 1);

        let config: TestConfigFile = toml::from_str(r#"listen = ["127.0.0.1:0"]"#).unwrap();
        #[rustfmt::skip]
        assert_eq!(config.listen.unwrap().ip_addrs().unwrap().flatten().count(), 1);

        let config: TestConfigFile = toml::from_str(r#"listen = [1]"#).unwrap();
        #[rustfmt::skip]
        assert_eq!(config.listen.unwrap().ip_addrs().unwrap().flatten().count(), 2);

        let config: TestConfigFile = toml::from_str(r#"listen = [1, 2]"#).unwrap();
        #[rustfmt::skip]
        assert_eq!(config.listen.unwrap().ip_addrs().unwrap().flatten().count(), 4);

        let config: TestConfigFile = toml::from_str(r#"listen = ["127.0.0.1:8080", 2]"#).unwrap();
        #[rustfmt::skip]
        assert_eq!(config.listen.unwrap().ip_addrs().unwrap().flatten().count(), 3);

        assert!(toml::from_str::<TestConfigFile>(r#"listen = [false]"#).is_err());
        assert!(toml::from_str::<TestConfigFile>(r#"listen = true"#).is_err());
        assert!(toml::from_str::<TestConfigFile>(r#"listen = [true]"#).is_err());
        assert!(toml::from_str::<TestConfigFile>(r#"listen = [0]"#).is_err());
        assert!(toml::from_str::<TestConfigFile>(r#"listen = ["127.0.0.1:8080", 0]"#).is_err());
        assert!(toml::from_str::<TestConfigFile>(r#"listen = ["foo"]"#).is_err());
        assert!(toml::from_str::<TestConfigFile>(r#"listen = ["127.0.0.1:8080", "foo"]"#).is_err());
        assert!(toml::from_str::<TestConfigFile>(r#"listen = [""]"#).is_err());
        assert!(toml::from_str::<TestConfigFile>(r#"listen = ["127.0.0.1:8080", ""]"#).is_err());
    }

    #[test]
    fn constructor() {
        let l = Listen::new_none();
        assert!(l.is_empty());
        assert_eq!(l.ip_addrs().unwrap().flatten().count(), 0);

        let l = Listen::new_localhost(1234);
        assert!(!l.is_empty());
        assert_eq!(l.ip_addrs().unwrap().flatten().count(), 2);

        let l = Listen::new_localhost(0);
        assert!(l.is_empty());
        assert_eq!(l.ip_addrs().unwrap().flatten().count(), 0);

        let l = Listen::new_localhost_optional(Some(1234));
        assert!(!l.is_empty());
        assert_eq!(l.ip_addrs().unwrap().flatten().count(), 2);

        let l = Listen::new_localhost_optional(Some(0));
        assert!(l.is_empty());
        assert_eq!(l.ip_addrs().unwrap().flatten().count(), 0);

        let l = Listen::new_localhost_optional(None);
        assert!(l.is_empty());
        assert_eq!(l.ip_addrs().unwrap().flatten().count(), 0);
    }

    #[test]
    fn display_listen() {
        let empty = Listen::new_none();
        assert_eq!(empty.to_string(), "");

        let one_port = Listen::new_localhost(1234);
        assert_eq!(one_port.to_string(), "localhost port 1234");

        let multi_port = Listen(CustomizableListen::List(vec![
            ListenItem::Port(1111.try_into().unwrap()),
            ListenItem::Port(2222.try_into().unwrap()),
        ]));
        assert_eq!(
            multi_port.to_string(),
            "localhost port 1111, localhost port 2222"
        );

        let multi_addr = Listen(CustomizableListen::List(vec![
            ListenItem::Port(1234.try_into().unwrap()),
            ListenItem::General("1.2.3.4:5678".parse().unwrap()),
        ]));
        assert_eq!(multi_addr.to_string(), "localhost port 1234, 1.2.3.4:5678");

        let multi_addr = Listen(CustomizableListen::List(vec![
            ListenItem::Auto,
            ListenItem::AutoPort("1.2.3.4".parse().unwrap()),
        ]));
        assert_eq!(multi_addr.to_string(), "auto, 1.2.3.4:auto");
    }

    #[test]
    fn is_localhost() {
        fn localhost_only(s: &str) -> bool {
            let tc: TestConfigFile = toml::from_str(s).expect(s);
            tc.listen.unwrap().is_loopback_only()
        }

        assert_eq!(localhost_only(r#"listen = [ ]"#), true);
        assert_eq!(localhost_only(r#"listen = [ 3 ]"#), true);
        assert_eq!(localhost_only(r#"listen = [ 3, 10 ]"#), true);
        assert_eq!(localhost_only(r#"listen = [ "127.0.0.1:9050" ]"#), true);
        assert_eq!(localhost_only(r#"listen = [ "[::1]:9050" ]"#), true);
        assert_eq!(
            localhost_only(r#"listen = [ "[::1]:9050", "192.168.0.1:1234" ]"#),
            false
        );
        assert_eq!(localhost_only(r#"listen = [  "192.168.0.1:1234" ]"#), false);
    }
}
