//! Configuration for ports and addresses to listen on.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::{fmt::Display, iter, num::NonZeroU16};

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
#[derive(Clone, Hash, Debug, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "ListenSerde", into = "ListenSerde")]
#[derive(Default)]
pub struct Listen(Vec<ListenItem>);

impl Listen {
    /// Create a new `Listen` specifying no addresses (no listening)
    pub fn new_none() -> Listen {
        Listen(vec![])
    }

    /// Create a new `Listen` specifying listening on a port on localhost
    ///
    /// Special case: if `port` is zero, specifies no listening.
    pub fn new_localhost(port: u16) -> Listen {
        Listen(
            port.try_into()
                .ok()
                .map(ListenItem::Localhost)
                .into_iter()
                .collect_vec(),
        )
    }

    /// Create a new `Listen`, possibly specifying listening on a port on localhost
    ///
    /// Special case: if `port` is `Some(0)`, also specifies no listening.
    pub fn new_localhost_optional(port: Option<u16>) -> Listen {
        Self::new_localhost(port.unwrap_or_default())
    }

    /// Return true if no listening addresses have been configured
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
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
        Ok(self.0.iter().map(|i| i.iter()))
    }

    /// Get the localhost port to listen on
    ///
    /// Returns `None` if listening is configured to be disabled.
    ///
    /// Fails, giving an unsupported error, if the configuration
    /// isn't just "listen on a single localhost port in all address families"
    pub fn localhost_port_legacy(&self) -> Result<Option<u16>, ListenUnsupported> {
        use ListenItem as LI;
        Ok(match &*self.0 {
            [] => None,
            [LI::Localhost(port)] => Some((*port).into()),
            _ => return Err(ListenUnsupported {}),
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
        use ListenItem as LI;
        Ok(match &*self.0 {
            [] => None,
            [LI::Localhost(port)] => Some((Ipv4Addr::LOCALHOST, u16::from(*port)).into()),
            [LI::General(sa)] => Some(*sa),
            _ => return Err(ListenUnsupported {}),
        })
    }

    /// Return true if this `Listen` only configures listening on localhost.
    pub fn is_localhost_only(&self) -> bool {
        self.0.iter().all(ListenItem::is_localhost)
    }
}

impl Display for Listen {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut sep = "";
        for a in &self.0 {
            write!(f, "{sep}{a}")?;
            sep = ", ";
        }
        Ok(())
    }
}
/// [`Listen`] configuration specified something not supported by application code
#[derive(thiserror::Error, Debug, Clone)]
#[non_exhaustive]
#[error("Unsupported listening configuration")]
pub struct ListenUnsupported {}

/// One item in the `Listen`
///
/// We distinguish `Localhost`,
/// rather than just storing two `net:SocketAddr`,
/// so that we can handle localhost (which means two address families) specially
/// in order to implement `localhost_port_legacy()`.
#[derive(Clone, Hash, Debug, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
enum ListenItem {
    /// One port, both IPv6 and IPv4
    Localhost(NonZeroU16),

    /// Any other single socket address
    General(SocketAddr),
}

impl ListenItem {
    /// Return the `SocketAddr`s implied by this item
    fn iter(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        use ListenItem as LI;
        match self {
            &LI::Localhost(port) => Either::Left({
                let port = port.into();
                let addrs: [IpAddr; 2] = [Ipv6Addr::LOCALHOST.into(), Ipv4Addr::LOCALHOST.into()];
                addrs.into_iter().map(move |ip| SocketAddr::new(ip, port))
            }),
            LI::General(addr) => Either::Right(iter::once(addr).cloned()),
        }
    }

    /// Return true if this is a localhost address.
    fn is_localhost(&self) -> bool {
        use ListenItem as LI;
        match self {
            LI::Localhost(_) => true,
            LI::General(addr) => addr.ip().is_loopback(),
        }
    }
}

impl Display for ListenItem {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ListenItem::Localhost(port) => write!(f, "localhost port {}", port)?,
            ListenItem::General(addr) => write!(f, "{}", addr)?,
        }
        Ok(())
    }
}
/// How we (de) serialize a [`Listen`]
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
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
enum ListenItemSerde {
    /// An integer.
    ///
    /// When appearing "loose" (in ListenSerde::One), `0` is parsed as none.
    Port(u16),

    /// An string which will be parsed as an address and port
    ///
    /// When appearing "loose" (in ListenSerde::One), `""` is parsed as none.
    String(String),
}

// This implementation isn't fallible, but clippy thinks it is because of the unwrap.
// The unwrap is just there because we can't pattern-match on a Vec
#[allow(clippy::fallible_impl_from)]
impl From<Listen> for ListenSerde {
    fn from(l: Listen) -> ListenSerde {
        let l = l.0;
        match l.len() {
            0 => ListenSerde::Bool(false),
            1 => ListenSerde::One(l.into_iter().next().expect("len=1 but no next").into()),
            _ => ListenSerde::List(l.into_iter().map(Into::into).collect()),
        }
    }
}
impl From<ListenItem> for ListenItemSerde {
    fn from(i: ListenItem) -> ListenItemSerde {
        use ListenItem as LI;
        use ListenItemSerde as LIS;
        match i {
            LI::Localhost(port) => LIS::Port(port.into()),
            LI::General(addr) => LIS::String(addr.to_string()),
        }
    }
}

/// Listen configuration is invalid
#[derive(thiserror::Error, Debug, Clone)]
#[non_exhaustive]
pub enum InvalidListen {
    /// Bool was `true` but that's not an address.
    #[error("Invalid listen specification: need actual addr/port, or `false`; not `true`")]
    InvalidBool,

    /// Specified listen was a string but couldn't parse to a [`SocketAddr`].
    #[error("Invalid listen specification: failed to parse string: {0}")]
    InvalidString(#[from] std::net::AddrParseError),

    /// Specified listen was a list containing a zero integer
    #[error("Invalid listen specification: zero (for no port) not permitted in list")]
    ZeroPortInList,
}
impl TryFrom<ListenSerde> for Listen {
    type Error = InvalidListen;

    fn try_from(l: ListenSerde) -> Result<Listen, Self::Error> {
        use ListenSerde as LS;
        Ok(Listen(match l {
            LS::Bool(false) => vec![],
            LS::Bool(true) => return Err(InvalidListen::InvalidBool),
            LS::One(i) if i.means_none() => vec![],
            LS::One(i) => vec![i.try_into()?],
            LS::List(l) => l.into_iter().map(|i| i.try_into()).try_collect()?,
        }))
    }
}
impl ListenItemSerde {
    /// Is this item actually a sentinel, meaning "don't listen, disable this thing"?
    ///
    /// Allowed only bare, not in a list.
    fn means_none(&self) -> bool {
        use ListenItemSerde as LIS;
        match self {
            &LIS::Port(port) => port == 0,
            LIS::String(s) => s.is_empty(),
        }
    }
}
impl TryFrom<ListenItemSerde> for ListenItem {
    type Error = InvalidListen;

    fn try_from(i: ListenItemSerde) -> Result<ListenItem, Self::Error> {
        use ListenItem as LI;
        use ListenItemSerde as LIS;
        Ok(match i {
            LIS::String(s) => LI::General(s.parse()?),
            LIS::Port(p) => LI::Localhost(p.try_into().map_err(|_| InvalidListen::ZeroPortInList)?),
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
    #![allow(clippy::unchecked_duration_subtraction)]
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
            assert_eq!(ll, Listen(exp_i));
            assert_eq!(
                ll.ip_addrs()
                    .map(|a| a.map(|l| l.collect_vec()).collect_vec())
                    .map_err(|_| ()),
                exp_addrs
            );
            assert_eq!(ll.localhost_port_legacy().map_err(|_| ()), exp_lpd);
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
                vec![v, LI::Localhost(23.try_into().unwrap())],
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
            LI::Localhost(42.try_into().unwrap()),
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

        chk_err_1("need actual addr/port", "did not match any variant", "true");
        chk_err("did not match any variant", r#"listen = [ [] ]"#);
    }

    #[test]
    fn display_listen() {
        let empty = Listen::new_none();
        assert_eq!(empty.to_string(), "");

        let one_port = Listen::new_localhost(1234);
        assert_eq!(one_port.to_string(), "localhost port 1234");

        let multi_port = Listen(vec![
            ListenItem::Localhost(1111.try_into().unwrap()),
            ListenItem::Localhost(2222.try_into().unwrap()),
        ]);
        assert_eq!(
            multi_port.to_string(),
            "localhost port 1111, localhost port 2222"
        );

        let multi_addr = Listen(vec![
            ListenItem::Localhost(1234.try_into().unwrap()),
            ListenItem::General("1.2.3.4:5678".parse().unwrap()),
        ]);
        assert_eq!(multi_addr.to_string(), "localhost port 1234, 1.2.3.4:5678");
    }

    #[test]
    fn is_localhost() {
        fn localhost_only(s: &str) -> bool {
            let tc: TestConfigFile = toml::from_str(s).expect(s);
            tc.listen.unwrap().is_localhost_only()
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
