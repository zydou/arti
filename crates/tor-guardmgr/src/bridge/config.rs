//! Configuration logic and types for bridges.

use std::fmt::{self, Display};
use std::iter;
use std::net::SocketAddr;
use std::str::FromStr;

use itertools::{chain, Itertools};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use tor_basic_utils::derive_serde_raw;
use tor_config::define_list_builder_accessors;
use tor_config::{impl_standard_builder, ConfigBuildError};
use tor_linkspec::{ChanTarget, ChannelMethod, HasChanMethod};
use tor_linkspec::{HasAddrs, HasRelayIds, RelayIdRef, RelayIdType};
use tor_linkspec::{RelayId, RelayIdError, TransportIdError};
use tor_llcrypto::pk::{ed25519::Ed25519Identity, rsa::RsaIdentity};

use tor_linkspec::BridgeAddr;

#[cfg(feature = "pt-client")]
use tor_linkspec::{PtAddrError, PtTarget, PtTargetInvalidSetting};

/// A relay not listed on the main tor network, used for anticensorship.
///
/// This object represents a bridge as configured by the user or by software
/// running on the user's behalf.
///
/// # String representation
///
/// Can be parsed from, and represented as, a "bridge line" string,
/// using the [`FromStr`] and [`Display`] implementations.
///
/// The syntax supported is a sequence of words,
/// separated by ASCII whitespace,
/// in the following order:
///
///  * Optionally, the word `Bridge` (or a case variant thereof).
///    (`Bridge` is not part of a bridge line, but is ignored here
///    for convenience when copying a line out of a C Tor `torrc`.)
///
///  * Optionally, the name of the pluggable transport to use.
///    If not supplied, Arti will make the connection directly, itself.
///
///  * The `Host:ORPort` to connect to.
///    `Host` can be an IPv4 address, or an IPv6 address in brackets `[ ]`.
///    When a pluggable transport is in use, `Host` can also be a hostname;
///    or
///    if the transport supports operating without a specified address.
///    `Host:ORPort` can be omitted and replaced with `-`.
///
///  * One or more identity key fingerprints,
///    each in one of the supported (RSA or ed25519) fingerprint formats.
///    Currently, supplying an RSA key is required; an ed25519 key is optional.
///
///  * When a pluggable transport is in use,
///    zero or more `key=value` parameters to pass to the transport
///    (smuggled in the SOCKS handshake, as described in the Tor PT specification).
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
// TODO pt-client: Derive builder and associated config types.  See ticket #604.
pub struct BridgeConfig {
    // TODO pt-client: I am not sold on this exact representation for Bridge; it
    // needs to be something like this, but not necessarily this exact set of
    // members.
    //
    /// Address and transport via which the bridge can be reached, and
    /// the parameters for those transports.
    ///
    /// Restriction: This `addrs` may NOT contain more than one address.
    addrs: ChannelMethod,

    /// The RSA identity of the bridge.
    rsa_id: RsaIdentity,

    /// The Ed25519 identity of the bridge.
    ed_id: Option<Ed25519Identity>,
}

impl HasRelayIds for BridgeConfig {
    fn identity(&self, key_type: RelayIdType) -> Option<RelayIdRef<'_>> {
        match key_type {
            RelayIdType::Ed25519 => self.ed_id.as_ref().map(RelayIdRef::Ed25519),
            RelayIdType::Rsa => Some(RelayIdRef::Rsa(&self.rsa_id)),
            _ => None,
        }
    }
}

impl HasChanMethod for BridgeConfig {
    fn chan_method(&self) -> ChannelMethod {
        self.addrs.clone()
    }
}

impl HasAddrs for BridgeConfig {
    fn addrs(&self) -> &[SocketAddr] {
        self.addrs.addrs()
    }
}

impl ChanTarget for BridgeConfig {}

derive_serde_raw! {
/// Builder for a `BridgeConfig`.
///
/// Construct this with [`BridgeConfigBuilder::default()`] or [`BridgeConfig::builder()`],
/// call setter methods, and then call `build().`
//
// `BridgeConfig` contains a `ChannelMethod`.  This is convenient for its users,
// but means we can't use `#[derive(Builder)]` to autogenerate this.
#[derive(Deserialize, Serialize, Default, Clone, Debug)]
#[serde(try_from="BridgeConfigBuilderSerde", into="BridgeConfigBuilderSerde")]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct BridgeConfigBuilder = "BridgeConfigBuilder" {
    /// The `PtTransportName`, but not yet parsed or checked.
    ///
    /// `""` and `"-"` and `"bridge"` all mean "do not use a pluggable transport".
    transport: Option<String>,

    /// Host:ORPort
    addrs: Option<Vec<BridgeAddr>>,

    /// IDs
    ids: Option<Vec<RelayId>>,

    /// Settings (for the transport)
    settings: Option<Vec<(String, String)>>,
}
}
impl_standard_builder! { BridgeConfig: !Default }

/// serde representation of a `BridgeConfigBuilder`
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum BridgeConfigBuilderSerde {
    /// We understand a bridge line
    BridgeLine(String),
    /// We understand a dictionary matching BridgeConfigBuilder
    Dict(#[serde(with = "BridgeConfigBuilder_Raw")] BridgeConfigBuilder),
}

impl TryFrom<BridgeConfigBuilderSerde> for BridgeConfigBuilder {
    type Error = BridgeParseError;
    fn try_from(input: BridgeConfigBuilderSerde) -> Result<Self, Self::Error> {
        use BridgeConfigBuilderSerde::*;
        match input {
            BridgeLine(s) => s.parse(),
            Dict(d) => Ok(d),
        }
    }
}

impl From<BridgeConfigBuilder> for BridgeConfigBuilderSerde {
    fn from(input: BridgeConfigBuilder) -> BridgeConfigBuilderSerde {
        use BridgeConfigBuilderSerde::*;
        // Try to serialize as a bridge line if we can
        match input.build() {
            Ok(bridge) => BridgeLine(bridge.to_string()),
            Err(_) => Dict(input),
        }
    }
}

impl BridgeConfigBuilder {
    /// Set the transport protocol name (eg, a pluggable transport) to use.
    ///
    /// The empty string `""`, a single hyphen `"-"`, and the word `"bridge"`,
    /// all mean to connect directly;
    /// i.e., passing one of this is equivalent to
    /// calling [`direct()`](BridgeConfigBuilder::direct).
    ///
    /// The value is not checked at this point.
    pub fn transport(&mut self, transport: impl Into<String>) -> &mut Self {
        self.transport = Some(transport.into());
        self
    }

    /// Specify to use a direct connection.
    pub fn direct(&mut self) -> &mut Self {
        self.transport("")
    }

    /// Add a pluggable transport setting
    pub fn push_setting(&mut self, k: impl Into<String>, v: impl Into<String>) -> &mut Self {
        self.settings().push((k.into(), v.into()));
        self
    }
}

impl BridgeConfigBuilder {
    /// Build a `BridgeConfig`
    pub fn build(&self) -> Result<BridgeConfig, ConfigBuildError> {
        let transport = self.transport.as_deref().unwrap_or_default();
        let addrs = self.addrs.as_deref().unwrap_or_default();
        let settings = self.settings.as_deref().unwrap_or_default();

        #[allow(clippy::comparison_to_empty)] // .is_empty() would *not* be clearer
        let addrs = if transport == "" || transport == "-" || transport == "bridge" {
            if !settings.is_empty() {
                return Err(ConfigBuildError::Inconsistent {
                    fields: vec!["transport".into(), "settings".into()],
                    problem: "Specified `settings` for a direct bridge connection".into(),
                });
            }
            let addrs = addrs.iter().filter_map(|pta| match pta {
                BridgeAddr::IpPort(sa) => Some(Ok(*sa)),
                BridgeAddr::HostPort(..) => Some(Err(ConfigBuildError::Inconsistent {
                    fields: vec!["addrs".into(), "transport".into()],
                    problem: "`addrs` contains hostname and port, but only numeric addresses are supported for a direct bridge connection".into(),
                })),
                BridgeAddr::None => None,
                _ => Some(Err(ConfigBuildError::Inconsistent {
                    fields: vec!["addrs".into(), "transport".into()],
                    problem: "`addrs` contains unspported target address type, but only numeric addresses are supported for a direct bridge connection".into(),
                })),
            }).collect::<Result<Vec<SocketAddr>,_>>()?;
            if addrs.is_empty() {
                return Err(ConfigBuildError::Inconsistent {
                    fields: vec!["addrs".into(), "transport".into()],
                    problem: "Missing `addrs` for a direct bridge connection".into(),
                });
            }
            ChannelMethod::Direct(addrs)
        } else {
            #[cfg(not(feature = "pt-client"))]
            {
                return Err(ConfigBuildError::Invalid {
                    field: "transport".into(),
                    problem: "pluggable transport support disabled in tor-guardmgr cargo features"
                        .into(),
                });
            }
            #[cfg(feature = "pt-client")]
            {
                let addr = match addrs {
                    [] => BridgeAddr::None,
                    [addr] => addr.clone(),
                    [_, _, ..] => return Err(ConfigBuildError::Inconsistent {
                        fields: vec!["addrs".into(), "transport".into()],
                        problem:
                            "Transport (non-direct bridge) only supports a single nominal address"
                                .into(),
                    }),
                };
                let transport =
                    transport
                        .parse()
                        .map_err(|e: TransportIdError| ConfigBuildError::Invalid {
                            field: "transport".into(),
                            problem: e.to_string(),
                        })?;
                let mut target = PtTarget::new(transport, addr);
                for (i, (k, v)) in settings.iter().enumerate() {
                    // Using PtTargetSettings TryFrom would prevent us reporting the index i
                    target
                        .push_setting(k, v)
                        .map_err(|e| ConfigBuildError::Invalid {
                            field: format!("settings.{}", i),
                            problem: e.to_string(),
                        })?;
                }
                ChannelMethod::Pluggable(target)
            }
        };

        let mut rsa_id = None;
        let mut ed_id = None;

        /// Helper to store an id in `rsa_id` or `ed_id`
        fn store_id<T: Clone>(
            u: &mut Option<T>,
            desc: &str,
            v: &T,
        ) -> Result<(), ConfigBuildError> {
            if u.is_some() {
                Err(ConfigBuildError::Invalid {
                    field: "ids".into(),
                    problem: format!("multiple different ids of the same type ({})", desc),
                })
            } else {
                *u = Some(v.clone());
                Ok(())
            }
        }

        for (i, id) in self.ids.as_deref().unwrap_or_default().iter().enumerate() {
            match id {
                RelayId::Rsa(rsa) => store_id(&mut rsa_id, "RSA", rsa)?,
                RelayId::Ed25519(ed) => store_id(&mut ed_id, "ed25519", ed)?,
                other => {
                    return Err(ConfigBuildError::Invalid {
                        field: format!("ids.{}", i),
                        problem: format!("unsupported bridge id type {}", other.id_type()),
                    })
                }
            }
        }

        let rsa_id = rsa_id.ok_or_else(|| ConfigBuildError::Invalid {
            field: "ids".into(),
            problem: "need an RSA identity".into(),
        })?;

        Ok(BridgeConfig {
            addrs,
            rsa_id,
            ed_id,
        })
    }
}

/// `BridgeConfigBuilder` parses the same way as `BridgeConfig`
//
// We implement it this way round (rather than having the `impl FromStr for BridgeConfig`
// call this and then `build`, because the `BridgeConfig` parser
// does a lot of bespoke checking of the syntax and semantics.
// Doing it the other way, we'd have to unwrap a supposedly-never-existing `ConfigBuildError`,
// in `BridgeConfig`'s `FromStr` impl.
impl FromStr for BridgeConfigBuilder {
    type Err = BridgeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bridge: BridgeConfig = s.parse()?;

        let (transport, addrs, settings) = match bridge.addrs {
            ChannelMethod::Direct(addrs) => (
                "".into(),
                addrs.into_iter().map(BridgeAddr::IpPort).collect(),
                vec![],
            ),
            #[cfg(feature = "pt-client")]
            ChannelMethod::Pluggable(target) => {
                let (transport, addr, settings) = target.into_parts();
                (transport.into_inner(), vec![addr], settings.into_inner())
            }
        };

        let ids = chain!(
            iter::once(bridge.rsa_id.into()),
            bridge.ed_id.into_iter().map(Into::into),
        )
        .collect_vec();

        Ok(BridgeConfigBuilder {
            transport: Some(transport),
            addrs: Some(addrs),
            settings: Some(settings),
            ids: Some(ids),
        })
    }
}

define_list_builder_accessors! {
    struct BridgeConfigBuilder {
        pub addrs: [BridgeAddr],
        pub ids: [RelayId],
        pub settings: [(String,String)],
    }
}

/// Error when parsing a bridge line from a string
#[derive(Error, Clone, Debug)]
#[non_exhaustive]
pub enum BridgeParseError {
    /// Bridge line was empty
    #[error("Bridge line was empty")]
    Empty,

    /// Expected PT name or host:port, looked a bit like a PT name, but didn't parse
    #[error(
        "Cannot parse {word:?} as PT name ({pt_error}), nor as direct bridge IpAddress:ORPort"
    )]
    InvalidPtOrAddr {
        /// The offending word
        word: String,
        /// Why we couldn't parse it as a PT name
        pt_error: TransportIdError,
    },

    /// Expected PT name or host:port, looked a bit like a host:port, but didn't parse
    #[error(
        "Cannot parse {word:?} as direct bridge IpAddress:ORPort ({addr_error}), nor as PT name"
    )]
    InvalidIpAddrOrPt {
        /// The offending word
        word: String,
        /// Why we couldn't parse it as an IP address and port
        addr_error: std::net::AddrParseError,
    },

    /// Cannot parse pluggable transport host address
    #[cfg(feature = "pt-client")]
    #[error("Cannot parse {word:?} as pluggable transport Host:ORPort")]
    InvalidIPtHostAddr {
        /// The offending word
        word: String,
        /// Why we couldn't parse it as a PT target Host:ORPort
        #[source]
        source: PtAddrError,
    },

    /// Cannot parse value as identity key, or PT key=value
    #[error("Cannot parse {word:?} as identity key ({id_error}), or PT key=value")]
    InvalidIdentityOrParameter {
        /// The offending word
        word: String,
        /// Why we couldn't parse it as a fingerprint
        id_error: RelayIdError,
    },

    /// PT key=value parameter does not contain an equals sign
    #[cfg(feature = "pt-client")]
    #[error("Expected PT key=value parameter, found {word:?} (which lacks an equals sign)")]
    InvalidPtKeyValue {
        /// The offending word
        word: String,
    },

    /// Invalid pluggable transport setting syntax
    #[cfg(feature = "pt-client")]
    #[error("Cannot parse {word:?} as a PT key=value parameter")]
    InvalidPluggableTransportSetting {
        /// The offending word
        word: String,
        /// Why we couldn't parse it
        #[source]
        source: PtTargetInvalidSetting,
    },

    /// More than one identity of the same type specified
    #[error("More than one identity of the same type specified, at {word:?}")]
    MultipleIdentitiesOfSameType {
        /// The offending word
        word: String,
    },

    /// Identity specified of unsupported type
    #[error("Identity specified but not of supported type, at {word:?}")]
    UnsupportedIdentityType {
        /// The offending word
        word: String,
    },

    /// Parameters may only be specified with a pluggable transport
    #[error("Parameters supplied but not valid without a pluggable transport")]
    DirectParametersNotAllowed,

    /// Every bridge must have an RSA identity
    #[error("Bridge line lacks specification of RSA identity key")]
    NoRsaIdentity,

    /// Pluggable transport support disabled in cargo features
    // We deliberately make this one *not* configured out if PT support is enabled
    #[error("Pluggable transport requested ({word:?} is not an IpAddress:ORPort), but support disabled in cargo features")]
    PluggableTransportsNotSupported {
        /// The offending word
        word: String,
    },
}

impl FromStr for BridgeConfig {
    type Err = BridgeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use BridgeParseError as BPE;

        let mut s = s.trim().split_ascii_whitespace().peekable();

        // This implements the parsing of bridge lines.
        // Refer to the specification in the rustdoc comment for `Bridge`.

        //  * Optionally, the word `Bridge` ...

        let bridge_word = s.peek().ok_or(BPE::Empty)?;
        if bridge_word.eq_ignore_ascii_case("bridge") {
            s.next();
        }

        //  * Optionally, the name of the pluggable transport to use.
        //  * The `Host:ORPort` to connect to.

        #[cfg_attr(not(feature = "pt-client"), allow(unused_mut))]
        let mut method = {
            let word = s.next().ok_or(BPE::Empty)?;
            if word.contains(':') {
                // Not a PT name.  Hope it's an address:port.
                let addr = word.parse().map_err(|addr_error| BPE::InvalidIpAddrOrPt {
                    word: word.to_string(),
                    addr_error,
                })?;
                ChannelMethod::Direct(vec![addr])
            } else {
                #[cfg(not(feature = "pt-client"))]
                return Err(BPE::PluggableTransportsNotSupported {
                    word: word.to_string(),
                });

                #[cfg(feature = "pt-client")]
                {
                    let pt_name = word.parse().map_err(|pt_error| BPE::InvalidPtOrAddr {
                        word: word.to_string(),
                        pt_error,
                    })?;
                    let addr = s
                        .next()
                        .map(|s| s.parse())
                        .transpose()
                        .map_err(|source| BPE::InvalidIPtHostAddr {
                            word: word.to_string(),
                            source,
                        })?
                        .unwrap_or(BridgeAddr::None);
                    ChannelMethod::Pluggable(PtTarget::new(pt_name, addr))
                }
            }
        };

        //  * One or more identity key fingerprints,

        let mut rsa_id = None;
        let mut ed_id = None;

        while let Some(word) = s.peek() {
            // Helper to generate the errors if the same key type is specified more than once
            let check_several = |was_some| {
                if was_some {
                    Err(BPE::MultipleIdentitiesOfSameType {
                        word: word.to_string(),
                    })
                } else {
                    Ok(())
                }
            };

            match word.parse() {
                Err(id_error) => {
                    if word.contains('=') {
                        // Not a fingerprint, then, but a key=value.
                        break;
                    }
                    return Err(BPE::InvalidIdentityOrParameter {
                        word: word.to_string(),
                        id_error,
                    });
                }
                Ok(RelayId::Ed25519(id)) => check_several(ed_id.replace(id).is_some())?,
                Ok(RelayId::Rsa(id)) => check_several(rsa_id.replace(id).is_some())?,
                Ok(_) => {
                    return Err(BPE::UnsupportedIdentityType {
                        word: word.to_string(),
                    })?
                }
            }
            s.next();
        }

        //  * When a pluggable transport is in use,
        //    zero or more `key=value` parameters to pass to the transport

        #[cfg(not(feature = "pt-client"))]
        if s.next().is_some() {
            return Err(BPE::DirectParametersNotAllowed);
        }

        #[cfg(feature = "pt-client")]
        for word in s {
            let (k, v) = word.split_once('=').ok_or_else(|| BPE::InvalidPtKeyValue {
                word: word.to_string(),
            })?;

            match &mut method {
                ChannelMethod::Direct(_) => return Err(BPE::DirectParametersNotAllowed),
                ChannelMethod::Pluggable(t) => t.push_setting(k, v).map_err(|source| {
                    BPE::InvalidPluggableTransportSetting {
                        word: word.to_string(),
                        source,
                    }
                })?,
            }
        }

        let rsa_id = rsa_id.ok_or(BPE::NoRsaIdentity)?;
        Ok(BridgeConfig {
            addrs: method,
            rsa_id,
            ed_id,
        })
    }
}

impl Display for BridgeConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let BridgeConfig {
            addrs,
            rsa_id,
            ed_id,
        } = self;

        //  * Optionally, the name of the pluggable transport to use.
        //  * The `Host:ORPort` to connect to.

        let settings = match addrs {
            ChannelMethod::Direct(a) => {
                if a.len() == 1 {
                    write!(f, "{}", a[0])?;
                } else {
                    panic!("Somehow created a Bridge config with multiple addrs.");
                }
                None
            }

            #[cfg(feature = "pt-client")]
            ChannelMethod::Pluggable(target) => {
                write!(f, "{} {}", target.transport(), target.addr())?;
                Some(target.settings())
            }
        };

        //  * One or more identity key fingerprints,

        write!(f, " {}", rsa_id)?;
        if let Some(ed_id) = ed_id {
            write!(f, " ed25519:{}", ed_id)?;
        }

        //  * When a pluggable transport is in use,
        //    zero or more `key=value` parameters to pass to the transport

        #[cfg(not(feature = "pt-client"))]
        let _: Option<()> = settings;

        #[cfg(feature = "pt-client")]
        for (k, v) in settings.into_iter().flatten() {
            write!(f, " {}={}", k, v)?;
        }

        Ok(())
    }
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
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    #[cfg(feature = "pt-client")]
    fn mk_pt_target(name: &str, addr: BridgeAddr, params: &[(&str, &str)]) -> ChannelMethod {
        let mut target = PtTarget::new(name.parse().unwrap(), addr);
        for &(k, v) in params {
            target.push_setting(k, v).unwrap();
        }
        ChannelMethod::Pluggable(target)
    }

    fn mk_direct(s: &str) -> ChannelMethod {
        ChannelMethod::Direct(vec![s.parse().unwrap()])
    }

    fn mk_rsa(s: &str) -> RsaIdentity {
        match s.parse().unwrap() {
            RelayId::Rsa(y) => y,
            _ => panic!("not rsa {:?}", s),
        }
    }
    fn mk_ed(s: &str) -> Ed25519Identity {
        match s.parse().unwrap() {
            RelayId::Ed25519(y) => y,
            _ => panic!("not ed {:?}", s),
        }
    }

    #[test]
    fn bridge_lines() {
        let chk = |sl: &[&str], exp: BridgeConfig| {
            for s in sl {
                let got: BridgeConfig = s.parse().expect(s);
                assert_eq!(got, exp, "{:?}", s);

                let display = got.to_string();
                assert_eq!(display, sl[0]);
            }
        };

        let chk_e = |sl: &[&str], exp: &str| {
            for s in sl {
                let got: Result<BridgeConfig, _> = s.parse();
                let got = got.expect_err(s);
                let got_s = got.to_string();
                assert!(
                    got_s.contains(exp),
                    "{:?} => {:?} ({}) not {}",
                    s,
                    &got,
                    &got_s,
                    exp
                );
            }
        };

        // example from https://tb-manual.torproject.org/bridges/, with cert= truncated
        #[cfg(feature = "pt-client")]
        chk(&[
            "obfs4 38.229.33.83:80 $0bac39417268b96b9f514e7f63fa6fba1a788955 cert=VwEFpk9F/UN9JED7XpG1XOjm/O8ZCXK80oPecgWnNDZDv5pdkhq1Op iat-mode=1",
            "obfs4 38.229.33.83:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955 cert=VwEFpk9F/UN9JED7XpG1XOjm/O8ZCXK80oPecgWnNDZDv5pdkhq1Op iat-mode=1",
            "Bridge obfs4 38.229.33.83:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955 cert=VwEFpk9F/UN9JED7XpG1XOjm/O8ZCXK80oPecgWnNDZDv5pdkhq1Op iat-mode=1",
        ], BridgeConfig {
            addrs: mk_pt_target(
                "obfs4",
                BridgeAddr::IpPort("38.229.33.83:80".parse().unwrap()),
                &[
                    ("cert", "VwEFpk9F/UN9JED7XpG1XOjm/O8ZCXK80oPecgWnNDZDv5pdkhq1Op" ),
                    ("iat-mode", "1"),
                ],
            ),
            rsa_id: mk_rsa("0BAC39417268B96B9F514E7F63FA6FBA1A788955"),
            ed_id: None,
        });

        #[cfg(feature = "pt-client")]
        chk(&[
            "obfs4 some-host:80 $0bac39417268b96b9f514e7f63fa6fba1a788955 ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE iat-mode=1",
            "obfs4 some-host:80 ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE 0BAC39417268B96B9F514E7F63FA6FBA1A788955 iat-mode=1",
        ], BridgeConfig {
            addrs: mk_pt_target(
                "obfs4",
                BridgeAddr::HostPort("some-host".into(), 80),
                &[
                    ("iat-mode", "1"),
                ],
            ),
            rsa_id: mk_rsa("0BAC39417268B96B9F514E7F63FA6FBA1A788955"),
            ed_id: Some(mk_ed("dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE")),
        });

        chk(
            &[
                "38.229.33.83:80 $0bac39417268b96b9f514e7f63fa6fba1a788955",
                "Bridge 38.229.33.83:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955",
            ],
            BridgeConfig {
                addrs: mk_direct("38.229.33.83:80"),
                rsa_id: mk_rsa("0BAC39417268B96B9F514E7F63FA6FBA1A788955"),
                ed_id: None,
            },
        );

        chk(
            &[
                "[2001:db8::42]:123 $0bac39417268b96b9f514e7f63fa6fba1a788955",
                "[2001:0db8::42]:123 $0bac39417268b96b9f514e7f63fa6fba1a788955",
            ],
            BridgeConfig {
                addrs: mk_direct("[2001:0db8::42]:123"),
                rsa_id: mk_rsa("0BAC39417268B96B9F514E7F63FA6FBA1A788955"),
                ed_id: None,
            },
        );

        chk(&[
            "38.229.33.83:80 $0bac39417268b96b9f514e7f63fa6fba1a788955 ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE",
            "38.229.33.83:80 ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE 0BAC39417268B96B9F514E7F63FA6FBA1A788955",
        ], BridgeConfig {
            addrs: mk_direct("38.229.33.83:80"),
            rsa_id: mk_rsa("0BAC39417268B96B9F514E7F63FA6FBA1A788955"),
            ed_id: Some(mk_ed("dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE")),
        });

        chk_e(
            &[
                "38.229.33.83:80 ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE",
                "Bridge 38.229.33.83:80 ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE",
            ],
            "lacks specification of RSA identity key",
        );

        chk_e(&["", "bridge"], "Bridge line was empty");

        chk_e(
            &["999.329.33.83:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955"],
            // Some Rust versions say "invalid socket address syntax",
            // some "invalid IP address syntax"
            r#"Cannot parse "999.329.33.83:80" as direct bridge IpAddress:ORPort"#,
        );

        chk_e(
            &[
                "38.229.33.83:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955 key=value",
                "Bridge 38.229.33.83:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955 key=value",
            ],
            "Parameters supplied but not valid without a pluggable transport",
        );

        chk_e(
            &[
                "bridge bridge some-host:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955",
                "yikes! some-host:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955",
            ],
            #[cfg(feature = "pt-client")]
            r" is not a valid pluggable transport ID), nor as direct bridge IpAddress:ORPort",
            #[cfg(not(feature = "pt-client"))]
            "is not an IpAddress:ORPort), but support disabled in cargo features",
        );

        #[cfg(feature = "pt-client")]
        chk_e(
            &["obfs4 garbage 0BAC39417268B96B9F514E7F63FA6FBA1A788955"],
            "as pluggable transport Host:ORPort",
        );

        #[cfg(feature = "pt-client")]
        chk_e(
            &["obfs4 some-host:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955 key=value garbage"],
            r#"Expected PT key=value parameter, found "garbage" (which lacks an equals sign"#,
        );

        #[cfg(feature = "pt-client")]
        chk_e(
            &["obfs4 some-host:80 garbage"],
            r#"Cannot parse "garbage" as identity key (Invalid base64 data), or PT key=value"#,
        );

        chk_e(
            &[
                "38.229.33.83:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955 23AC39417268B96B9F514E7F63FA6FBA1A788955",
                "38.229.33.83:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955 dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE xGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE",
            ],
            "More than one identity of the same type specified",
        );
    }

    #[test]
    fn config_api() {
        let chk_bridgeline = |line: &str, jsons: &[&str], f: &dyn Fn(&mut BridgeConfigBuilder)| {
            eprintln!(" ---- chk_bridgeline ----\n{}", line);

            let mut bcb = BridgeConfigBuilder::default();
            f(&mut bcb);
            let built = bcb.build().unwrap();
            assert_eq!(&built, &line.parse::<BridgeConfig>().unwrap());

            let parsed_b: BridgeConfigBuilder = line.parse().unwrap();
            assert_eq!(&built, &parsed_b.build().unwrap());

            let re_serialized = serde_json::to_value(&bcb).unwrap();
            assert_eq!(re_serialized, serde_json::Value::String(line.to_string()));

            for json in jsons {
                let from_dict: BridgeConfigBuilder = serde_json::from_str(json).unwrap();
                assert_eq!(&from_dict, &bcb);
                assert_eq!(&built, &from_dict.build().unwrap());
            }
        };

        chk_bridgeline(
            "38.229.33.83:80 $0bac39417268b96b9f514e7f63fa6fba1a788955 ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE",
            &[r#"{
                "addrs": ["38.229.33.83:80"],
                "ids": ["ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE",
                      "$0bac39417268b96b9f514e7f63fa6fba1a788955"]
            }"#],
            &|bcb| {
                bcb.addrs().push("38.229.33.83:80".parse().unwrap());
                bcb.ids().push("ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE".parse().unwrap());
                bcb.ids().push("$0bac39417268b96b9f514e7f63fa6fba1a788955".parse().unwrap());
            }
        );

        #[cfg(feature = "pt-client")]
        chk_bridgeline(
            "obfs4 some-host:80 $0bac39417268b96b9f514e7f63fa6fba1a788955 iat-mode=1",
            &[r#"{
                "transport": "obfs4",
                "addrs": ["some-host:80"],
                "ids": ["$0bac39417268b96b9f514e7f63fa6fba1a788955"],
                "settings": [["iat-mode", "1"]]
            }"#],
            &|bcb| {
                bcb.transport("obfs4");
                bcb.addrs().push("some-host:80".parse().unwrap());
                bcb.ids()
                    .push("$0bac39417268b96b9f514e7f63fa6fba1a788955".parse().unwrap());
                bcb.push_setting("iat-mode", "1");
            },
        );

        let chk_broken = |emsg: &str, jsons: &[&str], f: &dyn Fn(&mut BridgeConfigBuilder)| {
            eprintln!(" ---- chk_bridgeline ----\n{:?}", emsg);

            let mut bcb = BridgeConfigBuilder::default();
            f(&mut bcb);

            for json in jsons {
                let from_dict: BridgeConfigBuilder = serde_json::from_str(json).unwrap();
                assert_eq!(&from_dict, &bcb);
            }

            let err = bcb.build().expect_err("succeeded?!");
            let got_emsg = err.to_string();
            assert!(
                got_emsg.contains(emsg),
                "wrong error message: got_emsg={:?} err={:?}",
                &got_emsg,
                &err
            );

            // This is a kludge.  When we serialize `Option<Vec<_>>` as JSON,
            // we get a `Null` entry.  These `Null`s aren't in our test cases and we don't
            // really want them, although it's OK that they're there in the JSON.
            // The TOML serialization omits them completely, though.
            // So, we serialize the builder as TOML, and then convert the TOML to JSON Value.
            // That launders out the `Null`s and gives us the same Value as our original JSON.
            let toml_got = toml::to_string(&bcb).unwrap();
            let json_got: serde_json::Value = toml::from_str(&toml_got).unwrap();
            let json_exp: serde_json::Value = serde_json::from_str(jsons[0]).unwrap();
            assert_eq!(&json_got, &json_exp);
        };

        chk_broken(
            "Specified `settings` for a direct bridge connection",
            &[r#"{
                "settings": [["hi","there"]]
            }"#],
            &|bcb| {
                bcb.settings().push(("hi".into(), "there".into()));
            },
        );

        #[cfg(not(feature = "pt-client"))]
        chk_broken(
            "pluggable transport support disabled in tor-guardmgr cargo features",
            &[r#"{
                "transport": "obfs4"
            }"#],
            &|bcb| {
                bcb.transport("obfs4");
            },
        );

        #[cfg(feature = "pt-client")]
        chk_broken(
            "only numeric addresses are supported for a direct bridge connection",
            &[r#"{
                "transport": "bridge",
                "addrs": ["some-host:80"]
            }"#],
            &|bcb| {
                bcb.transport("bridge");
                bcb.addrs().push("some-host:80".parse().unwrap());
            },
        );

        chk_broken(
            "Missing `addrs` for a direct bridge connection",
            &[r#"{
                "transport": "-"
            }"#],
            &|bcb| {
                bcb.transport("-");
            },
        );

        #[cfg(feature = "pt-client")]
        chk_broken(
            "only supports a single nominal address",
            &[r#"{
                "transport": "obfs4",
                "addrs": ["some-host:80", "38.229.33.83:80"]
            }"#],
            &|bcb| {
                bcb.transport("obfs4");
                bcb.addrs().push("some-host:80".parse().unwrap());
                bcb.addrs().push("38.229.33.83:80".parse().unwrap());
            },
        );

        chk_broken(
            "multiple different ids of the same type (ed25519)",
            &[r#"{
                "addrs": ["38.229.33.83:80"],
                "ids": ["ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE",
                        "ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISA"]
            }"#],
            &|bcb| {
                bcb.addrs().push("38.229.33.83:80".parse().unwrap());
                bcb.ids().push(
                    "ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE"
                        .parse()
                        .unwrap(),
                );
                bcb.ids().push(
                    "ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISA"
                        .parse()
                        .unwrap(),
                );
            },
        );

        chk_broken(
            "need an RSA identity",
            &[r#"{
                "addrs": ["38.229.33.83:80"],
                "ids": ["ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE"]
            }"#],
            &|bcb| {
                bcb.addrs().push("38.229.33.83:80".parse().unwrap());
                bcb.ids().push(
                    "ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE"
                        .parse()
                        .unwrap(),
                );
            },
        );
    }
}
