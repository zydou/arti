//! Configuration logic and types for bridges.
#![allow(dead_code)] // TODO pt-client: remove.

use std::fmt::{self, Display};
use std::str::FromStr;

use thiserror::Error;

use tor_linkspec::ChannelMethod;
use tor_linkspec::{RelayId, RelayIdError, TransportIdError};
use tor_llcrypto::pk::{ed25519::Ed25519Identity, rsa::RsaIdentity};

#[cfg(feature = "pt-client")]
use tor_linkspec::{PtAddrError, PtTarget, PtTargetAddr};

/// A relay not listed on the main tor network, used for anticensorship.
///
/// This object represents a bridge as configured by the user or by software
/// running on the user's behalf.
#[derive(Debug, Clone, Eq, PartialEq)]
// TODO pt-client: Derive builder and associated config types.
pub struct Bridge {
    // TODO pt-client: I am not sold on this exact representation for Bridge; it
    // needs to be something like this, but not necessarily this exact set of
    // members.
    //
    /// Address and transport via which the bridge can be reached, and
    /// the parameters for those transports.
    addrs: ChannelMethod,

    /// The RSA identity of the bridge.
    rsa_id: RsaIdentity,

    /// The Ed25519 identity of the bridge.
    ed_id: Option<Ed25519Identity>,
}
// TODO pt-client: when implementing deserialization for this type, make sure
// that it can accommodate a large variety of possible configurations methods,
// and check that the toml looks okay.  For discussion see
// https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/704/diffs#note_2835271

// TODO pt-client Additionally, make sure that Bridge can be deserialized from a string,
// when that string is a "bridge" line.

// TODO pt-client We want a "list of bridges'" configuration type
//
// TODO pt-client we want a "should we use bridges at this moment"
// configuration object.
//
// (These last two might be part of the same configuration type.)

/// Error when parsing a bridge line from a string
#[derive(Error, Clone, Debug)]
#[non_exhaustive]
pub enum BridgeParseError {
    /// Bridge line was empty
    #[error("Bridge line was empty")]
    Empty,

    /// Cannot parse value as direct address
    #[error("Cannot parse value as PT name ({0}), or direct bridge Addr:ORPort")]
    InvalidPtOrAddr(#[from] TransportIdError),

    /// Cannot parse value as direct bridge address
    #[error("Invalid direct bridge Address:ORPort (NB hostnames are not allowed)")]
    InvalidIDirectHostAddr(#[from] std::net::AddrParseError),

    /// Cannot parse pluggable transport host address
    #[cfg(feature = "pt-client")]
    #[error("Invalid pluggable transport Host:ORPort")]
    InvalidIPtHostAddr(#[from] PtAddrError),

    /// Cannot parse value as identity key, or PT key=value
    #[error("Cannot parse value as identity key ({0}), or PT key=value")]
    InvalidIdentityOrParameter(RelayIdError),

    /// PT key=value parameter does not contain an equals sign
    #[cfg(feature = "pt-client")]
    #[error("Invalid PT key=value parameters (does not contain an equals sign)")]
    InvalidPtKeyValue,

    /// More than one identity of the same type specified
    #[error("More than one identity of the same type specified, at {0}")]
    MultipleIdentitiesOfSameType(String),

    /// Identity specified of unsupported type
    #[error("Identity specified but not of supported type, at {0}")]
    UnsupportedIdentityType(String),

    /// Parameters may only be specified with a pluggable transport
    #[error("Parameters supplied but not valid without a pluggable transport")]
    DirectParametersNotAllowed,

    /// Every bridge must have an RSA identity
    #[error("Bridge line lacks specification of RSA identity key")]
    NoRsaIdentity,

    /// Pluggable transport support disabled in cargo features
    // We deliberately make this one *not* configured out if PT support is enabled
    #[error("Pluggable transport support disabled in cargo features")]
    PluggableTransportsNotSupported,
}

impl FromStr for Bridge {
    type Err = BridgeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use BridgeParseError as BPE;

        let mut s = s.trim().split_ascii_whitespace().peekable();

        let bridge_word = s.peek().ok_or(BPE::Empty)?;
        if bridge_word.eq_ignore_ascii_case("bridge") {
            s.next();
        }

        #[cfg_attr(not(feature = "pt-client"), allow(unused_mut))]
        let mut method = {
            let word = s.next().ok_or(BPE::Empty)?;
            if word.contains(':') {
                let addr = word.parse()?;
                ChannelMethod::Direct(addr)
            } else {
                #[cfg(not(feature = "pt-client"))]
                return Err(BPE::PluggableTransportsNotSupported);

                #[cfg(feature = "pt-client")]
                {
                    let pt_name = word.parse()?;
                    let addr = s
                        .next()
                        .map(|s| s.parse())
                        .transpose()?
                        .unwrap_or(PtTargetAddr::None);
                    ChannelMethod::Pluggable(PtTarget::new(pt_name, addr))
                }
            }
        };

        let mut rsa_id = None;
        let mut ed_id = None;

        while let Some(word) = s.peek() {
            let check_several = |was_some| {
                if was_some {
                    Err(BPE::MultipleIdentitiesOfSameType(word.to_string()))
                } else {
                    Ok(())
                }
            };

            match word.parse() {
                Err(id_err) => {
                    if word.contains('=') {
                        break;
                    }
                    return Err(BPE::InvalidIdentityOrParameter(id_err));
                }
                Ok(RelayId::Ed25519(id)) => check_several(ed_id.replace(id).is_some())?,
                Ok(RelayId::Rsa(id)) => check_several(rsa_id.replace(id).is_some())?,
                Ok(_) => return Err(BPE::UnsupportedIdentityType(word.to_string()))?,
            }
            s.next();
        }

        #[cfg(not(feature = "pt-client"))]
        if s.next().is_some() {
            return Err(BPE::DirectParametersNotAllowed);
        }

        #[cfg(feature = "pt-client")]
        for word in s {
            let (k, v) = word.split_once('=').ok_or(BPE::InvalidPtKeyValue)?;

            match &mut method {
                ChannelMethod::Direct(_) => return Err(BPE::DirectParametersNotAllowed),
                ChannelMethod::Pluggable(t) => t.push_setting(k.into(), v.into()),
            }
        }

        let rsa_id = rsa_id.ok_or(BPE::NoRsaIdentity)?;
        Ok(Bridge {
            addrs: method,
            rsa_id,
            ed_id,
        })
    }
}

impl Display for Bridge {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let Bridge {
            addrs,
            rsa_id,
            ed_id,
        } = self;
        let settings = match addrs {
            ChannelMethod::Direct(a) => {
                write!(f, "{}", a)?;
                None
            }

            #[cfg(feature = "pt-client")]
            ChannelMethod::Pluggable(target) => {
                write!(f, "{} {}", target.transport(), target.addr())?;
                Some(target.settings())
            }
        };
        write!(f, " {}", rsa_id)?;
        if let Some(ed_id) = ed_id {
            write!(f, " ed25519:{}", ed_id)?;
        }

        #[cfg(not(feature = "pt-client"))]
        let _: Option<()> = settings;

        #[cfg(feature = "pt-client")]
        for (k, v) in settings.into_iter().flatten() {
            // TODO pt-client: this fails to properly unparse arbitrary values
            // The values ought not to be arbitrary, but the spec is not clear.
            // See the comment on PtTargetSettings.
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
    #![allow(clippy::unwrap_used)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    #[cfg(feature = "pt-client")]
    fn mk_pt_target(name: &str, addr: PtTargetAddr, params: &[(&str, &str)]) -> ChannelMethod {
        let mut target = PtTarget::new(name.parse().unwrap(), addr);
        for &(k, v) in params {
            target.push_setting(k.into(), v.into());
        }
        ChannelMethod::Pluggable(target)
    }

    fn mk_direct(s: &str) -> ChannelMethod {
        ChannelMethod::Direct(s.parse().unwrap())
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
        let chk = |sl: &[&str], exp: Bridge| {
            for s in sl {
                let got: Bridge = s.parse().expect(s);
                assert_eq!(got, exp, "{:?}", s);

                let display = got.to_string();
                assert_eq!(display, sl[0]);
            }
        };

        let chk_e = |sl: &[&str], exp: &str| {
            for s in sl {
                let got: Result<Bridge, _> = s.parse();
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
        ], Bridge {
            addrs: mk_pt_target(
                "obfs4",
                PtTargetAddr::IpPort("38.229.33.83:80".parse().unwrap()),
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
        ], Bridge {
            addrs: mk_pt_target(
                "obfs4",
                PtTargetAddr::HostPort("some-host".into(), 80),
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
            Bridge {
                addrs: mk_direct("38.229.33.83:80"),
                rsa_id: mk_rsa("0BAC39417268B96B9F514E7F63FA6FBA1A788955"),
                ed_id: None,
            },
        );

        chk(&[
            "38.229.33.83:80 $0bac39417268b96b9f514e7f63fa6fba1a788955 ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE",
            "38.229.33.83:80 ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE 0BAC39417268B96B9F514E7F63FA6FBA1A788955",
        ], Bridge {
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
            "Invalid direct bridge Address:ORPort",
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
            "Cannot parse value as PT name",
            #[cfg(not(feature = "pt-client"))]
            "Pluggable transport support disabled in cargo features",
        );

        #[cfg(feature = "pt-client")]
        chk_e(
            &["obfs4 garbage 0BAC39417268B96B9F514E7F63FA6FBA1A788955"],
            "Invalid pluggable transport Host:ORPort",
        );

        #[cfg(feature = "pt-client")]
        chk_e(
            &["obfs4 some-host:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955 key=value garbage"],
            "Invalid PT key=value parameters (does not contain an equals sign)",
        );

        #[cfg(feature = "pt-client")]
        chk_e(
            &["obfs4 some-host:80 garbage"],
            "Cannot parse value as identity key (Invalid base64 data), or PT key=value",
        );

        chk_e(
            &[
                "38.229.33.83:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955 23AC39417268B96B9F514E7F63FA6FBA1A788955",
                "38.229.33.83:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955 dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE xGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE",
            ],
            "More than one identity of the same type specified",
        );
    }
}
