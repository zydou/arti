//! Analyze a list of link specifiers as a `OwnedChanTarget`.
//!
//! This functionality is used in the onion service subsystem, and for relays.
//! The onion service subsystem uses this to decode a description of a relay as
//! provided in a HsDesc or an INTRODUCE2 message; relays use this to handle
//! EXTEND2 messages and figure out where to send a circuit.

use std::net::SocketAddr;

use crate::{EncodedLinkSpec, LinkSpec, OwnedChanTargetBuilder, RelayIdType};
use itertools::Itertools as _;

/// A rule for how strictly to parse a list of LinkSpecifiers when converting it into
/// an [`OwnedChanTarget`](crate::OwnedChanTarget).
//
// For now, there is only one level of strictness, but it is all but certain
// that we will add more in the future.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Strictness {
    /// Enforce the standard rules described in `tor-spec`:
    ///
    /// Namely:
    ///   * There must be exactly one Ed25519 identity.
    ///   * There must be exactly one RSA identity.
    ///   * There must be at least one IPv4 ORPort.
    Standard,
}

impl OwnedChanTargetBuilder {
    /// Construct an [`OwnedChanTargetBuilder`] from a list of [`LinkSpec`],
    /// validating it according to a given level of [`Strictness`].
    pub fn from_linkspecs(
        strictness: Strictness,
        linkspecs: &[LinkSpec],
    ) -> Result<Self, ChanTargetDecodeError> {
        // We ignore the strictness for now, since there is only one variant.
        let _ = strictness;

        // There must be exactly one Ed25519 identity.
        let ed_id = linkspecs
            .iter()
            .filter_map(|ls| match ls {
                LinkSpec::Ed25519Id(ed) => Some(ed),
                _ => None,
            })
            .exactly_one()
            .map_err(|mut e| match e.next() {
                Some(_) => ChanTargetDecodeError::DuplicatedId(RelayIdType::Ed25519),
                None => ChanTargetDecodeError::MissingId(RelayIdType::Ed25519),
            })?;

        // There must be exactly one RSA identity.
        let rsa_id = linkspecs
            .iter()
            .filter_map(|ls| match ls {
                LinkSpec::RsaId(rsa) => Some(rsa),
                _ => None,
            })
            .exactly_one()
            .map_err(|mut e| match e.next() {
                Some(_) => ChanTargetDecodeError::DuplicatedId(RelayIdType::Rsa),
                None => ChanTargetDecodeError::MissingId(RelayIdType::Rsa),
            })?;

        let addrs: Vec<SocketAddr> = linkspecs
            .iter()
            .filter_map(|ls| match ls {
                LinkSpec::OrPort(addr, port) => Some(SocketAddr::new(*addr, *port)),
                _ => None,
            })
            .collect();
        // There must be at least one IPv4 ORPort.
        if !addrs.iter().any(|addr| addr.is_ipv4()) {
            return Err(ChanTargetDecodeError::MissingAddr);
        }
        let mut builder = OwnedChanTargetBuilder::default();

        builder
            .ed_identity(*ed_id)
            .rsa_identity(*rsa_id)
            .addrs(addrs);
        Ok(builder)
    }

    /// As `from_linkspecs`, but take a list of encoded linkspecs and fail if
    /// any are known to be ill-formed.
    pub fn from_encoded_linkspecs(
        strictness: Strictness,
        linkspecs: &[EncodedLinkSpec],
    ) -> Result<Self, ChanTargetDecodeError> {
        // Decode the link specifiers and use them to find out what we can about
        // this relay.
        let linkspecs_decoded = linkspecs
            .iter()
            .map(|ls| ls.parse())
            .collect::<Result<Vec<_>, _>>()
            .map_err(ChanTargetDecodeError::MisformedLinkSpec)?;
        Self::from_linkspecs(strictness, &linkspecs_decoded)
    }
}

/// An error that occurred while constructing a `ChanTarget` from a set of link
/// specifiers.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ChanTargetDecodeError {
    /// A required identity key was missing.
    #[error("Missing a required {0} identity key")]
    MissingId(RelayIdType),
    /// A required identity key was included more than once.
    #[error("Duplicated a {0} identity key")]
    DuplicatedId(RelayIdType),
    /// A required address type was missing.
    #[error("Missing a required address type")]
    MissingAddr,
    /// Couldn't parse a provided linkspec of recognized type.
    #[error("Mis-formatted link specifier")]
    MisformedLinkSpec(#[source] tor_bytes::Error),
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

    use crate::OwnedChanTarget;

    use super::*;
    #[test]
    fn decode_ok() {
        let ct = OwnedChanTarget::builder()
            .addrs(vec![
                "[::1]:99".parse().unwrap(),
                "127.0.0.1:11".parse().unwrap(),
            ])
            .ed_identity([42; 32].into())
            .rsa_identity([45; 20].into())
            .build()
            .unwrap();

        let ls = vec![
            LinkSpec::OrPort("::1".parse().unwrap(), 99),
            LinkSpec::OrPort("127.0.0.1".parse().unwrap(), 11),
            LinkSpec::Ed25519Id([42; 32].into()),
            LinkSpec::RsaId([45; 20].into()),
        ];
        let ct2 = OwnedChanTargetBuilder::from_linkspecs(Strictness::Standard, &ls)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(format!("{:?}", &ct), format!("{:?}", ct2));
    }

    #[test]
    fn decode_errs() {
        use ChanTargetDecodeError as E;
        use RelayIdType as ID;

        let ipv4 = LinkSpec::OrPort("127.0.0.1".parse().unwrap(), 11);
        let ipv6 = LinkSpec::OrPort("::1".parse().unwrap(), 99);
        let ed = LinkSpec::Ed25519Id([42; 32].into());
        let rsa = LinkSpec::RsaId([45; 20].into());
        let err_from = |lst: &[&LinkSpec]| {
            OwnedChanTargetBuilder::from_linkspecs(
                Strictness::Standard,
                &lst.iter().map(|ls| (*ls).clone()).collect::<Vec<_>>()[..],
            )
            .err()
        };

        assert!(err_from(&[&ipv4, &ipv6, &ed, &rsa]).is_none());
        assert!(err_from(&[&ipv4, &ed, &rsa]).is_none());
        assert!(matches!(
            err_from(&[&ipv4, &ed, &ed, &rsa]),
            Some(E::DuplicatedId(ID::Ed25519))
        ));
        assert!(matches!(
            err_from(&[&ipv4, &ed, &rsa, &rsa]),
            Some(E::DuplicatedId(ID::Rsa))
        ));
        assert!(matches!(
            err_from(&[&ipv4, &rsa]),
            Some(E::MissingId(ID::Ed25519))
        ));
        assert!(matches!(
            err_from(&[&ipv4, &ed]),
            Some(E::MissingId(ID::Rsa))
        ));
        assert!(matches!(
            err_from(&[&ipv6, &ed, &rsa]),
            Some(E::MissingAddr)
        ));
    }
}
