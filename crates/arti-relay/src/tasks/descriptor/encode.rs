//! Encoding descriptor code.

use anyhow::Context;
use std::net::SocketAddr;

use tor_key_forge::ToEncodableKey as _;
use tor_netdoc::doc::routerdesc::{
    RelayPlatform, RouterDesc, RouterDescConstructor, RouterDescIntroItemConstructor,
};
use tor_netdoc::types::Curve25519Public;
use web_time_compat::SystemTime;

use crate::tasks::crypto::RouterDescKeyMaterial;

use super::{RouterDescInfo, cert};

/// Encode and sign a [`RouterDesc`] with the given descriptor info and key material.
///
/// Return a result of the encoded descriptor as a [`String`].
pub(super) fn encode_and_sign_router_desc(
    info: &RouterDescInfo,
    keys: RouterDescKeyMaterial,
    now: SystemTime,
) -> anyhow::Result<String> {
    // TODO(relay): Need to decide what we do for IPv6 only relays as in with an explicit
    // flag in the config or just parsing the available IPs is enough.
    let primary_addr = info.advertise.primary_ipv4();
    let identity_ed25519 = cert::build_identity_cert(keys.ed_signing_cert, keys.ed_identity, now)?;
    // TODO(relay): Need bandwidth, uptime, extrainfo, family, overload general and exit
    // policy.
    //
    // tor-netdoc "Constructor" pattern holds only the required fields and `construct()`
    // fills the rest with default values.
    let desc = RouterDesc {
        contact: info.contact.clone(),
        platform: Some(RelayPlatform::Other(format!(
            "Arti {}",
            env!("CARGO_PKG_VERSION")
        ))),
        fingerprint: Some(keys.rsa_identity_kp.to_rsa_identity().into()),
        tunnelled_dir_server: Some(Default::default()),
        proto: crate::supported_protocols(),
        // These are all other IPs except the primary one.
        or_address: info
            .advertise
            .all_addr()
            .into_iter()
            .filter(|addr| *addr != SocketAddr::V4(*primary_addr))
            .collect(),
        ..RouterDescConstructor {
            router: RouterDescIntroItemConstructor {
                nickname: info.nickname.clone(),
                address: *primary_addr.ip(),
                orport: primary_addr.port(),
            }
            .construct(),
            identity_ed25519,
            master_key_ed25519: keys.ed_identity.into(),
            published: now.into(),
            ntor_onion_key: Curve25519Public(*keys.ntor_key.inner()),
            ntor_onion_key_crosscert: keys.ntor_crosscert,
            signing_key: keys.rsa_identity_kp.keypair().to_public_key(),
        }
        .construct()
    };

    // Encode and sign. After this, it is ready to be uploaded.
    desc.encode_sign(
        keys.rsa_identity_kp.keypair(),
        &keys.relay_sign_kp.to_encodable_key(),
    )
    .context("Failed to encode and sign router descriptor")
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
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use crate::config;
    use std::time::Duration;
    use tor_key_forge::Keygen as _;
    use tor_netdoc::doc::routerdesc::{NtorOnionKeyCrossCertConstructor, RouterDescUnverified};
    use tor_netdoc::parse2::{ParseInput, parse_netdoc};
    use tor_netdoc::types::{Ed25519NtorCrossCert, NumericBoolean};
    use tor_relay_crypto::pk::{
        RelayIdentityKeypair, RelayIdentityRsaKeypair, RelayNtorKeypair, RelaySigningKeypair,
    };

    /// Build what we need to build a descriptor as in descriptor info and key material.
    ///
    /// Return all this along the now time used for the certificates.
    fn descriptor_fixture() -> (RouterDescInfo, RouterDescKeyMaterial, SystemTime) {
        let advertise = config::Advertise::new(
            ["192.0.2.1:9001", "192.0.2.1:9003", "192.0.2.2:9001"]
                .map(|addr| addr.parse().unwrap())
                .to_vec()
                .try_into()
                .unwrap(),
            ["[2001:42::1]:9002", "[2001:42::2]:9004"]
                .map(|addr| addr.parse().unwrap())
                .to_vec(),
        );
        let info = RouterDescInfo {
            nickname: "Compassion".parse().unwrap(),
            contact: Some("Abed Nadir<abed.nadir@foo.bar>".parse().unwrap()),
            advertise,
        };
        let rng = &mut tor_llcrypto::rng::CautiousRng;
        let now = SystemTime::UNIX_EPOCH;
        let expiry = now + Duration::from_secs(7 * 24 * 60 * 60);
        let ed_identity_kp = RelayIdentityKeypair::generate(rng).unwrap();
        let relay_sign_kp = RelaySigningKeypair::generate(rng).unwrap();
        let rsa_identity_kp = RelayIdentityRsaKeypair::generate(rng).unwrap();
        let ntor_keypair = RelayNtorKeypair::generate(rng).unwrap();
        let ed_identity = ed_identity_kp.to_ed25519_id();
        let ed_signing_cert =
            tor_relay_crypto::gen_signing_cert(&ed_identity_kp, &relay_sign_kp, expiry).unwrap();
        let (ntor_ed_kp, signbit) =
            tor_llcrypto::pk::keymanip::convert_curve25519_to_ed25519_private(
                ntor_keypair.secret(),
            )
            .unwrap();
        let keys = RouterDescKeyMaterial {
            ed_identity,
            ed_signing_cert,
            ntor_crosscert: NtorOnionKeyCrossCertConstructor {
                bit: NumericBoolean(signbit != 0),
                cert: Ed25519NtorCrossCert::new_signed(&ntor_ed_kp, ed_identity, expiry).unwrap(),
            }
            .construct(),
            ntor_key: ntor_keypair.public(),
            relay_sign_kp,
            rsa_identity_kp,
        };
        (info, keys, now)
    }

    #[test]
    fn signed_descriptor_roundtrip() {
        let (info, keys, now) = descriptor_fixture();
        let ed_identity = keys.ed_identity;
        let rsa_identity = keys.rsa_identity_kp.to_rsa_identity();
        let ntor_key = *keys.ntor_key.inner();
        let encoded = encode_and_sign_router_desc(&info, keys, now).unwrap();
        let verified = parse_netdoc::<RouterDescUnverified>(&ParseInput::new(&encoded, "encoded"))
            .unwrap()
            .verify()
            .unwrap();
        let desc = verified.dangerously_peek();
        assert_eq!(desc.ed_identity(), &ed_identity);
        assert_eq!(desc.rsa_identity(), rsa_identity);
        assert_eq!(desc.ntor_onion_key(), &ntor_key);
        assert_eq!(desc.published(), now);
        assert_eq!(desc.router.nickname, info.nickname);
        assert_eq!(desc.router.address, *info.advertise.primary_ipv4().ip());
        assert_eq!(desc.router.orport, 9001);
        assert_eq!(desc.router.socksport, 0);
        assert_eq!(desc.router.dirport, 0);
        assert_eq!(desc.contact, info.contact);
        assert!(desc.tunnelled_dir_server.is_some());
        // TODO(relay): For now we don't support it.
        assert!(desc.hidden_service_dir.is_none());
        assert_eq!(
            desc.or_address,
            vec![
                "192.0.2.1:9003".parse().unwrap(),
                "192.0.2.2:9001".parse().unwrap(),
                "[2001:42::1]:9002".parse().unwrap(),
                "[2001:42::2]:9004".parse().unwrap(),
            ]
        );
        assert_eq!(
            desc.ipv4_policy.allows(&"192.0.2.2".parse().unwrap(), 443),
            Some(tor_netdoc::types::policy::RuleKind::Reject),
        );
        assert!(!desc.ipv6_policy.allows_some_port());

        // Both signatures must cover the descriptor body.
        let tampered = encoded.replace("Compassion", "Flamboyance");
        assert!(
            parse_netdoc::<RouterDescUnverified>(&ParseInput::new(&tampered, "tampered"),)
                .unwrap()
                .verify()
                .is_err()
        );
    }

    /// Test that using an expired certificate is caught.
    #[test]
    fn expired_signing_cert() {
        let (info, keys, now) = descriptor_fixture();
        let after_expiry = now + Duration::from_secs(8 * 24 * 60 * 60);
        let err = encode_and_sign_router_desc(&info, keys, after_expiry).unwrap_err();
        assert!(matches!(
            err.downcast_ref::<tor_checkable::TimeValidityError>(),
            Some(tor_checkable::TimeValidityError::Expired(_))
        ));
    }

    #[test]
    fn mismatched_cert_identity() {
        let (info, mut keys, now) = descriptor_fixture();
        keys.ed_identity = RelayIdentityKeypair::generate(&mut tor_llcrypto::rng::CautiousRng)
            .unwrap()
            .to_ed25519_id();
        let err = encode_and_sign_router_desc(&info, keys, now).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Relay signing cert does not match relay identity"
        );
    }

    #[test]
    fn mismatched_cert_signing_key() {
        let (info, mut keys, now) = descriptor_fixture();
        keys.relay_sign_kp =
            RelaySigningKeypair::generate(&mut tor_llcrypto::rng::CautiousRng).unwrap();
        let err = encode_and_sign_router_desc(&info, keys, now).unwrap_err();
        assert!(format!("{err:#}").contains("Ed25519 signing key does not match"));
    }

    #[test]
    fn mismatched_cert_type() {
        let (info, mut keys, now) = descriptor_fixture();
        let identity_kp =
            RelayIdentityKeypair::generate(&mut tor_llcrypto::rng::CautiousRng).unwrap();
        keys.ed_identity = identity_kp.to_ed25519_id();
        keys.ed_signing_cert = tor_cert::Ed25519Cert::builder()
            .cert_type(tor_cert::CertType::SIGNING_V_LINK_AUTH)
            .expiration(now + Duration::from_secs(24 * 60 * 60))
            .signing_key(keys.ed_identity)
            .cert_key(tor_cert::CertifiedKey::Ed25519(
                keys.relay_sign_kp.to_ed25519_id(),
            ))
            .encode_and_sign(&identity_kp)
            .unwrap()
            .into();
        let err = encode_and_sign_router_desc(&info, keys, now).unwrap_err();
        assert_eq!(err.to_string(), "Failed to verify relay signing cert");
    }
}
