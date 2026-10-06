//! Encoding descriptor code.

use anyhow::Context;
use std::net::SocketAddr;

use tor_key_forge::ToEncodableKey as _;
use tor_netdoc::doc::routerdesc::{
    RelayPlatform, RouterDesc, RouterDescConstructor, RouterDescIntroItemConstructor,
};
use tor_netdoc::types::Curve25519Public;
use web_time_compat::SystemTime;

use crate::config;
use crate::tasks::crypto::RouterDescKeyMaterial;

use super::cert;

/// Encode and sign a [`RouterDesc`] with the given relay config and key material.
///
/// Return a result of the encoded descriptor as a [`String`].
pub(super) fn encode_and_sign_router_desc(
    config: &config::RelayConfig,
    keys: RouterDescKeyMaterial,
    now: SystemTime,
) -> anyhow::Result<String> {
    // TODO(relay): Need to decide what we do for IPv6 only relays as in with an explicit
    // flag in the config or just parsing the available IPs is enough.
    let primary_addr = config.advertise.primary_ipv4();
    let identity_ed25519 = cert::build_identity_cert(keys.ed_signing_cert, keys.ed_identity, now)?;
    // TODO(relay): Need bandwidth, uptime, extrainfo, family, overload general and exit
    // policy.
    //
    // tor-netdoc "Constructor" pattern holds only the required fields and `construct()`
    // fills the rest with default values.
    let desc = RouterDesc {
        contact: config.contact.clone(),
        platform: Some(RelayPlatform::Other(format!(
            "Arti {}",
            env!("CARGO_PKG_VERSION")
        ))),
        fingerprint: Some(keys.rsa_identity_kp.to_rsa_identity().into()),
        tunnelled_dir_server: Some(Default::default()),
        proto: crate::supported_protocols(),
        // These are all other IPs except the primary one.
        or_address: config
            .advertise
            .all_addr()
            .into_iter()
            .filter(|addr| *addr != SocketAddr::V4(*primary_addr))
            .collect(),
        ..RouterDescConstructor {
            router: RouterDescIntroItemConstructor {
                nickname: config.nickname.clone(),
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
