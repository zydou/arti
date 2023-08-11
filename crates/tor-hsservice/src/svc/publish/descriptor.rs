//! Helpers for building and representing hidden service descriptors.

use std::time::SystemTime;

use derive_builder::Builder;
use rand_core::{CryptoRng, RngCore};

use tor_cert::Ed25519Cert;
use tor_error::{internal, Bug};
use tor_hscrypto::pk::{HsBlindIdKey, HsBlindIdKeypair, HsIdKey};
use tor_hscrypto::time::TimePeriod;
use tor_hscrypto::RevisionCounter;
use tor_llcrypto::pk::curve25519;
use tor_netdoc::doc::hsdesc::{HsDescBuilder, IntroPointDesc};
use tor_netdoc::NetdocBuilder;

// TODO HSS: Dummy types that should be implemented elsewhere.

/// An introduction point.
/// TODO Add a real Ipt type
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Ipt {
    // TODO HSS: decide what this looks like
}

/// TODO: add a real x25519 cert type in tor-cert.
#[allow(unreachable_pub)]
#[derive(Clone)]
pub struct X25519Cert;

impl X25519Cert {
    #[allow(unreachable_pub)]
    /// The time when this certificate will expire.
    pub fn expiry(&self) -> SystemTime {
        // TODO
        SystemTime::now()
    }
}

// TODO HSS: should this be configurable? If so, we should read it from the svc config.
//
/// The default lifetime of a descriptor in minutes (3h).
pub(super) const DESC_DEFAULT_LIFETIME: u16 = 3 * 60;

/// A hidden service descriptor.
#[derive(Clone, Builder)]
#[builder(pattern = "mutable")]
pub(super) struct Descriptor {
    /// If true, this a "single onion service" and is not trying to keep its own location private.
    is_single_onion_service: bool,
    /// The list of clients authorized to access the hidden service. If empty, client
    /// authentication is disabled.
    ///
    /// If client authorization is disabled, the resulting middle document will contain a single
    /// `auth-client` line populated with random values.
    #[builder(default)]
    auth_clients: Vec<curve25519::PublicKey>,
    /// One or more introduction points used to contact the onion service.
    ipts: Vec<Ipt>,
    /// The expiration time of an introduction point authentication key certificate.
    intro_auth_key_cert: Ed25519Cert,
    /// The expiration time of an introduction point encryption key certificate.
    intro_enc_key_cert: X25519Cert,
    /// A revision counter to tell whether this descriptor is more or less recent
    /// than another one for the same blinded ID.
    revision_counter: RevisionCounter,
}

impl DescriptorBuilder {
    /// Check whether we have enough information to build this descriptor.
    pub(crate) fn validate(&self) -> Result<(), Bug> {
        todo!()
    }

    /// Build the descriptor.
    ///
    /// Note: `blind_id_kp` is the blinded hidden service signing keypair used to sign descriptor
    /// signing keys (KP_hs_blind_id, KS_hs_blind_id).
    #[allow(unreachable_code)] // TODO HSS: remove
    #[allow(clippy::diverging_sub_expression)] // TODO HSS: remove
    pub(crate) fn build_sign<Rng: RngCore + CryptoRng>(
        &self,
        hsid: HsIdKey,
        blind_id_kp: &HsBlindIdKeypair,
        period: TimePeriod,
        rng: &mut Rng,
    ) -> Result<String, Bug> {
        // TODO HSS: should this be configurable? If so, we should read it from the svc config.
        //
        /// The CREATE handshake type we support.
        const CREATE2_FORMATS: &[u32] = &[1, 2];

        if self.validate().is_err() {
            return Err(internal!("tried to build descriptor from incomplete data"));
        }

        let desc = self
            .build()
            .map_err(|_| internal!("failed to build descriptor"))?;

        let intro_points = desc
            .ipts
            .iter()
            .map(Self::build_intro_point_desc)
            .collect::<Vec<_>>();

        let blind_id_key = HsBlindIdKey::from(blind_id_kp);
        let subcredential = hsid.compute_subcredential(&blind_id_key, period);
        // The short-term descriptor signing key (KP_hs_desc_sign, KS_hs_desc_sign).
        // TODO HSS: these should be provided by the KeyMgr.
        let hs_desc_sign = todo!();
        let hs_desc_sign_cert: Ed25519Cert = todo!();
        // TODO HSS: support introduction-layer authentication.
        let auth_required = None;

        Ok(HsDescBuilder::default()
            .blinded_id(blind_id_kp)
            .hs_desc_sign(hs_desc_sign)
            .hs_desc_sign_cert_expiry(hs_desc_sign_cert.expiry())
            .create2_formats(CREATE2_FORMATS)
            .auth_required(auth_required)
            .is_single_onion_service(desc.is_single_onion_service)
            .intro_points(&intro_points[..])
            .intro_auth_key_cert_expiry(desc.intro_auth_key_cert.expiry())
            .intro_enc_key_cert_expiry(desc.intro_enc_key_cert.expiry())
            .lifetime(DESC_DEFAULT_LIFETIME.into())
            .revision_counter(desc.revision_counter) // TODO HSS
            .subcredential(subcredential)
            .auth_clients(&desc.auth_clients)
            .build_sign(rng)?)
    }

    /// Create an [`IntroPointDesc`] from the specified introduction point.
    fn build_intro_point_desc(_ipt: &Ipt) -> IntroPointDesc {
        todo!()
    }
}

/// The freshness status of a descriptor at a particular HsDir.
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub(super) enum DescriptorStatus {
    #[default]
    /// Dirty, needs to be (re)uploaded.
    Dirty,
    /// Clean, does not need to be reuploaded.
    Clean,
}
