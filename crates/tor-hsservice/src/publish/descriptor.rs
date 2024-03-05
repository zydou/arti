//! Helpers for building and representing hidden service descriptors.

use super::*;
use tor_cell::chancell::msg::HandshakeType;

/// Build the descriptor.
///
/// The `now` argument is used for computing the expiry of the `intro_{auth, enc}_key_cert`
/// certificates included in the descriptor. The expiry will be set to 54 hours from `now`.
///
/// Note: `blind_id_kp` is the blinded hidden service signing keypair used to sign descriptor
/// signing keys (KP_hs_blind_id, KS_hs_blind_id).
pub(super) fn build_sign<Rng: RngCore + CryptoRng>(
    keymgr: &Arc<KeyMgr>,
    config: &Arc<OnionServiceConfig>,
    ipt_set: &IptSet,
    period: TimePeriod,
    revision_counter: RevisionCounter,
    rng: &mut Rng,
    now: SystemTime,
) -> Result<VersionedDescriptor, FatalError> {
    // TODO: should this be configurable? If so, we should read it from the svc config.
    //
    /// The CREATE handshake type we support.
    const CREATE2_FORMATS: &[HandshakeType] = &[HandshakeType::NTOR];

    /// Lifetime of the intro_{auth, enc}_key_cert certificates in the descriptor.
    ///
    /// From C-Tor src/feature/hs/hs_descriptor.h:
    ///
    /// "This defines the lifetime of the descriptor signing key and the cross certification cert of
    /// that key. It is set to 54 hours because a descriptor can be around for 48 hours and because
    /// consensuses are used after the hour, add an extra 6 hours to give some time for the service
    /// to stop using it."
    const HS_DESC_CERT_LIFETIME_SEC: Duration = Duration::from_secs(54 * 60 * 60);

    let intro_points = ipt_set
        .ipts
        .iter()
        .map(|ipt_in_set| ipt_in_set.ipt.clone())
        .collect::<Vec<_>>();

    let nickname = &config.nickname;

    let svc_key_spec = HsIdKeypairSpecifier::new(nickname.clone());
    let hsid_kp = keymgr
        .get::<HsIdKeypair>(&svc_key_spec)?
        .ok_or_else(|| FatalError::MissingHsIdKeypair(nickname.clone()))?;
    let hsid = HsIdKey::from(&hsid_kp);

    let blind_id_key_spec = BlindIdKeypairSpecifier::new(nickname.clone(), period);

    // TODO: make the keystore selector configurable
    let keystore_selector = Default::default();
    let blind_id_kp = read_blind_id_keypair(keymgr, nickname, period)?
        .ok_or_else(|| internal!("hidden service offline mode not supported"))?;

    let blind_id_key = HsBlindIdKey::from(&blind_id_kp);
    let subcredential = hsid.compute_subcredential(&blind_id_key, period);

    let hs_desc_sign_key_spec = DescSigningKeypairSpecifier::new(nickname.clone(), period);
    let hs_desc_sign = keymgr.get_or_generate::<HsDescSigningKeypair>(
        &hs_desc_sign_key_spec,
        keystore_selector,
        rng,
    )?;

    // TODO #1028: support introduction-layer authentication.
    let auth_required = None;

    let is_single_onion_service =
        matches!(config.anonymity, crate::Anonymity::DangerouslyNonAnonymous);

    // TODO (#955): perhaps the certificates should be read from the keystore, rather than created
    // when building the descriptor. See #1048
    let intro_auth_key_cert_expiry = now + HS_DESC_CERT_LIFETIME_SEC;
    let intro_enc_key_cert_expiry = now + HS_DESC_CERT_LIFETIME_SEC;
    let hs_desc_sign_cert_expiry = now + HS_DESC_CERT_LIFETIME_SEC;

    // TODO (#1206): Temporarily disabled while we figure out how we want the client auth config to
    // work; see #1028
    /*
    let auth_clients: Option<Vec<curve25519::PublicKey>> = config.encrypt_descriptor
        .map(|auth_clients| build_auth_clients(&auth_clients));
    */

    let auth_clients: Option<Vec<curve25519::PublicKey>> = None;

    let desc_signing_key_cert = create_desc_sign_key_cert(
        &hs_desc_sign.as_ref().verifying_key(),
        &blind_id_kp,
        hs_desc_sign_cert_expiry,
    )
    .map_err(into_bad_api_usage!(
        "failed to sign the descriptor signing key"
    ))?;

    let desc = HsDescBuilder::default()
        .blinded_id(&(&blind_id_kp).into())
        .hs_desc_sign(hs_desc_sign.as_ref())
        .hs_desc_sign_cert(desc_signing_key_cert)
        .create2_formats(CREATE2_FORMATS)
        .auth_required(auth_required)
        .is_single_onion_service(is_single_onion_service)
        .intro_points(&intro_points[..])
        .intro_auth_key_cert_expiry(intro_auth_key_cert_expiry)
        .intro_enc_key_cert_expiry(intro_enc_key_cert_expiry)
        .lifetime(((ipt_set.lifetime.as_secs() / 60) as u16).into())
        .revision_counter(revision_counter)
        .subcredential(subcredential)
        .auth_clients(auth_clients.as_deref())
        .build_sign(rng)
        .map_err(|e| into_internal!("failed to build descriptor")(e))?;

    Ok(VersionedDescriptor {
        desc,
        revision_counter,
    })
}

/// Decode an encoded curve25519 key.
fn decode_curve25519_str(key: &str) -> Result<curve25519::PublicKey, AuthorizedClientConfigError> {
    use base64ct::{Base64, Encoding};
    let Some(enc_key) = key.strip_prefix("curve25519:") else {
        return Err(AuthorizedClientConfigError::MalformedKey);
    };
    let key = Base64::decode_vec(enc_key.trim_end())
        .map_err(AuthorizedClientConfigError::Base64Decode)?;
    let bytes: [u8; 32] = key
        .try_into()
        .map_err(|_| AuthorizedClientConfigError::MalformedKey)?;
    Ok(curve25519::PublicKey::from(bytes))
}

/// Return the keys in a directory or an error if the directory is malformed
fn read_key_dir(
    dir: &std::path::Path,
) -> Result<Vec<curve25519::PublicKey>, AuthorizedClientConfigError> {
    // TODO (#1206): We will eventually need to validate the key file names and
    // extensions.
    std::fs::read_dir(dir)
        .map_err(|e| AuthorizedClientConfigError::KeyDir {
            action: "traversing a directory",
            path: dir.into(),
            error: e.into(),
        })?
        .map(|entry| {
            let file = entry.map_err(|e| AuthorizedClientConfigError::KeyDir {
                action: "invalid key dir entry",
                path: dir.into(),
                error: e.into(),
            })?;

            let meta = file
                .metadata()
                .map_err(|e| AuthorizedClientConfigError::KeyDir {
                    action: "read metadata",
                    path: file.path(),
                    error: e.into(),
                })?;

            if !meta.is_file() {
                return Err(AuthorizedClientConfigError::MalformedFile { path: file.path() });
            }

            let buffer = std::fs::read_to_string(file.path()).map_err(|e| {
                AuthorizedClientConfigError::KeyDir {
                    action: "read",
                    path: file.path(),
                    error: e.into(),
                }
            })?;

            decode_curve25519_str(buffer.as_str())
        })
        .collect::<Result<Vec<_>, _>>()
}

/// Return the list of authorized public keys from the specified [`DescEncryptionConfig`].
fn build_auth_clients(
    auth_clients: &DescEncryptionConfig,
) -> Result<Vec<curve25519::PublicKey>, AuthorizedClientConfigError> {
    use crate::config::AuthorizedClientConfig::{Curve25519Key, DirectoryOfKeys};

    Ok(auth_clients
        .authorized_client
        .iter()
        .map(|client| match client {
            Curve25519Key(key) => Ok(vec![**key]),
            DirectoryOfKeys(dir) => read_key_dir(dir.as_ref()),
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>())
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

/// A descriptor and its revision.
#[derive(Clone)]
pub(super) struct VersionedDescriptor {
    /// The serialized descriptor.
    pub(super) desc: String,
    /// The revision counter.
    pub(super) revision_counter: RevisionCounter,
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
    use crate::config::AuthorizedClientConfig::Curve25519Key;
    use crate::publish::descriptor::{
        build_auth_clients, decode_curve25519_str, DescEncryptionConfig,
    };
    use tor_basic_utils::test_rng::testing_rng;
    use tor_llcrypto::pk::curve25519::{PublicKey, StaticSecret};

    #[test]
    fn build_auth_clients_curve25519() {
        let a: PublicKey = (&StaticSecret::random_from_rng(testing_rng())).into();
        let b: PublicKey = (&StaticSecret::random_from_rng(testing_rng())).into();

        let a_ck = Curve25519Key(a.into());
        let b_ck = Curve25519Key(b.into());

        let desc_enc_cfg = DescEncryptionConfig {
            authorized_client: vec![a_ck, b_ck],
        };

        let auth_clients = build_auth_clients(&desc_enc_cfg);
        let auth_clients_ref = vec![a, b];

        assert_eq!(auth_clients.unwrap(), auth_clients_ref);
    }

    #[test]
    fn build_auth_clients_keydir() {
        use crate::config::AuthorizedClientConfig::DirectoryOfKeys;
        use std::path::PathBuf;

        fn create_file(path: PathBuf, buf: &str) {
            use std::io::Write;
            let mut file = std::fs::File::create(path).unwrap();
            file.write_all(buf.as_bytes()).unwrap();
        }

        let a_base64: &str = "curve25519:NRzb4zeU4t5t2pSTW8E4DhRKmL9OiGRQrObslME08G8=";
        let a_dir = tempfile::tempdir().unwrap();
        create_file(a_dir.path().to_path_buf().join("client_a"), a_base64);

        let b_base64: &str = "curve25519:HpyxYe2ODbwZdjx2VAFDO86mrjygc5lnIMnwJUOB9ww=";
        let b_dir = tempfile::tempdir().unwrap();
        create_file(b_dir.path().to_path_buf().join("client_b"), b_base64);

        let desc_enc_cfg = DescEncryptionConfig {
            authorized_client: vec![
                DirectoryOfKeys(a_dir.path().to_str().unwrap().to_owned()),
                DirectoryOfKeys(b_dir.path().to_str().unwrap().to_owned()),
            ],
        };

        let auth_clients = build_auth_clients(&desc_enc_cfg).unwrap();

        let a = decode_curve25519_str(a_base64.to_string().as_str());
        let b = decode_curve25519_str(b_base64.to_string().as_str());
        let auth_clients_ref = vec![a.unwrap(), b.unwrap()];

        assert_eq!(auth_clients, auth_clients_ref);
    }
}
