//! Hidden service (onion service) client key management functionality

// TODO HS what layer should be responsible for finding and dispatching keys?
// I think it should be as high as possible, so keys should be passed into
// the hs connector for each connection.  Otherwise there would have to be an
// HsKeyProvider trait here, and error handling gets complicated.

use std::fmt::{self, Debug};
use std::hash::{Hash, Hasher};
use std::sync::Arc;

#[allow(deprecated)]
use tor_hscrypto::pk::HsClientIntroAuthKeypair;
use tor_hscrypto::pk::{HsClientDescEncKeypair, HsId};
use tor_keymgr::{derive_deftly_template_KeySpecifier, CTorPath};

use derive_deftly::Deftly;
use derive_more::Constructor;
use tor_keymgr::KeySpecifier;

/// Service discovery keys (if any) to use when connecting to a specific onion service.
///
/// Represents a possibly empty subset of the following keys:
///  * `KS_hsc_desc_enc`, [`HsClientDescEncKeypair`]
///  * `KS_hsc_intro_auth`, [`HsClientIntroAuthKeypair`]
///
/// `HsClientSecretKeys` is constructed with a `Builder`:
/// use `ClientSecretKeysBuilder::default()`,
/// optionally call setters, and then call `build()`.
///
/// For client connections to share circuits and streams,
/// call `build` only once.
/// Different calls to `build` yield `HsClientSecretKeys` values
/// which won't share HS circuits, streams, or authentication.
///
/// Conversely, `Clone`s of an `HsClientSecretKeys` *can* share circuits.
//
/// All [empty](HsClientSecretKeys::is_empty) `HsClientSecretKeys`
/// (for example, from [`:none()`](HsClientSecretKeys::none))
/// *can* share circuits.
//
// TODO HS some way to read these from files or something!
//
// TODO HS: some of our APIs take Option<HsClientSecretKeys>.
// But HsClientSecretKeys is can be empty, so we should remove the `Option`.
#[derive(Clone, Default)]
pub struct HsClientSecretKeys {
    /// The actual keys
    ///
    /// This is compared and hashed by the Arc pointer value.
    /// We don't want to implement key comparison by comparing secret key values.
    pub(crate) keys: Arc<ClientSecretKeyValues>,
}

impl Debug for HsClientSecretKeys {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // TODO derive this?
        let mut d = f.debug_tuple("HsClientSecretKeys");
        d.field(&Arc::as_ptr(&self.keys));
        self.keys
            .ks_hsc_desc_enc
            .as_ref()
            .map(|_| d.field(&"<desc_enc>"));
        self.keys
            .ks_hsc_intro_auth
            .as_ref()
            .map(|_| d.field(&"<intro_uath>"));
        d.finish()
    }
}

impl PartialEq for HsClientSecretKeys {
    fn eq(&self, other: &Self) -> bool {
        self.is_empty() && other.is_empty() || Arc::ptr_eq(&self.keys, &other.keys)
    }
}
impl Eq for HsClientSecretKeys {}
impl Hash for HsClientSecretKeys {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.keys).hash(state);
    }
}

impl HsClientSecretKeys {
    /// Create a new `HsClientSecretKeys`, for making connections to services
    /// that are not running in restricted discovery mode.
    ///
    /// Creates a `HsClientSecretKeys` which has no actual keys,
    /// so will not use a descriptor cookie when decrypting the second layer
    /// of descriptor encryption.
    pub fn none() -> Self {
        Self::default()
    }

    /// Tests whether this `HsClientSecretKeys` actually contains any keys
    pub fn is_empty(&self) -> bool {
        // TODO derive this.  For now, we deconstruct it to prove we check all the fields.
        let ClientSecretKeyValues {
            ks_hsc_desc_enc,
            ks_hsc_intro_auth,
        } = &*self.keys;
        ks_hsc_desc_enc.is_none() && ks_hsc_intro_auth.is_none()
    }
}

/// Client secret key values
///
/// Skip the whole builder pattern derivation, etc. - the types are just the same
type ClientSecretKeyValues = HsClientSecretKeysBuilder;

/// Builder for `HsClientSecretKeys`
#[derive(Default, Debug)]
pub struct HsClientSecretKeysBuilder {
    /// Possibly, a key that is used to decrypt a descriptor.
    pub(crate) ks_hsc_desc_enc: Option<HsClientDescEncKeypair>,

    /// Possibly, a key that is used to authenticate while introducing.
    #[allow(deprecated)]
    pub(crate) ks_hsc_intro_auth: Option<HsClientIntroAuthKeypair>,
}

// TODO derive these setters
//
// TODO HS is this what we want for an API?  We need *some* API.
// This is a bit like config but we probably don't want to
// feed secret key material through config-rs, etc.
impl HsClientSecretKeysBuilder {
    /// Provide a descriptor decryption key
    pub fn ks_hsc_desc_enc(&mut self, ks: HsClientDescEncKeypair) -> &mut Self {
        self.ks_hsc_desc_enc = Some(ks);
        self
    }
    /// Provide an introduction authentication key
    #[deprecated]
    #[allow(deprecated)]
    pub fn ks_hsc_intro_auth(&mut self, ks: HsClientIntroAuthKeypair) -> &mut Self {
        self.ks_hsc_intro_auth = Some(ks);
        self
    }

    /// Convert these
    pub fn build(self) -> Result<HsClientSecretKeys, tor_config::ConfigBuildError> {
        Ok(HsClientSecretKeys {
            keys: Arc::new(self),
        })
    }
}

#[derive(Deftly, PartialEq, Debug, Constructor)]
#[derive_deftly(KeySpecifier)]
#[deftly(prefix = "client")]
#[deftly(role = "KS_hsc_desc_enc")]
#[deftly(summary = "Descriptor decryption key")]
#[deftly(ctor_path = "client_desc_enc_keypair_key_specifier_ctor_path")]
/// A key for deriving keys for decrypting HS descriptors (KS_hsc_desc_enc).
pub struct HsClientDescEncKeypairSpecifier {
    /// The hidden service this authorization key is for.
    pub(crate) hs_id: HsId,
}
/// The `CTorPath` of HsClientDescEncKeypairSpecifier
fn client_desc_enc_keypair_key_specifier_ctor_path(
    spec: &HsClientDescEncKeypairSpecifier,
) -> CTorPath {
    CTorPath::ClientHsDescEncKey(spec.hs_id)
}
