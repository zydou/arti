//! Hidden service (onion service) client key management functionality

// TODO HS what layer should be responsible for finding and dispatching keys?
// I think it should be as high as possible, so keys should be passed into
// the hs connector for each connection.  Otherwise there would have to be an
// HsKeyProvider trait here, and error handling gets complicated.

use std::fmt::{self, Debug};
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use std::sync::Arc;

#[allow(deprecated)]
use tor_hscrypto::pk::HsClientIntroAuthKeypair;
use tor_hscrypto::pk::{HsClientDescEncKeypair, HsId};
use tor_keymgr::{
    derive_adhoc_template_KeySpecifier, ArtiPathSyntaxError,
    KeySpecifierComponentViaDisplayFromStr,
};

use derive_adhoc::Adhoc;
use derive_more::Constructor;
use tor_persist::slug::{Slug, BadSlug};

/// Keys (if any) to use when connecting to a specific onion service.
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
    /// Create a new `HsClientSecretKeys`, for making unauthenticated connections
    ///
    /// Creates a `HsClientSecretKeys` which has no actual keys,
    /// so will make connections to hidden services
    /// without any Tor-protocol-level client authentication.
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

/// An HS client identifier.
///
/// Distinguishes different "clients" or "users" of this Arti instance,
/// so that they can have different sets of HS client authentication keys.
///
/// An `HsClientSpecifier` must be a valid [`Slug`].
/// See [slug](tor_persist::slug) for the syntactic requirements.
///
// TODO: rename `HsClientSpecifier` to `HsClientNickname`
// TODO: we should forbid empty strings, like we do for `HsNickname`
// (should we have a single FooNickname struct instead of the two?)
#[derive(
    Clone,
    Debug,
    PartialEq,
    derive_more::Display,
    derive_more::Into,
    derive_more::AsRef,
)]
pub struct HsClientSpecifier(Slug);

impl FromStr for HsClientSpecifier {
    type Err = BadSlug;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Slug::try_from(s.to_string()).map(HsClientSpecifier)
    }
}

impl KeySpecifierComponentViaDisplayFromStr for HsClientSpecifier {}

impl HsClientSpecifier {
    /// Create a new [`HsClientSpecifier`].
    ///
    /// The `inner` string **must** be a valid [`ArtiPathComponent`].
    pub fn new(inner: String) -> Result<Self, ArtiPathSyntaxError> {
        Ok(Slug::new(inner).map(Self)?)
    }
}

#[derive(Adhoc, PartialEq, Debug, Constructor)]
#[derive_adhoc(KeySpecifier)]
#[adhoc(prefix = "client")]
#[adhoc(role = "KS_hsc_desc_enc")]
#[adhoc(summary = "Descriptor decryption key")]
/// A key for deriving keys for decrypting HS descriptors (KS_hsc_desc_enc).
pub struct HsClientDescEncKeypairSpecifier {
    /// The client associated with this key.
    pub(crate) client_id: HsClientSpecifier,
    /// The hidden service this authorization key is for.
    pub(crate) hs_id: HsId,
}
