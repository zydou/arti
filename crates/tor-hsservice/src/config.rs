//! Configuration information for onion services.

use base64ct::{Base64Unpadded, Encoding as _};
use derive_adhoc::Adhoc;
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tor_cell::relaycell::hs::est_intro;
use tor_config::ConfigBuildError;
use tor_error::into_internal;
use tor_hscrypto::pk::HsClientDescEncKey;
use tor_llcrypto::pk::curve25519;

use crate::HsNickname;

/// Configuration for one onion service.
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError", validate = "Self::validate"))]
#[builder(derive(Serialize, Deserialize, Debug, Adhoc, Eq, PartialEq))]
#[builder_struct_attr(derive_adhoc(tor_config::Flattenable))]
pub struct OnionServiceConfig {
    /// The nickname used to look up this service's keys, state, configuration, etc.
    pub(crate) nickname: HsNickname,

    // TODO: Perhaps this belongs at a higher level.  Perhaps we don't need it
    // at all.
    //
    // enabled: bool,
    /// Whether we want this to be a non-anonymous "single onion service".
    /// We could skip this in v1.  We should make sure that our state
    /// is built to make it hard to accidentally set this.
    #[builder(default)]
    pub(crate) anonymity: crate::Anonymity,

    /// Number of intro points; defaults to 3; max 20.
    #[builder(default = "DEFAULT_NUM_INTRO_POINTS")]
    pub(crate) num_intro_points: u8,

    /// A rate-limit on the acceptable rate of introduction requests.
    ///
    /// We send this to the send to the introduction point to configure how many
    /// introduction requests it sends us.  
    /// If this is not set, the introduction point chooses a default based on
    /// the current consensus.
    ///
    /// We do not enforce this limit ourselves.
    ///
    /// This configuration is sent as a `DOS_PARAMS` extension, as documented in
    /// <https://spec.torproject.org/rend-spec/introduction-protocol.html#EST_INTRO_DOS_EXT>.
    #[builder(default)]
    rate_limit_at_intro: Option<TokenBucketConfig>,
    // TODO #1124 Implement max_concurrent_streams_per_circuit
    // /// How many streams will we allow to be open at once for a single circuit on
    // /// this service?
    // #[builder(default = "65535")]
    // max_concurrent_streams_per_circuit: u32,

    // TODO POW: The POW items are disabled for now, since they aren't implemented.
    // /// If true, we will require proof-of-work when we're under heavy load.
    // // enable_pow: bool,
    // /// Disable the compiled backend for proof-of-work.
    // // disable_pow_compilation: bool,

    // TODO POW: C tor has this, but I don't know if we want it.
    //
    // TODO POW: It's possible that we want this to relate, somehow, to our
    // rate_limit_at_intro settings.
    //
    // /// A rate-limit on dispatching requests from the request queue when
    // /// our proof-of-work defense is enabled.
    // pow_queue_rate: TokenBucketConfig,
    // ...

    // /// Configure descriptor-based client authorization.
    // ///
    // /// When this is enabled, we encrypt our list of introduction point and keys
    // /// so that only clients holding one of the listed keys can decrypt it.
    //
    // TODO (#1206): we'd like this to be an Option, but that doesn't work well with
    // sub_builder.  We need to figure out what to do there.
    //
    // TODO (#1206): Temporarily disabled while we figure out how we want it to work;
    // see also #1028
    //
    // pub(crate) encrypt_descriptor: Option<DescEncryptionConfig>,
}

/// Default number of introduction points.
const DEFAULT_NUM_INTRO_POINTS: u8 = 3;

impl OnionServiceConfig {
    /// Return a reference to this configuration's nickname.
    pub fn nickname(&self) -> &HsNickname {
        &self.nickname
    }

    /// Check whether an onion service running with this configuration can
    /// switch over `other` according to the rules of `how`.
    ///
    //  Return an error if it can't; otherwise return the new config that we
    //  should change to.
    pub(crate) fn for_transition_to(
        &self,
        mut other: OnionServiceConfig,
        how: tor_config::Reconfigure,
    ) -> Result<OnionServiceConfig, tor_config::ReconfigureError> {
        /// Arguments to a handler for a field
        ///
        /// The handler must:
        ///  * check whether this field can be updated
        ///  * if necessary, throw an error (in which case `*other` may be wrong)
        ///  * if it doesn't throw an error, ensure that `*other`
        ///    is appropriately updated.
        //
        // We could have a trait but that seems overkill.
        #[allow(clippy::missing_docs_in_private_items)] // avoid otiosity
        struct HandlerInput<'i, 'o, T> {
            how: tor_config::Reconfigure,
            self_: &'i T,
            other: &'o mut T,
            field_name: &'i str,
        }
        /// Convenience alias
        type HandlerResult = Result<(), tor_config::ReconfigureError>;

        /// Handler for config fields that cannot be changed
        #[allow(clippy::needless_pass_by_value)]
        fn unchangeable<T: Clone + PartialEq>(i: HandlerInput<T>) -> HandlerResult {
            if i.self_ != i.other {
                i.how.cannot_change(i.field_name)?;
                // If we reach here, then `how` is WarnOnFailures, so we keep the
                // original value.
                *i.other = i.self_.clone();
            }
            Ok(())
        }
        /// Handler for config fields that can be freely changed
        #[allow(clippy::unnecessary_wraps)]
        fn simply_update<T>(_: HandlerInput<T>) -> HandlerResult {
            Ok(())
        }

        /// Check all the fields.  Input maps fields to handlers.
        macro_rules! fields { {
            $(
                $field:ident: $handler:expr
            ),* $(,)?
        } => {
            // XXXX enable this
            // // prove that we have handled every field
            // let OnionServiceConfig { $( $field: _, )* } = self;

            $(
                $handler(HandlerInput {
                    how,
                    self_: &self.$field,
                    other: &mut other.$field,
                    field_name: stringify!($field),
                })?;
            )*
        } }

        fields! {
            nickname: unchangeable,

            // Note: C Tor absolutely forbids changing between different
            // values here.
            //
            // The rationale thinking here is that if you have ever published a
            // given service non-anonymously, it is de-anonymized forever, and
            // that if you ever de-anonymize a service, you are de-anonymizing
            // it retroactively.
            //
            // We may someday want to ease this behavior.
            anonymity: unchangeable,

            // IPT manager will respond by adding or removing IPTs as desired.
            // (Old IPTs are not proactively removed, but they will not be replaced
            // as they are rotated out.)
            num_intro_points: simply_update,

            // TODO Changing this would involve abolishing our IPTs and making new ones.
            // Currently that's not implemented.  It could be done by the Establisher
            // reporting WantsToRetire, or by the Manager recording the last setting
            // and abolishing the IPTs.
            rate_limit_at_intro: unchangeable,
        }

        Ok(other)
    }

    /// Return the DosParams extension we should send for this configuration, if any.
    pub(crate) fn dos_extension(&self) -> Result<Option<est_intro::DosParams>, crate::FatalError> {
        Ok(self
            .rate_limit_at_intro
            .as_ref()
            .map(dos_params_from_token_bucket_config)
            .transpose()
            .map_err(into_internal!(
                "somehow built an un-validated rate-limit-at-intro"
            ))?)
    }
}

impl OnionServiceConfigBuilder {
    /// Builder helper: check whether the options in this builder are consistent.
    fn validate(&self) -> Result<(), ConfigBuildError> {
        /// Largest number of introduction points supported.
        ///
        /// (This is not a very principled value; it's just copied from the C
        /// implementation.)
        const MAX_NUM_INTRO_POINTS: u8 = 20;
        /// Supported range of numbers of intro points.
        const ALLOWED_NUM_INTRO_POINTS: std::ops::RangeInclusive<u8> =
            DEFAULT_NUM_INTRO_POINTS..=MAX_NUM_INTRO_POINTS;

        // Make sure MAX_INTRO_POINTS is in range.
        if let Some(ipts) = self.num_intro_points {
            if !ALLOWED_NUM_INTRO_POINTS.contains(&ipts) {
                return Err(ConfigBuildError::Invalid {
                    field: "num_intro_points".into(),
                    problem: format!(
                        "out of range {}-{}",
                        DEFAULT_NUM_INTRO_POINTS, MAX_NUM_INTRO_POINTS
                    ),
                });
            }
        }

        // Make sure that our rate_limit_at_intro is valid.
        if let Some(Some(ref rate_limit)) = self.rate_limit_at_intro {
            let _ignore_extension: est_intro::DosParams =
                dos_params_from_token_bucket_config(rate_limit)?;
        }

        Ok(())
    }

    /// Return the configured nickname for this service, if it has one.
    pub fn peek_nickname(&self) -> Option<&HsNickname> {
        self.nickname.as_ref()
    }
}

/// Configure a token-bucket style limit on some process.
//
// TODO: Someday we may wish to lower this; it will be used in far more places.
//
// TODO: Do we want to parameterize this, or make it always u32?  Do we want to
// specify "per second"?
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct TokenBucketConfig {
    /// The maximum number of items to process per second.
    rate: u32,
    /// The maximum number of items to process in a single burst.
    burst: u32,
}

impl TokenBucketConfig {
    /// Create a new token-bucket configuration to rate-limit some action.
    ///
    /// The "bucket" will have a maximum capacity of `burst`, and will fill at a
    /// rate of `rate` per second.  New actions are permitted if the bucket is nonempty;
    /// each action removes one token from the bucket.
    pub fn new(rate: u32, burst: u32) -> Self {
        Self { rate, burst }
    }
}

/// Helper: Try to create a DosParams from a given token bucket configuration.
/// Give an error if the value is out of range.
///
/// This is a separate function so we can use the same logic when validating
/// and when making the extension object.
fn dos_params_from_token_bucket_config(
    c: &TokenBucketConfig,
) -> Result<est_intro::DosParams, ConfigBuildError> {
    let err = || ConfigBuildError::Invalid {
        field: "rate_limit_at_intro".into(),
        problem: "out of range".into(),
    };
    let cast = |n| i32::try_from(n).map_err(|_| err());
    est_intro::DosParams::new(Some(cast(c.rate)?), Some(cast(c.burst)?)).map_err(|_| err())
}

/// Configuration for descriptor encryption.
#[derive(Debug, Clone, Builder, PartialEq)]
#[builder(derive(Serialize, Deserialize))]
#[non_exhaustive]
pub struct DescEncryptionConfig {
    /// A list of our authorized clients.
    ///
    /// Note that if this list is empty, no clients can connect.  
    //
    // TODO (#1206): It might be good to replace this with a trait or something, so that
    // we can let callers give us a ClientKeyProvider or some plug-in that reads
    // keys from somewhere else. On the other hand, we might have this configure
    // our default ClientKeyProvider, and only allow programmatic ClientKeyProviders
    pub authorized_client: Vec<AuthorizedClientConfig>,
}

/// A single client (or a collection of clients) authorized using the descriptor encryption mechanism.
#[derive(Debug, Clone, PartialEq, serde_with::DeserializeFromStr, serde_with::SerializeDisplay)]
#[non_exhaustive]
pub enum AuthorizedClientConfig {
    /// A directory full of authorized public keys.
    DirectoryOfKeys(PathBuf),
    /// A single authorized public key.
    Curve25519Key(HsClientDescEncKey),
}

impl std::fmt::Display for AuthorizedClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DirectoryOfKeys(pb) => write!(f, "dir:{}", pb.display()),
            Self::Curve25519Key(key) => write!(
                f,
                "curve25519:{}",
                Base64Unpadded::encode_string(key.as_bytes())
            ),
        }
    }
}

/// A problem encountered while parsing an AuthorizedClientConfig.
#[derive(thiserror::Error, Clone, Debug)]
#[non_exhaustive]
pub enum AuthorizedClientParseError {
    /// Didn't recognize the type of this [`AuthorizedClientConfig`].
    ///
    /// Recognized types are `dir` and `curve25519`.
    #[error("Unrecognized authorized client type")]
    InvalidType,
    /// Couldn't parse a curve25519 key.
    #[error("Invalid curve25519 key")]
    InvalidKey,
}

impl std::str::FromStr for AuthorizedClientConfig {
    type Err = AuthorizedClientParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((tp, val)) = s.split_once(':') else {
            return Err(Self::Err::InvalidType);
        };
        if tp == "dir" {
            Ok(Self::DirectoryOfKeys(val.into()))
        } else if tp == "curve25519" {
            let bytes: [u8; 32] = Base64Unpadded::decode_vec(val)
                .map_err(|_| Self::Err::InvalidKey)?
                .try_into()
                .map_err(|_| Self::Err::InvalidKey)?;

            Ok(Self::Curve25519Key(HsClientDescEncKey::from(
                curve25519::PublicKey::from(bytes),
            )))
        } else {
            Err(Self::Err::InvalidType)
        }
    }
}
