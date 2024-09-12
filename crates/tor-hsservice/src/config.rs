//! Configuration information for onion services.

use crate::internal_prelude::*;

use amplify::Getters;
use derive_deftly::derive_deftly_adhoc;
use tor_cell::relaycell::hs::est_intro;

use crate::config::restricted_discovery::{
    RestrictedDiscoveryConfig, RestrictedDiscoveryConfigBuilder,
};

#[cfg(feature = "restricted-discovery")]
pub mod restricted_discovery;

// Only exported with pub visibility if the restricted-discovery feature is enabled.
#[cfg(not(feature = "restricted-discovery"))]
// Use cfg(all()) to prevent this from being documented as
// "Available on non-crate feature `restricted-discovery` only"
#[cfg_attr(docsrs, doc(cfg(all())))]
pub(crate) mod restricted_discovery;

/// Configuration for one onion service.
#[derive(Debug, Clone, Builder, Eq, PartialEq, Deftly, Getters)]
#[builder(build_fn(error = "ConfigBuildError", validate = "Self::validate"))]
#[builder(derive(Serialize, Deserialize, Debug, Deftly))]
#[builder_struct_attr(derive_deftly(tor_config::Flattenable))]
#[derive_deftly_adhoc]
pub struct OnionServiceConfig {
    /// The nickname used to look up this service's keys, state, configuration, etc.
    #[deftly(publisher_view)]
    pub(crate) nickname: HsNickname,

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

    /// How many streams will we allow to be open at once for a single circuit on
    /// this service?
    #[builder(default = "65535")]
    max_concurrent_streams_per_circuit: u32,

    /// Configure restricted discovery mode.
    ///
    /// When this is enabled, we encrypt our list of introduction point and keys
    /// so that only clients holding one of the listed keys can decrypt it.
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    #[deftly(publisher_view)]
    #[getter(as_mut)]
    pub(crate) restricted_discovery: RestrictedDiscoveryConfig,

    // TODO(#727): add support for single onion services
    //
    // TODO: Perhaps this belongs at a higher level.  Perhaps we don't need it
    // at all.
    //
    // enabled: bool,
    // /// Whether we want this to be a non-anonymous "single onion service".
    // /// We could skip this in v1.  We should make sure that our state
    // /// is built to make it hard to accidentally set this.
    // #[builder(default)]
    // #[deftly(publisher_view)]
    // pub(crate) anonymity: crate::Anonymity,


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
}

derive_deftly_adhoc! {
    OnionServiceConfig expect items:

    ${defcond PUBLISHER_VIEW fmeta(publisher_view)}

    #[doc = concat!("Descriptor publisher's view of [`", stringify!($tname), "`]")]
    #[derive(PartialEq, Clone, Debug)]
    pub(crate) struct $<$tname PublisherView><$tdefgens>
    where $twheres
    ${vdefbody $vname $(
        ${when PUBLISHER_VIEW}
        ${fattrs doc}
        $fvis $fname: $ftype,
    ) }

    impl<$tgens> From<$tname> for $<$tname PublisherView><$tdefgens>
    where $twheres
    {
        fn from(config: $tname) -> $<$tname PublisherView><$tdefgens> {
            Self {
                $(
                    ${when PUBLISHER_VIEW}
                    $fname: config.$fname,
                )
            }
        }
    }

    impl<$tgens> From<&$tname> for $<$tname PublisherView><$tdefgens>
    where $twheres
    {
        fn from(config: &$tname) -> $<$tname PublisherView><$tdefgens> {
            Self {
                $(
                    ${when PUBLISHER_VIEW}
                    #[allow(clippy::clone_on_copy)] // some fields are Copy
                    $fname: config.$fname.clone(),
                )
            }
        }
    }
}

/// Default number of introduction points.
const DEFAULT_NUM_INTRO_POINTS: u8 = 3;

impl OnionServiceConfig {
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
            // prove that we have handled every field
            let OnionServiceConfig { $( $field: _, )* } = self;

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

            // IPT manager will respond by adding or removing IPTs as desired.
            // (Old IPTs are not proactively removed, but they will not be replaced
            // as they are rotated out.)
            num_intro_points: simply_update,

            // IPT manager's "new configuration" select arm handles this,
            // by replacing IPTs if necessary.
            rate_limit_at_intro: simply_update,

            // We extract this on every introduction request.
            max_concurrent_streams_per_circuit: simply_update,

            // The descriptor publisher responds by generating and publishing a new descriptor.
            restricted_discovery: simply_update,
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

    /// Return a RequestFilter based on this configuration.
    pub(crate) fn filter_settings(&self) -> crate::rend_handshake::RequestFilter {
        crate::rend_handshake::RequestFilter {
            max_concurrent_streams: self.max_concurrent_streams_per_circuit as usize,
        }
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
