//! Types for managing directory configuration.
//!
//! Directory configuration tells us where to load and store directory
//! information, where to fetch it from, and how to validate it.
//!
//! # Semver note
//!
//! The types in this module are re-exported from `arti-client`: any changes
//! here must be reflected in the version of `arti-client`.

use std::time::Duration;

use derive_builder::Builder;
use getset::{CopyGetters, Getters};
use serde::{Deserialize, Serialize};
use tor_checkable::timed::TimerangeBound;
use tor_config::{ConfigBuildError, define_list_builder_accessors, impl_standard_builder};
use tor_netdoc::doc::netstatus::Lifetime;

use crate::{
    authority::{AuthorityBuilder, AuthorityList, AuthorityListBuilder},
    fallback::{FallbackDirBuilder, FallbackList, FallbackListBuilder},
    retry::{DownloadSchedule, DownloadScheduleBuilder},
};

/// Configuration information about the Tor network itself; used as
/// part of Arti's configuration.
///
/// This type is immutable once constructed. To make one, use
/// [`NetworkConfigBuilder`], or deserialize it from a string.
//
// TODO: We should move this type around, since the fallbacks part will no longer be used in
// dirmgr, but only in guardmgr.  Probably this type belongs in `arti-client`.
#[derive(Debug, Clone, Builder, Eq, PartialEq, Getters)]
#[builder(build_fn(validate = "Self::validate", error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
#[non_exhaustive]
pub struct NetworkConfig {
    /// List of locations to look in when downloading directory information, if
    /// we don't actually have a directory yet.
    ///
    /// (If we do have a cached directory, we use directory caches listed there
    /// instead.)
    ///
    /// This section can be changed in a running Arti client.  Doing so will
    /// affect future download attempts only.
    ///
    /// The default is to use a set of compiled-in fallback directories,
    /// whose addresses and public keys are shipped as part of the Arti source code.
    #[builder(sub_builder, setter(custom))]
    #[getset(get = "pub")]
    fallback_caches: FallbackList,

    /// List of directory authorities which we expect to sign consensus
    /// documents.
    ///
    /// (If none are specified, we use a default list of authorities shipped
    /// with Arti.)
    ///
    /// This section cannot be changed in a running Arti client.
    ///
    /// The default is to use a set of compiled-in authorities,
    /// whose identities and public keys are shipped as part of the Arti source code.
    #[builder(sub_builder, setter(custom))]
    #[getset(get = "pub")]
    authorities: AuthorityList,
}

impl_standard_builder! { NetworkConfig }

define_list_builder_accessors! {
    struct NetworkConfigBuilder {
        pub fallback_caches: [FallbackDirBuilder],
        pub authorities: [AuthorityBuilder],
    }
}

impl NetworkConfigBuilder {
    /// Check that this builder will give a reasonable network.
    fn validate(&self) -> std::result::Result<(), ConfigBuildError> {
        if self.opt_authorities().is_some() && self.opt_fallback_caches().is_none() {
            return Err(ConfigBuildError::Inconsistent {
                fields: vec!["authorities".to_owned(), "fallbacks".to_owned()],
                problem: "Non-default authorities are use, but the fallback list is not overridden"
                    .to_owned(),
            });
        }

        Ok(())
    }
}

/// Configuration information for how exactly we download documents from the
/// Tor directory caches.
///
/// This type is immutable once constructed. To make one, use
/// [`DownloadScheduleConfigBuilder`], or deserialize it from a string.
#[derive(Debug, Clone, Builder, Eq, PartialEq, Getters, CopyGetters)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
#[non_exhaustive]
pub struct DownloadScheduleConfig {
    /// Top-level configuration for how to retry our initial bootstrap attempt.
    #[builder(
        sub_builder,
        field(build = "self.retry_bootstrap.build_retry_bootstrap()?")
    )]
    #[builder_field_attr(serde(default))]
    #[getset(get_copy = "pub")]
    retry_bootstrap: DownloadSchedule,

    /// Configuration for how to retry a consensus download.
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    #[getset(get_copy = "pub")]
    retry_consensus: DownloadSchedule,

    /// Configuration for how to retry an authority cert download.
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    #[getset(get_copy = "pub")]
    retry_certs: DownloadSchedule,

    /// Configuration for how to retry a microdescriptor download.
    #[builder(
        sub_builder,
        field(build = "self.retry_microdescs.build_retry_microdescs()?")
    )]
    #[builder_field_attr(serde(default))]
    #[getset(get_copy = "pub")]
    retry_microdescs: DownloadSchedule,
}

impl_standard_builder! { DownloadScheduleConfig }

/// Configuration for how much much to extend the official tolerances of our
/// directory information.
///
/// Because of possible clock skew, and because we want to tolerate possible
/// failures of the directory authorities to reach a consensus, we want to
/// consider a directory to be valid for a while before and after its official
/// range of validity.
#[derive(Debug, Clone, Builder, Eq, PartialEq, Getters, CopyGetters)]
#[builder(derive(Debug, Serialize, Deserialize))]
#[builder(build_fn(error = "ConfigBuildError"))]
#[non_exhaustive]
pub struct DirTolerance {
    /// For how long before a directory document is valid should we accept it?
    ///
    /// Having a nonzero value here allows us to tolerate a little clock skew.
    ///
    /// Defaults to 1 day.
    #[builder(default = "Duration::from_secs(24 * 60 * 60)")]
    #[builder_field_attr(serde(default, with = "humantime_serde::option"))]
    #[getset(get_copy = "pub")]
    pre_valid_tolerance: Duration,

    /// For how long after a directory document is valid should we consider it
    /// usable?
    ///
    /// Having a nonzero value here allows us to tolerate a little clock skew,
    /// and makes us more robust to temporary failures for the directory
    /// authorities to reach consensus.
    ///
    /// Defaults to 3 days (per [prop212]).
    ///
    /// [prop212]:
    ///     https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/proposals/212-using-old-consensus.txt
    #[builder(default = "Duration::from_secs(3 * 24 * 60 * 60)")]
    #[builder_field_attr(serde(default, with = "humantime_serde::option"))]
    #[getset(get_copy = "pub")]
    post_valid_tolerance: Duration,
}

impl_standard_builder! { DirTolerance }

impl DirTolerance {
    /// Return a new [`TimerangeBound`] that extends the validity interval of
    /// `timebound` according to this configuration.
    pub fn extend_tolerance<B>(&self, timebound: TimerangeBound<B>) -> TimerangeBound<B> {
        timebound
            .extend_tolerance(self.post_valid_tolerance)
            .extend_pre_tolerance(self.pre_valid_tolerance)
    }

    /// Return a new consensus [`Lifetime`] that extends the validity intervals
    /// of `lifetime` according to this configuration.
    pub fn extend_lifetime(&self, lifetime: &Lifetime) -> Lifetime {
        Lifetime::new(
            lifetime.valid_after() - self.pre_valid_tolerance,
            lifetime.fresh_until(),
            lifetime.valid_until() + self.post_valid_tolerance,
        )
        .expect("Logic error when constructing lifetime")
    }
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
    #![allow(clippy::unnecessary_wraps)]

    use crate::{authority::Authority, fallback::FallbackDir};

    use super::*;

    #[test]
    fn build_network() {
        let dflt = NetworkConfig::default();

        // with nothing set, we get the default.
        let mut bld = NetworkConfig::builder();
        let cfg = bld.build().unwrap();
        assert_eq!(cfg.authorities.len(), dflt.authorities.len());
        assert_eq!(cfg.fallback_caches.len(), dflt.fallback_caches.len());

        // with any authorities set, the fallback list _must_ be set
        // or the build fails.
        bld.set_authorities(vec![
            Authority::builder()
                .name("Hello")
                .v3ident([b'?'; 20].into())
                .clone(),
            Authority::builder()
                .name("world")
                .v3ident([b'!'; 20].into())
                .clone(),
        ]);
        assert!(bld.build().is_err());

        bld.set_fallback_caches(vec![{
            let mut bld = FallbackDir::builder();
            bld.rsa_identity([b'x'; 20].into())
                .ed_identity([b'y'; 32].into());
            bld.orports().push("127.0.0.1:99".parse().unwrap());
            bld.orports().push("[::]:99".parse().unwrap());
            bld
        }]);
        let cfg = bld.build().unwrap();
        assert_eq!(cfg.authorities.len(), 2);
        assert_eq!(cfg.fallback_caches.len(), 1);
    }
}
