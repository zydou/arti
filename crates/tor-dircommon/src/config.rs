//! Types for managing directory configuration.
//!
//! Directory configuration tells us where to load and store directory
//! information, where to fetch it from, and how to validate it.
//!
//! # Semver note
//!
//! The types in this module are re-exported from `arti-client`: any changes
//! here must be reflected in the version of `arti-client`.

use std::{fmt::Formatter, time::Duration};

use derive_builder::Builder;
use getset::{CopyGetters, Getters};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{MapAccess, SeqAccess, Visitor, value::MapAccessDeserializer},
};
use tor_checkable::timed::TimerangeBound;
use tor_config::{ConfigBuildError, define_list_builder_accessors, impl_standard_builder};
use tor_netdoc::doc::netstatus::Lifetime;
use tracing::warn;

use crate::{
    authority::{AuthorityContacts, AuthorityContactsBuilder, LegacyAuthority},
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

    /// List of directory authorities which we expect to perform various operations
    /// affecting the overall Tor network.
    ///
    /// (If none are specified, we use a default list of authorities shipped
    /// with Arti.)
    ///
    /// This section cannot be changed in a running Arti client.
    ///
    /// The default is to use a set of compiled-in authorities,
    /// whose identities and public keys are shipped as part of the Arti source code.
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default, deserialize_with = "authority_compat"))]
    #[getset(get = "pub")]
    authorities: AuthorityContacts,
}

impl_standard_builder! { NetworkConfig }

define_list_builder_accessors! {
    struct NetworkConfigBuilder {
        pub fallback_caches: [FallbackDirBuilder],
    }
}

/// Compatibility function for legacy configuration syntaxes.
///
/// Before Arti 1.6.0, we used the following syntax for defining custom authorities:
/// ```toml
/// [tor_network]
/// authorities = [
///     { name = "test000a", v3ident = "1811E131971D37C118E3D3842A53400D5F5DFFA6" },
///     { name = "test001a", v3ident = "5F2AB6BAB847F18CBFCDD9425EAB4761473632A4" },
///     { name = "test002a", v3ident = "F92C5F21BF17035E03CD4B73262F1B7F10FAFE98" },
///     { name = "test003a", v3ident = "997E81DA5052D5172073E6FAB22A97165EDA8912" },
/// ]
/// ```
///
/// Starting with Arti 1.6.0 and the implementation of prop330, we now use a
/// different syntax, which is without doubt way more cumbersome to define.
/// However, this option is rarely set by hand and it allows greater flexibility.
/// ```toml
/// [tor_network.authorities]
/// v3idents = [
///     "000D252DCFA8FC91143A4DC5A3EDE0ECF29919AE",
///     "754169383C399466CA2531D0B3B71AA06DDFF853",
///     "1DB224D49199FAF22327031888EAE56AE4D3E99C",
///     "F216A4D49B51A3F460350410AE666594E87624D5",
/// ]
/// uploads = [
///     [
///         "127.0.0.1:7100",
///     ],
///     [
///         "127.0.0.1:7101",
///     ],
///     [
///         "127.0.0.1:7102",
///     ],
///     [
///         "127.0.0.1:7103",
///     ],
/// ]
/// downloads = [
///     [
///         "127.0.0.1:7100",
///     ],
///     [
///         "127.0.0.1:7101",
///     ],
///     [
///         "127.0.0.1:7102",
///     ],
///     [
///         "127.0.0.1:7103",
///     ],
/// ]
/// votes = [
///     [
///         "127.0.0.1:7100",
///     ],
///     [
///         "127.0.0.1:7101",
///     ],
///     [
///         "127.0.0.1:7102",
///     ],
///     [
///         "127.0.0.1:7103",
///     ],
/// ]
/// ```
///
/// This code is largely inspired by the following serde document:
/// <https://serde.rs/string-or-struct.html>
fn authority_compat<'de, D>(deserializer: D) -> Result<AuthorityContactsBuilder, D::Error>
where
    D: Deserializer<'de>,
{
    struct LegacyOrProp330;

    impl<'de> Visitor<'de> for LegacyOrProp330 {
        type Value = AuthorityContactsBuilder;

        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            formatter.write_str("legacy or prop330")
        }

        /// A sequence (aka list) means that we are using the legacy syntax.
        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            warn!("using deprecated (before arti 1.6.0) authority configuration syntax");
            let mut builder = AuthorityContacts::builder();
            while let Some(legacy_authority) = seq.next_element::<LegacyAuthority>()? {
                builder.v3idents().push(legacy_authority.v3ident);
            }

            Ok(builder)
        }

        /// A map means it is the new syntax; pass responsibility to
        /// [`AuthorityContactsBuilder`] using [`MapAccessDeserializer`].
        fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            Deserialize::deserialize(MapAccessDeserializer::new(map))
        }
    }

    deserializer.deserialize_any(LegacyOrProp330)
}

impl NetworkConfigBuilder {
    /// Check that this builder will give a reasonable network.
    fn validate(&self) -> std::result::Result<(), ConfigBuildError> {
        if self.authorities.opt_v3idents().is_some() && self.opt_fallback_caches().is_none() {
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
///
/// TODO: Remove the [`Default`] because it is too tightly bound to a client.
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    #![allow(clippy::unnecessary_wraps)]

    use crate::fallback::FallbackDir;

    use super::*;

    #[test]
    fn build_network() {
        let dflt = NetworkConfig::default();

        // with nothing set, we get the default.
        let mut bld = NetworkConfig::builder();
        let cfg = bld.build().unwrap();
        assert_eq!(
            cfg.authorities.v3idents().len(),
            dflt.authorities.v3idents().len()
        );
        assert_eq!(cfg.fallback_caches.len(), dflt.fallback_caches.len());

        // with any authorities set, the fallback list _must_ be set
        // or the build fails.
        bld.authorities
            .set_v3idents(vec![[b'?'; 20].into(), [b'!'; 20].into()]);
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
        assert_eq!(cfg.authorities.v3idents().len(), 2);
        assert_eq!(cfg.fallback_caches.len(), 1);
    }

    #[test]
    fn deserialize_compat() {
        // Test whether we can serialize both formats.

        let mut netcfg_legacy: NetworkConfigBuilder = toml::from_str(
            "
        authorities = [
            { name = \"test000a\", v3ident = \"911F7C74212214823DDBDE3044B5B1AF3EFB98A0\" },
            { name = \"test001a\", v3ident = \"46C4A4492D103A8C5CA544AC653B51C7B9AC8692\" },
            { name = \"test002a\", v3ident = \"28D4680EA9C3660D1028FC40BACAC1319414581E\" },
            { name = \"test003a\", v3ident = \"3817C9EB7E41C957594D0D9BCD6C7D7D718479C2\" },
        ]",
        )
        .unwrap();

        let mut netcfg_prop330: NetworkConfigBuilder = toml::from_str(
            "
        [authorities]
        v3idents = [
            \"911F7C74212214823DDBDE3044B5B1AF3EFB98A0\",
            \"46C4A4492D103A8C5CA544AC653B51C7B9AC8692\",
            \"28D4680EA9C3660D1028FC40BACAC1319414581E\",
            \"3817C9EB7E41C957594D0D9BCD6C7D7D718479C2\",
        ]",
        )
        .unwrap();

        assert_eq!(netcfg_legacy.authorities.v3idents().len(), 4);
        assert_eq!(
            netcfg_legacy.authorities.v3idents(),
            netcfg_prop330.authorities.v3idents(),
        );
    }
}
