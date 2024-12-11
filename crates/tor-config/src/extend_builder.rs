//! Functionality for merging one config builder into another.

use derive_deftly::define_derive_deftly;
use std::collections::BTreeMap;

/// A builder that can be extended from another builder.
pub trait ExtendBuilder {
    /// Consume `other`, and merge its contents into `self`.
    ///
    /// We use this trait to implement map-style configuration options
    /// that need to have defaults.
    /// Rather than simply replacing the maps wholesale
    /// (as would happen with serde defaults ordinarily)
    /// we use this trait to copy inner options from the provided options over the defaults
    /// in the most fine-grained manner possible.
    ///
    /// ## When `strategy` is [`ExtendStrategy::ReplaceLists`]:
    ///
    /// (No other strategies currently exist.)
    ///
    /// Every simple option that is set in `other` should be moved into `self`,
    /// replacing a previous value (if there was one).
    ///
    /// Every list option that is set in `other` should be moved into `self`,
    /// replacing a previous value (if there was one).
    ///
    /// Any complex option (one with an internal tree structure) that is set in `other`
    /// should recursively be extended, replacing each piece of it that is set in other.
    fn extend_from(&mut self, other: Self, strategy: ExtendStrategy);
}

/// Strategy for extending one builder with another.
///
/// Currently, only one strategy is defined:
/// this enum exists so that we can define others in the future.
#[derive(Clone, Debug, Copy, Eq, PartialEq)]
// We declare this to be an exhaustive enum, since every ExtendBuilder implementation
// must support every strategy.
// So if we add a new strategy, that has to be a breaking change in `ExtendBuilder`.
#[allow(clippy::exhaustive_enums)]
pub enum ExtendStrategy {
    /// Replace all simple options (those with no internal structure).
    ///
    /// Replace all list options.
    ///
    /// Recursively extend all tree options.
    ReplaceLists,
}

impl<K: Ord, T: ExtendBuilder> ExtendBuilder for BTreeMap<K, T> {
    fn extend_from(&mut self, other: Self, strategy: ExtendStrategy) {
        use std::collections::btree_map::Entry::*;
        for (other_k, other_v) in other.into_iter() {
            match self.entry(other_k) {
                Vacant(vacant_entry) => {
                    vacant_entry.insert(other_v);
                }
                Occupied(mut occupied_entry) => {
                    occupied_entry.get_mut().extend_from(other_v, strategy);
                }
            }
        }
    }
}

define_derive_deftly! {
    /// Provide an [`ExtendBuilder`] implementation for a struct's builder.
    ///
    /// This template is only sensible when used alongside `#[derive(Builder)]`.
    ///
    /// When a field in the struct is tagged with `#[builder(sub_builder)]`,
    /// you must also tag the same field with `#[deftly(extend_builder(sub_builder))]`;
    /// otherwise, compilation will fail.
    export ExtendBuilder for struct, expect items:

    impl $crate::extend_builder::ExtendBuilder for $<$ttype Builder> {
        fn extend_from(&mut self, other: Self, strategy: $crate::extend_builder::ExtendStrategy) {
            let _ = strategy; // This will be unused when there is no sub-builder.
            ${for fields {

                ${if fmeta(extend_builder(sub_builder)) {
                    $crate::extend_builder::ExtendBuilder::extend_from(&mut self.$fname, other.$fname, strategy);
                } else {
                    if let Some(other_val) = other.$fname {
                        self.$fname = Some(other_val);
                    }
                }}

            }}
        }
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

    use super::*;
    use derive_deftly::Deftly;

    #[derive(Clone, Debug, derive_builder::Builder, Eq, PartialEq, Deftly)]
    #[derive_deftly(ExtendBuilder)]
    struct Album {
        title: String,
        year: u32,
        #[builder(setter(strip_option), default)]
        n_volumes: Option<u8>,
        #[builder(sub_builder)]
        #[deftly(extend_builder(sub_builder))]
        artist: Artist,
    }

    #[derive(Clone, Debug, derive_builder::Builder, Eq, PartialEq, Deftly)]
    #[derive_deftly(ExtendBuilder)]
    struct Artist {
        name: String,
        #[builder(setter(strip_option), default)]
        year_formed: Option<u32>,
    }

    #[test]
    fn extend() {
        let mut a = AlbumBuilder::default();
        a.artist().year_formed(1940);
        a.title("Untitled".to_string());

        let mut b = AlbumBuilder::default();
        b.year(1980).artist().name("Unknown artist".to_string());
        let mut aa = a.clone();
        aa.extend_from(b, ExtendStrategy::ReplaceLists);
        let aa = aa.build().unwrap();
        assert_eq!(
            aa,
            Album {
                title: "Untitled".to_string(),
                year: 1980,
                n_volumes: None,
                artist: Artist {
                    name: "Unknown artist".to_string(),
                    year_formed: Some(1940)
                }
            }
        );

        let mut b = AlbumBuilder::default();
        b.year(1969)
            .title("Hot Rats".to_string())
            .artist()
            .name("Frank Zappa".into());
        let mut aa = a.clone();
        aa.extend_from(b, ExtendStrategy::ReplaceLists);
        let aa = aa.build().unwrap();
        assert_eq!(
            aa,
            Album {
                title: "Hot Rats".to_string(),
                year: 1969,
                n_volumes: None,
                artist: Artist {
                    name: "Frank Zappa".to_string(),
                    year_formed: Some(1940)
                }
            }
        );
    }
}
