//! Functionality for merging one config builder into another.

use derive_deftly::define_derive_deftly;
use std::collections::BTreeMap;

/// A builder that can be extended from another builder.
pub trait ExtendBuilder {
    /// Consume `other`, and merge its contents into `self`.
    ///
    /// Generally, whenever a field is set in `other`,
    /// it should replace any corresponding field in `self`.
    /// Unset fields in `other` should have no effect.
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
    /// The provided `extend_from` function will behave as:
    ///  * For every non-`sub_builder` field,
    ///    if there is a value set in `other`,
    ///    replace the value in `self` (if any) with that value.
    ///    (Otherwise, leave the value in `self` as it is).
    ///  * For every `sub_builder` field,
    ///    recursively use `extend_from` to extend that builder
    ///    from the corresponding builder in `other`.
    ///
    /// # Interaction with `sub_builder`.
    ///
    /// When a field in the struct is tagged with `#[builder(sub_builder)]`,
    /// you must also tag the same field with `#[deftly(extend_builder(sub_builder))]`;
    /// otherwise, compilation will fail.
    ///
    /// # Interaction with `strip_option` and `default`.
    ///
    /// **The flags have no special effect on the `ExtendBuilder`, and will work fine.**
    ///
    /// (See comments in the code for details about why, and what this means.
    /// Remember, `builder(default)` is applied when `build()` is called,
    /// and does not automatically cause an un-set option to count as set.)
    export ExtendBuilder for struct, expect items:

    impl $crate::extend_builder::ExtendBuilder for $<$ttype Builder> {
        fn extend_from(&mut self, other: Self, strategy: $crate::extend_builder::ExtendStrategy) {
            let _ = strategy; // This will be unused when there is no sub-builder.
            ${for fields {

                ${if fmeta(extend_builder(sub_builder)) {
                    $crate::extend_builder::ExtendBuilder::extend_from(&mut self.$fname, other.$fname, strategy);
                } else {
                    // Note that we do not need any special handling here for `strip_option` or
                    // `default`.
                    //
                    // Recall that:
                    // * `strip_option` only takes effect in a setter method,
                    //   and causes the setter to wrap an additional Some() around its argument.
                    // * `default` takes effect in the build method,
                    //   and controls that method's behavior when.
                    //
                    // In both cases, when the built object has a field of type `T`,
                    // the builder will have a corresponding field of type `Option<T>`,
                    // and will represent an un-set field with `None`.
                    // Therefore, since these flags don't effect the representation of a set or un-set field,
                    // our `extend_from` function doesn't need to know about them.
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

    #[derive(Clone, Debug, derive_builder::Builder, Eq, PartialEq, Deftly)]
    #[builder(derive(Debug, Eq, PartialEq))]
    #[derive_deftly(ExtendBuilder)]
    struct DAndS {
        simple: Option<u32>,
        #[builder(default = "Some(123)")]
        dflt: Option<u32>,
        #[builder(setter(strip_option))]
        strip: Option<u32>,
        #[builder(setter(strip_option), default = "Some(456)")]
        strip_dflt: Option<u32>,
    }
    // For reference, the above will crate code something like the example below.
    // (This may help the tests make more sense)
    /*
    #[derive(Default)]
    struct DAndSBuilder {
        simple: Option<Option<u32>>,
        dflt: Option<Option<u32>>,
        strip: Option<Option<u32>>,
        strip_dflt: Option<Option<u32>>,
    }
    #[allow(unused)]
    impl DAndSBuilder {
        fn simple(&mut self, val: Option<u32>) -> &mut Self {
            self.simple = Some(val);
            self
        }
        fn dflt(&mut self, val: Option<u32>) -> &mut Self {
            self.dflt = Some(val);
            self
        }
        fn strip(&mut self, val: u32) -> &mut Self {
            self.strip = Some(Some(val));
            self
        }
        fn strip_dflt(&mut self, val: u32) -> &mut Self {
            self.strip = Some(Some(val));
            self
        }
        fn build(&self) -> Result<DAndS, DAndSBuilderError> {
            Ok(DAndS {
                simple: self
                    .simple
                    .ok_or(DAndSBuilderError::UninitializedField("simple"))?,
                dflt: self.simple.unwrap_or(Some(123)),
                strip: self
                    .strip
                    .ok_or(DAndSBuilderError::UninitializedField("strip"))?,
                strip_dflt: self.simple.unwrap_or(Some(456)),
            })
        }
    }
    */

    #[test]
    // Demonstrate "default" and "strip_option" behavior without Extend.
    fn default_and_strip_noextend() {
        // Didn't set non-default options; this will fail.
        assert!(DAndSBuilder::default().build().is_err());
        assert!(DAndSBuilder::default().simple(Some(7)).build().is_err());
        assert!(DAndSBuilder::default().strip(7).build().is_err());

        // We can get away with setting only the non-defaulting options.
        let v = DAndSBuilder::default()
            .simple(Some(7))
            .strip(77)
            .build()
            .unwrap();
        assert_eq!(
            v,
            DAndS {
                simple: Some(7),
                dflt: Some(123),
                strip: Some(77),
                strip_dflt: Some(456)
            }
        );

        // But we _can_ also set the defaulting options.
        let v = DAndSBuilder::default()
            .simple(Some(7))
            .strip(77)
            .dflt(Some(777))
            .strip_dflt(7777)
            .build()
            .unwrap();
        assert_eq!(
            v,
            DAndS {
                simple: Some(7),
                dflt: Some(777),
                strip: Some(77),
                strip_dflt: Some(7777)
            }
        );

        // Now inspect the state of an uninitialized builder, and verify that it works as expected.
        //
        // Notably, everything is an Option<Option<...>> for this builder:
        // `strip_option` only affects the behavior of the setter function,
        // and `default` only affects the behavior of the build function.
        // Neither affects the representation..
        let mut bld = DAndSBuilder::default();
        assert_eq!(
            bld,
            DAndSBuilder {
                simple: None,
                dflt: None,
                strip: None,
                strip_dflt: None
            }
        );
        bld.simple(Some(7))
            .strip(77)
            .dflt(Some(777))
            .strip_dflt(7777);
        assert_eq!(
            bld,
            DAndSBuilder {
                simple: Some(Some(7)),
                dflt: Some(Some(777)),
                strip: Some(Some(77)),
                strip_dflt: Some(Some(7777)),
            }
        );
    }

    #[test]
    fn default_and_strip_extending() {
        fn combine_and_build(
            b1: &DAndSBuilder,
            b2: &DAndSBuilder,
        ) -> Result<DAndS, DAndSBuilderError> {
            let mut b = b1.clone();
            b.extend_from(b2.clone(), ExtendStrategy::ReplaceLists);
            b.build()
        }

        // We fail if neither builder sets some non-defaulting option.
        let dflt_builder = DAndSBuilder::default();
        assert!(combine_and_build(&dflt_builder, &dflt_builder).is_err());
        let mut simple_only = DAndSBuilder::default();
        simple_only.simple(Some(7));
        let mut strip_only = DAndSBuilder::default();
        strip_only.strip(77);
        assert!(combine_and_build(&dflt_builder, &simple_only).is_err());
        assert!(combine_and_build(&dflt_builder, &strip_only).is_err());
        assert!(combine_and_build(&simple_only, &dflt_builder).is_err());
        assert!(combine_and_build(&strip_only, &dflt_builder).is_err());
        assert!(combine_and_build(&strip_only, &strip_only).is_err());
        assert!(combine_and_build(&simple_only, &simple_only).is_err());

        // But if every non-defaulting option is set in some builder, we succeed.
        let v1 = combine_and_build(&strip_only, &simple_only).unwrap();
        let v2 = combine_and_build(&simple_only, &strip_only).unwrap();
        assert_eq!(v1, v2);
        assert_eq!(
            v1,
            DAndS {
                simple: Some(7),
                dflt: Some(123),
                strip: Some(77),
                strip_dflt: Some(456)
            }
        );

        // For every option, in every case: when a.extend(b) happens,
        // a set option overrides a non-set option.
        let mut all_set_1 = DAndSBuilder::default();
        all_set_1
            .simple(Some(1))
            .strip(11)
            .dflt(Some(111))
            .strip_dflt(1111);
        let v1 = combine_and_build(&all_set_1, &dflt_builder).unwrap();
        let v2 = combine_and_build(&dflt_builder, &all_set_1).unwrap();
        let expected_all_1s = DAndS {
            simple: Some(1),
            dflt: Some(111),
            strip: Some(11),
            strip_dflt: Some(1111),
        };
        assert_eq!(v1, expected_all_1s);
        assert_eq!(v2, expected_all_1s);

        // For every option, in every case: If the option is set in both cases,
        // the extended-from option overrides the previous one.
        let mut all_set_2 = DAndSBuilder::default();
        all_set_2
            .simple(Some(2))
            .strip(22)
            .dflt(Some(222))
            .strip_dflt(2222);
        let v1 = combine_and_build(&all_set_2, &all_set_1).unwrap();
        let v2 = combine_and_build(&all_set_1, &all_set_2).unwrap();
        let expected_all_2s = DAndS {
            simple: Some(2),
            dflt: Some(222),
            strip: Some(22),
            strip_dflt: Some(2222),
        };
        assert_eq!(v1, expected_all_1s); // since all_set_1 came last.
        assert_eq!(v2, expected_all_2s); // since all_set_2 came last.
    }
}
