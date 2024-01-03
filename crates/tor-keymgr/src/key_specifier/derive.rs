//! [`KeySpecifier`] derive-adhoc macro and its support code
//!
//! # STABILITY - NOTHING IN THIS MODULE IS PART OF THE STABLE PUBLIC API
//!
//! The `pub` items in this module are accessible as `$crate::key_specifier_derive`,
//! but `#[doc(hidden)]` is applied at the top level.
//!
//! (Recall that the actual derive-adhoc macro
//! `KeySpecifier` ends up in the crate toplevel,
//! so that *does* form part of our public API.)

use derive_adhoc::define_derive_adhoc;

define_derive_adhoc! {
    /// A helper for implementing [`KeySpecifier`]s.
    ///
    /// Applies to a struct that has some static components (`prefix`, `role`),
    /// and a number of variable components represented by its fields.
    ///
    /// Implements `KeySpecifier` and some helper methods.
    ///
    /// Each field is either a path field (which becomes a component in the `ArtiPath`),
    /// or a denotator (which becomes *part* of the final component in the `ArtiPath`).
    ///
    /// The `prefix` is the first component of the [`ArtiPath`] of the [`KeySpecifier`].
    ///
    /// The `role` is the _prefix of the last component_ of the [`ArtiPath`] of the specifier.
    /// The `role` is followed by the denotators of the key.
    ///
    /// The denotator fields, if there are any,
    /// should be anotated with `#[denotator]`.
    ///
    /// The declaration order of the fields is important.
    /// The inner components of the [`ArtiPath`] of the specifier are built
    /// from the string representation of its path fields, taken in declaration order,
    /// followed by the encoding of its denotators, also taken in the order they were declared.
    /// As such, all path fields, must implement [`KeySpecifierComponent`].
    /// and all denotators must implement [`KeySpecifierComponent`].
    /// The denotators are separated from the rest of the path, and from each other,
    /// by `+` characters.
    ///
    /// For example, a key specifier with `prefix` `"foo"` and `role` `"bar"`
    /// will have an [`ArtiPath`] of the form
    /// `"foo/<field1_str>/<field2_str>/../bar[+<denotators>]"`.
    ///
    /// A key specifier of this form, with denotators that encode to "d1" and "d2",
    /// would look like this: `"foo/<field1_str>/<field2_str>/../bar+d1+d2"`.
    ///
    /// ### Custom attributes
    ///
    ///  * **`#[adhoc(prefix)]`** (toplevel):
    ///    Specifies the fixed prefix (the first path component).
    ///    Must be a literal string.
    ///
    ///  * **`#[adhoc(role = "...")]`** (toplevel):
    ///    Specifies the role - the initial portion of the leafname.
    ///    Must be a literal string.
    ///    This or the field-level `#[adhoc(role)]` must be specified.
    ///
    ///  * **`[adhoc(role)]` (field):
    ///    Specifies that the role is determined at runtime.
    ///    The field type must implement [`KeyDenotator`].
    ///
    ///  * **`#[adhoc(summary = "...")]`** (summary, mandatory):
    ///    Specifies the summary; ends up as the `summary` field in [`KeyPathInfo`].
    ///    (See [`KeyPathInfoBuilder::summary()`].)
    ///    Must be a literal string.
    ///
    ///  * **`#[adhoc(denotator)]`** (field):
    ///    Designates a field that should be represented
    ///    in the key file leafname, after the role.
    ///
    ///  * **`#[adhoc(ctor_path = "expression")]`** (toplevel):
    ///    Specifies that this kind of key has a representation in C Tor keystores,
    ///    and provides an expression for computing the path.
    ///    The expression should have type `impl Fn(&Self) -> CTorPath`.
    ///
    ///    If not specified, the generated [`KeySpecifier::ctor_path`]
    ///    implementation will always return `None`.
    ///
    ///  * **`#[adhoc(fixed_path_component = "component")]`** (field):
    ///    Before this field insert a fixed path component `component`.
    ///    (Can be even used before a denotator component,
    ///    to add a final fixed path component.)
    ///
    pub KeySpecifier for struct =

    // A condition that evaluates to `true` for path fields.
    ${defcond F_IS_PATH not(any(fmeta(denotator), fmeta(role)))}
    ${defcond F_IS_ROLE all(fmeta(role), not(tmeta(role)))}

    impl<$tgens> $ttype
    where $twheres
    {
        #[doc = concat!("Create a new`", stringify!($ttype), "`")]
        #[allow(dead_code)] // caller might just construct Self with a struct literal
        pub(crate) fn new( $( $fname: $ftype , ) ) -> Self {
            Self {
                $( $fname , )
            }
        }

        /// A helper for generating the prefix shared by all `ArtiPath`s
        /// of the keys associated with this specifier.
        ///
        /// Returns the `ArtiPath`, minus the denotators.
        //
        // TODO HSS this function is a rather unprincipled addition to Self's API
        fn arti_path_prefix(
            $(${when F_IS_ROLE} $fname: Option<&$ftype> , )
            $(${when F_IS_PATH} $fname: Option<&$ftype> , )
        ) -> Result<String, tor_error::Bug> {
            // TODO this has a lot of needless allocations
            ${define F_COMP_STRING {
                match $fname {
                    Some(s) => $crate::KeySpecifierComponent::to_component(s)?.to_string(),
                    None => "*".to_string(),
                },
            }}
            Ok(vec![
                ${tmeta(prefix) as str}.to_string(),
                $(
                  ${if fmeta(fixed_path_component) {
                        ${fmeta(fixed_path_component) as str} .to_owned(),
                  }}
                  ${if F_IS_PATH { $F_COMP_STRING }}
                )
                ${for fields {
                  ${if F_IS_ROLE { $F_COMP_STRING }}
                }}
                ${if tmeta(role) { ${tmeta(role) as str}.to_string() , }}
            ].join("/"))
        }

        /// Get an [`KeyPathPattern`] that can match the [`ArtiPath`]s
        /// of all the keys of this type.
        ///
        /// This builds a pattern by joining the `prefix` of this specifier
        /// with the specified field values, its `role`, and a pattern
        /// that contains a wildcard (`*`) in place of each denotator.
        //
        // TODO HSS consider abolishing or modifying this depending on call site experiences
        // See https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1733#note_2966402
          $tvis fn arti_pattern(
              $(${when F_IS_ROLE} $fname: Option<&$ftype>,)
              $(${when F_IS_PATH} $fname: Option<&$ftype>,)
          ) -> Result<$crate::KeyPathPattern, tor_error::Bug> {
            #[allow(unused_mut)] // mut is only needed for specifiers that have denotators
              let mut pat = Self::arti_path_prefix(
                  $(${when fmeta(role)} $fname,)
                  $(${when F_IS_PATH} $fname,)
              )?;

            ${for fields {
                ${when fmeta(denotator)}

                pat.push_str(&format!("{}*", $crate::DENOTATOR_SEP));
            }}

            Ok(KeyPathPattern::Arti(pat))
        }

        /// A convenience wrapper around `Self::arti_path_prefix`.
        fn prefix(&self) -> Result<String, tor_error::Bug> {
            Self::arti_path_prefix(
                $(${when F_IS_ROLE} Some(&self.$fname),)
                $(${when F_IS_PATH} Some(&self.$fname),)
            )
        }
    }

    impl<$tgens> $crate::KeySpecifier for $ttype
    where $twheres
    {
        fn arti_path(&self) -> Result<$crate::ArtiPath, $crate::ArtiPathUnavailableError> {
            #[allow(unused_mut)] // mut is only needed for specifiers that have denotators
            let mut path = self.prefix()?;

            $(
                // We only care about the fields that are denotators
                ${ when fmeta(denotator) }

                let denotator = $crate::KeySpecifierComponent::to_component(&self.$fname)?;
                path.push($crate::DENOTATOR_SEP);
                path.push_str(&denotator.to_string());
            )

            return Ok($crate::ArtiPath::new(path).map_err(|e| tor_error::internal!("{e}"))?);
        }

        fn ctor_path(&self) -> Option<$crate::CTorPath> {
            ${if tmeta(ctor_path) {
                // TODO HSS: the HsSvcKeySpecifier will need to be configured with all the
                // directories used by C tor. The resulting CTorPath will be prefixed with the
                // appropriate C tor directory, based on the HsSvcKeyRole.
                //
                // Ie, provide the #[adhoc(ctor_path)] attribute
                Some( ${tmeta(ctor_path) as tokens} (self) )
            } else {
                None
            }}
        }
    }

    $crate::paste::paste! {
        struct [< $tname InfoExtractor >];

        impl<$tgens> $crate::KeyInfoExtractor for [< $tname InfoExtractor >]
        where $twheres
        {
            fn describe(
                &self,
                path: &$crate::KeyPath,
            ) -> std::result::Result<$crate::KeyPathInfo, $crate::KeyPathError> {
                // TODO: re-export into_internal! from tor-keymgr and
                // use $crate::into_internal! here.
                use tor_error::into_internal;

                // Check if this is a valid path
                let _ = $tname::try_from(path)?;

                // TODO: have users specify a `spec_name` for the key specifier.
                Ok(
                    // TODO: Add extra info the to the Keyinfo
                    $crate::KeyPathInfoBuilder::default()
                        .summary(${tmeta(summary) as str}.to_string())
                        .build()
                        .map_err(into_internal!("failed to build KeyPathInfo"))?
                )
            }
        }

        impl<$tgens> TryFrom<&$crate::KeyPath> for $tname
        where $twheres
        {
            type Error = $crate::KeyPathError;

            fn try_from(path: &$crate::KeyPath) -> std::result::Result<$tname, Self::Error> {
                //   1. Match the variable components using arti_pattern()
                //   2. If the path doesn't match, return an error
                //   3. If the path matches, check if variable components and denotators can be
                //   validated with KeySpecifierComponent::from_component
                //   respectively

                #[allow(unused_imports)] // KeySpecifierComponent is unused if there are no fields
                use $crate::KeySpecifierComponent;
                use $crate::KeyPathError as E;
                // TODO: re-export internal! from tor-keymgr and
                // use $crate::internal! here.
                use tor_error::internal;

                match path {
                    #[allow(unused)] // arti_path is unused if there are no fields
                    $crate::KeyPath::Arti(arti_path) => {
                        // Create an arti pattern that matches all ArtiPaths
                        // associated with this specifier: each variable
                        // component (i.e. field) is matched using a '*' glob.
                        let pat = $tname::arti_pattern(
                            ${for fields { ${when F_IS_ROLE} None, }}
                            ${for fields { ${when F_IS_PATH} None, }}
                        )?;

                        let Some(captures) = path.matches(&pat.clone().into()) else {
                            // If the pattern doesn't match at all, it
                            // means the path didn't come from a
                            // KeySpecifier of this type.
                            return Err(E::PatternNotMatched(pat));
                        };

                        let mut c = captures.into_iter();

                        // Try to match each capture with our fields/denotators,
                        // in order. Conceptually this is like zipping the
                        // capture iterators with an iterator over fields and
                        // denotators, if there was such a thing.
                        let mut component = || {
                            let Some(capture) = c.next() else {
                                return Err(internal!("more fields than captures?!").into());
                            };

                            let Some(component) = arti_path.substring(&capture) else {
                                return Err(internal!("capture not within bounds?!").into());
                            };

                                let component = $crate::ArtiPathComponent::new(
                                    component.to_owned()
                                )?;

                            Ok::<_, Self::Error>(component)
                        };

                        let error_handler = |fname: &'static str, value| {
                            move |error| $crate::KeyPathError::InvalidKeyPathComponentValue {
                                error,
                                key: fname.to_owned(),
                                value,
                            }
                        };

                        ${define F_EXTRACT {
                            // This use of $ftype is why we must store owned
                            // types in the struct the macro is applied to.
                            let comp = component()?;
                            let $fname = $ftype::from_component(&comp)
                                .map_err(error_handler(stringify!($fname), comp))?;
                        }}

                        ${for fields { ${when         F_IS_PATH             } $F_EXTRACT }}
                        ${for fields { ${when                    F_IS_ROLE  } $F_EXTRACT }}
                        ${for fields { ${when not(any(F_IS_PATH, F_IS_ROLE))} $F_EXTRACT }}

                        if c.next().is_some() {
                            return Err(internal!("too many captures?!").into());
                        }

                        Ok($tname::new( $($fname, ) ))
                    }
                    _ => {
                        // TODO HSS: support ctor stores
                        Err(internal!("not implemented").into())
                    },
                }
            }
        }

        // Register the info extractor with `KeyMgr`.
        $crate::inventory::submit!(&[< $tname InfoExtractor >] as &dyn $crate::KeyInfoExtractor);
    }
}
