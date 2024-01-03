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

use std::iter;

use derive_adhoc::define_derive_adhoc;
use itertools::izip;

use tor_error::{into_internal, Bug};

use super::*;
use crate::DENOTATOR_SEP;

/// Trait for (only) formatting as a [`KeySpecifierComponent`]
///
/// Like the fomratting part of `KeySpecifierComponent`
/// but implemented for Option and &str too.
pub trait RawKeySpecifierComponent {
    /// Append `self`s `KeySpecifierComponent` string representation to `s`
    //
    // This is not quite like `KeySpecifierComponent::to_component`,
    // since that *returns* a String (effectively) and we *append*.
    // At some future point we may change KeySpecifierComponent,
    // although the current API has the nice feature that
    // the syntax of the appended string is checked before we receive it here.
    fn append_to(&self, s: &mut String) -> Result<(), Bug>;
}
impl<T: KeySpecifierComponent> RawKeySpecifierComponent for T {
    fn append_to(&self, s: &mut String) -> Result<(), Bug> {
        self.to_component()?.as_str().append_to(s)
    }
}
impl<T: KeySpecifierComponent> RawKeySpecifierComponent for Option<T> {
    fn append_to(&self, s: &mut String) -> Result<(), Bug> {
        let v: &dyn RawKeySpecifierComponent = match self.as_ref() {
            Some(v) => v,
            None => &"*",
        };
        v.append_to(s)
    }
}
impl<'s> RawKeySpecifierComponent for &'s str {
    fn append_to(&self, s: &mut String) -> Result<(), Bug> {
        s.push_str(self);
        Ok(())
    }
}

/// Make an a string like `pc/pc/pc/lc_lc_lc`
fn arti_path_string_from_components(
    path_comps: &[&dyn RawKeySpecifierComponent],
    leaf_comps: &[&dyn RawKeySpecifierComponent],
) -> Result<String, Bug> {
    let mut path = String::new();

    for comp in path_comps {
        comp.append_to(&mut path)?;
        path.push('/');
    }
    for (delim, comp) in izip!(
        iter::once(None).chain(iter::repeat(Some(DENOTATOR_SEP))),
        leaf_comps,
    ) {
        if let Some(delim) = delim {
            path.push(delim);
        }
        comp.append_to(&mut path)?;
    }

    Ok(path)
}

/// Make an `ArtiPath` like `pc/pc/pc/lc_lc_lc`
///
/// This is the engine for the `KeySpecifier` macro's `arti_path()` impls.
///
/// The macro-generated code sets up couple of vectors.
/// Each vector entry is a pointer to the field in the original struct,
/// plus a vtable pointer saying what to do with it.
///
/// For fixed elements in the path,
/// the vtable entry's data pointer is a pointer to a constant &str.
///
/// In the macro, this is done by the user-defined expansion `ARTI_FROM_COMPONENTS_ARGS`.
///
/// Doing it this way minimises the amount of macro-generated machine code.
pub fn arti_path_from_components(
    path_comps: &[&dyn RawKeySpecifierComponent],
    leaf_comps: &[&dyn RawKeySpecifierComponent],
) -> Result<ArtiPath, ArtiPathUnavailableError> {
    Ok(arti_path_string_from_components(path_comps, leaf_comps)?
        .try_into()
        .map_err(into_internal!("bad ArtiPath from good components"))?)
}

/// Make a `KeyPathPattern::Arti` like `pc/pc/pc/lc_lc_lc`
pub fn arti_pattern_from_components(
    path_comps: &[&dyn RawKeySpecifierComponent],
    leaf_comps: &[&dyn RawKeySpecifierComponent],
) -> Result<KeyPathPattern, Bug> {
    Ok(KeyPathPattern::Arti(arti_path_string_from_components(
        path_comps, leaf_comps,
    )?))
}

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

    #[doc = concat!("Pattern matching some or all [`", stringify!($tname), "`]")]
    #[allow(dead_code)] // Not everyone will need the pattern feature
    $tvis struct $<$tname Pattern><$tdefgens>
    where $twheres
    ${vdefbody $vname $(
        ${fattrs doc}
        ///
        /// `None` to match keys with any value for this field.
        $fvis $fname: Option<$ftype>,
    ) }

    // ** MAIN KNOWLEDGE OF HOW THE PATH IS CONSTRUCTED **
    //
    // These two user-defined expansions,
    //   $ARTI_PATH_COMPONENTS
    //   $ARTI_LEAF_COMPONENTS
    // expand to code for handling each path and leaf component,
    // in the order in which they appear in the ArtiPath.
    //
    // The "code for handling", by default, is:
    //   - for a field, take a reference to the field in `self`
    //   - for a fixed component, take a reference to a &'static str
    // in each case with a comma appended.
    // So this is suitable for including in a &[&dyn ...].
    //
    // The call site can override the behaviour by locally redefining,
    // the two user-defined expansions DO_FIELD and DO_LITERAL.
    //
    // DO_FIELD should expand to the code necessary to handle a field.
    // It probably wants to refer to $fname.
    //
    // DO_LITERAL should expand to the code necessary to handle a literal value.
    // When DO_LITERAL is called the user-defined expansion LIT will expand to
    // something like `${fmeta(...) as str}`, which will in turn expand to
    // a string literal.
    //
    // This is the *only* places that knows how ArtiPaths are constructed,
    // when the path syntax is defined using the KeySpecifier d-a macro.
    // XXXX currently this isn't true!  But it will be.
    //
    // The actual code here is necessarily rather abstract.
    ${define ARTI_PATH_COMPONENTS {
        // #[adhoc(prefix = ...)]
        ${define LIT ${tmeta(prefix) as str}}
        $DO_LITERAL

        ${for fields {
            // #[adhoc(fixed_path_component = ...)]
            ${if fmeta(fixed_path_component) {
                // IWVNI d-a allowed arguments to use-defined expansions, but this will do
                ${define LIT ${fmeta(fixed_path_component) as str}}
                $DO_LITERAL
            }}
            // Path fields
            ${if F_IS_PATH { $DO_FIELD }}
        }}
    }}
    ${define ARTI_LEAF_COMPONENTS {
        ${if tmeta(role) {
            // #[adhoc(role = ...)] on the toplevel
            ${define LIT { ${tmeta(role) as str} }}
            $DO_LITERAL
        }}
        ${for fields {
            // #[adhoc(role)] on a field
            ${if F_IS_ROLE { $DO_FIELD }}
        }}
        ${for fields {
            // #[adhoc(denotator)]
            ${if fmeta(denotator) { $DO_FIELD }}
        }}
    }}

    ${define DO_FIELD { &self.$fname, }}
    ${define DO_LITERAL { &$LIT, }}

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
    }

    impl<$tgens> $crate::KeySpecifier for $ttype
    where $twheres
    {
        fn arti_path(&self) -> Result<$crate::ArtiPath, $crate::ArtiPathUnavailableError> {
            use $crate::key_specifier_derive::*;

            arti_path_from_components(
                &[ $ARTI_PATH_COMPONENTS ],
                &[ $ARTI_LEAF_COMPONENTS ],
            )
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

    impl<$tgens> $crate::KeySpecifierPattern for $<$tname Pattern><$tdefgens>
    where $twheres
    {
        fn arti_pattern(&self) -> Result<$crate::KeyPathPattern, tor_error::Bug> {
            use $crate::key_specifier_derive::*;

            arti_pattern_from_components(
                &[ $ARTI_PATH_COMPONENTS ],
                &[ $ARTI_LEAF_COMPONENTS ],
            )
        }

        fn new_any() -> Self {
            $< $tname Pattern > {
                $( $fname: None, )
            }
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
                        let pat = $< $tname Pattern >::<$tgens>::new_any().arti_pattern()?;

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
