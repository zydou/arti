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
use itertools::{izip, EitherOrBoth, Itertools};

use super::*;
use crate::DENOTATOR_SEP;

pub use crate::KeyPathInfoBuilder;
pub use tor_error::{internal, into_internal, Bug};

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

/// Make a string like `pc/pc/pc/lc_lc_lc`
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

/// Error returned from [`RawKeySpecifierComponentParser::parse`]
#[derive(Debug)]
#[allow(clippy::exhaustive_enums)] // Not part of public API
pub enum RawComponentParseResult {
    /// This was a field
    ///
    /// The `Option` has been filled with the actual value.
    /// It has an entry in the `keys` argument to [`parse_key_path`].
    ParsedField,
    /// This was a literal, and it matched
    MatchedLiteral,
    /// Becomes [`KeyPathError::PatternNotMatched`]
    PatternNotMatched,
    /// `InvalidKeyPathComponentValue`
    Invalid(InvalidKeyPathComponentValue),
}

use RawComponentParseResult as RCPR;

/// Trait for parsing a path component, used by [`parse_key_path`]
///
/// Implemented for `Option<impl KeySpecifierComponent>`,
/// and guarantees to fill in the Option if it succeeds.
///
/// Also implemented for `&str`: just checks that the string is right,
/// (and, doesn't modify `*self`).
pub trait RawKeySpecifierComponentParser {
    /// Check that `comp` is as expected, and store any results in `self`.
    fn parse(&mut self, comp: &Slug) -> RawComponentParseResult;
}

impl<T: KeySpecifierComponent> RawKeySpecifierComponentParser for Option<T> {
    fn parse(&mut self, comp: &Slug) -> RawComponentParseResult {
        let v = match T::from_component(comp) {
            Ok(v) => v,
            Err(e) => return RCPR::Invalid(e),
        };
        *self = Some(v);
        RCPR::ParsedField
    }
}
impl<'s> RawKeySpecifierComponentParser for &'s str {
    fn parse(&mut self, comp: &Slug) -> RawComponentParseResult {
        if comp.as_str() == *self {
            RCPR::MatchedLiteral
        } else {
            RCPR::PatternNotMatched
        }
    }
}

/// List of parsers for fields
type Parsers<'p> = [&'p mut dyn RawKeySpecifierComponentParser];

/// Parse a `KeyPath` as an `ArtiPath` like pc/pc/pc/lc_lc_lc
///
/// `keys` is the field names for each of the path_parsers and leaf_parsers,
/// *but* only the ones which will return `RCPR::ParsedField` (or `::Invalid`).
///
/// As with `arti_path_string_components` etc., we try to minimise
/// the amount of macro-generated machine code.
///
/// The macro-generated impl again assembles two vectors,
/// one for the path components and one for the leaf components.
///
/// For a field, the vector entry is a pointer to `&mut Option<...>`
/// for the field, along with a `RawKeySpecifierComponentParser` vtable entry.
/// (The macro-generated impl must unwrap each of these Options,
/// to assemble the final struct.  In principle this could be avoided with
/// use of `MaybeUninit` and unsafe.)
///
/// For a fixed string component, the vector entry data pointer points to its `&str`.
/// "Parsing" consists of checking that the string is as expected.
///
/// We also need the key names for error reporting.
/// We pass this as a *single* array, and a double-reference to the slice,
/// since that resolves to one pointer to a static structure.
pub fn parse_key_path(
    path: &KeyPath,
    keys: &&[&str],
    path_parsers: &mut Parsers,
    leaf_parsers: &mut Parsers,
) -> Result<(), KeyPathError> {
    let path = match path {
        KeyPath::Arti(path) => path.as_str(),
        KeyPath::CTor(_path) => {
            // TODO (#858): support ctor stores
            return Err(internal!("not implemented").into());
        }
    };

    let (path, leaf) = match path.rsplit_once('/') {
        Some((path, leaf)) => (Some(path), leaf),
        None => (None, path),
    };

    let mut keys: &[&str] = keys;

    /// Split a string into components and parse each one
    fn extract(
        input: Option<&str>,
        delim: char,
        parsers: &mut Parsers,
        keys: &mut &[&str],
    ) -> Result<(), KeyPathError> {
        for ent in Itertools::zip_longest(
            input.map(|input| input.split(delim)).into_iter().flatten(),
            parsers,
        ) {
            let EitherOrBoth::Both(comp, parser) = ent else {
                // wrong number of components
                return Err(KeyPathError::PatternNotMatched);
            };

            // TODO would be nice to avoid allocating again here,
            // but I think that needs an `SlugRef`.
            let comp = Slug::new(comp.to_owned()).map_err(ArtiPathSyntaxError::Slug)?;

            let missing_keys = || internal!("keys list too short, bad args to parse_key_path");

            match parser.parse(&comp) {
                RCPR::PatternNotMatched => Err(KeyPathError::PatternNotMatched),
                RCPR::Invalid(error) => Err(KeyPathError::InvalidKeyPathComponentValue {
                    error,
                    key: keys.first().ok_or_else(missing_keys)?.to_string(),
                    value: comp,
                }),
                RCPR::ParsedField => {
                    *keys = keys.split_first().ok_or_else(missing_keys)?.1;
                    Ok(())
                }
                RCPR::MatchedLiteral => Ok(()),
            }?;
        }
        Ok(())
    }

    extract(path, '/', path_parsers, &mut keys)?;
    extract(Some(leaf), DENOTATOR_SEP, leaf_parsers, &mut keys)?;
    Ok(())
}

/// Wrapper for `KeySpecifierComponent` that `Displays` via `fmt_pretty`
struct KeySpecifierComponentPrettyHelper<'c>(&'c dyn KeySpecifierComponent);

impl Display for KeySpecifierComponentPrettyHelper<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        KeySpecifierComponent::fmt_pretty(self.0, f)
    }
}

/// Build a `KeyPathInfo` given the information about a key specifier
///
/// Calling pattern, to minimise macro-generated machine code,
/// is similar `arti_path_from_components`.
///
/// The macro-generated code parses the path into its KeySpecifier impl
/// (as an owned value) and then feeds references to the various fields
/// to `describe_via_components`.
pub fn describe_via_components(
    summary: &&str,
    role: &dyn RawKeySpecifierComponent,
    extra_keys: &&[&str],
    extra_info: &[&dyn KeySpecifierComponent],
) -> Result<KeyPathInfo, KeyPathError> {
    let mut info = KeyPathInfoBuilder::default();
    info.summary(summary.to_string());
    info.role({
        let mut s = String::new();
        role.append_to(&mut s)?;
        s
    });
    for (key, value) in izip!(*extra_keys, extra_info) {
        let value = KeySpecifierComponentPrettyHelper(*value).to_string();
        info.extra_info(*key, value);
    }
    Ok(info
        .build()
        .map_err(into_internal!("failed to build KeyPathInfo"))?)
}

define_derive_adhoc! {
    /// A helper for implementing [`KeySpecifier`]s.
    ///
    /// Applies to a struct that has some static components (`prefix`, `role`),
    /// and a number of variable components represented by its fields.
    ///
    /// Implements `KeySpecifier` etc.
    ///
    /// Each field is either a path field (which becomes a component in the `ArtiPath`),
    /// or a denotator (which becomes *part* of the final component in the `ArtiPath`).
    ///
    /// The `prefix` is the first component of the [`ArtiPath`] of the [`KeySpecifier`].
    ///
    /// The role should be the name of the key in the Tor Specifications.
    /// The `role` is used as the _prefix of the last component_
    /// of the [`ArtiPath`] of the specifier.
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
    /// ### Results of applying this macro
    ///
    /// `#[derive(Adhoc)] #[derive_adhoc(KeySpecifier)] struct SomeKeySpec ...`
    /// generates:
    ///
    ///  * `impl `[`KeySpecifier`]` for SomeKeySpec`
    ///  * `struct SomeKeySpecPattern`,
    ///    a derived struct which contains an `Option` for each field.
    ///    `None` in the pattern means "any".
    ///  * `impl `[`KeySpecifierPattern`]` for SomeKeySpecPattern`
    ///  * `impl TryFrom<`[`KeyPath`]> for SomeKeySpec`
    ///  * Registration of an impl of [`KeyInfoExtractor`]
    ///    (on a private unit struct `SomeKeySpecInfoExtractor`)
    ///
    /// ### Custom attributes
    ///
    ///  * **`#[adhoc(prefix)]`** (toplevel):
    ///    Specifies the fixed prefix (the first path component).
    ///    Must be a literal string.
    ///
    ///  * **`#[adhoc(role = "...")]`** (toplevel):
    ///    Specifies the role - the initial portion of the leafname.
    ///    This should be the name of the key in the Tor Specifications.
    //     TODO (#1195): casing/syntax anomalies for key role:
    //        Some keys in tor-hsservice have roles like k_..., and some KP_... or KS_...
    //        Maybe we should use `KS_...` in #[adhoc(role)], but lowercase in ArtiPaths.
    //        It'll have to become the responsibility of code here to convert.
    //        (We should include the S or P in KS_ or KP, because we might in the future
    //        want to store public keys too; actually we even do store KP_hs_id right now,
    //        but that is wrong according to the design docs.)
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
    // For use sites which want to distinguish the role from other fields:
    // DO_ROLE_FIELD and DO_ROLE_LITERAL are used for the role.
    // They default to expanding $DO_FIELD and $DO_LITERAL respectively.
    //
    // This is the *only* place that knows how ArtiPaths are constructed,
    // when the path syntax is defined using the KeySpecifier d-a macro.
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
            $DO_ROLE_LITERAL
        }}
        ${for fields {
            // #[adhoc(role)] on a field
            ${if F_IS_ROLE { $DO_ROLE_FIELD }}
        }}
        ${for fields {
            // #[adhoc(denotator)]
            ${if fmeta(denotator) { $DO_FIELD }}
        }}
    }}

    ${define DO_FIELD { &self.$fname, }}
    ${define DO_LITERAL { &$LIT, }}
    ${define DO_ROLE_FIELD { $DO_FIELD }}
    ${define DO_ROLE_LITERAL { $DO_LITERAL }}

    impl<$tgens> $crate::KeySpecifier for $ttype
    where $twheres
    {
        fn arti_path(
            &self,
        ) -> std::result::Result<$crate::ArtiPath, $crate::ArtiPathUnavailableError> {
            use $crate::key_specifier_derive::*;

            arti_path_from_components(
                &[ $ARTI_PATH_COMPONENTS ],
                &[ $ARTI_LEAF_COMPONENTS ],
            )
        }

        fn ctor_path(&self) -> Option<$crate::CTorPath> {
            ${if tmeta(ctor_path) {
                // TODO (#858): the HsSvcKeySpecifier will need to be configured with all the
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
        fn arti_pattern(
            &self,
        ) -> std::result::Result<$crate::KeyPathPattern, $crate::key_specifier_derive::Bug> {
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

    struct $< $tname InfoExtractor >;

    impl<$tgens> $crate::KeyInfoExtractor for $< $tname InfoExtractor >
    where $twheres
    {
        fn describe(
            &self,
            path: &$crate::KeyPath,
        ) -> std::result::Result<$crate::KeyPathInfo, $crate::KeyPathError> {
            use $crate::key_specifier_derive::*;

            // Parse this path
            #[allow(unused_variables)] // Unused if no fields
            let spec = $ttype::try_from(path)?;

            // none of this cares about non-role literals
            // all the others three be explicitly defined each time
            ${define DO_LITERAL {}}

            static NON_ROLE_FIELD_KEYS: &[&str] = &[
                ${define DO_FIELD { stringify!($fname), }}
                ${define DO_ROLE_FIELD {}}
                ${define DO_ROLE_LITERAL {}}
                $ARTI_PATH_COMPONENTS
                $ARTI_LEAF_COMPONENTS
            ];

            describe_via_components(
                &${tmeta(summary) as str},

                // role
                ${define DO_FIELD {}}
                ${define DO_ROLE_FIELD { &spec.$fname, }}
                ${define DO_ROLE_LITERAL { &$LIT, }}
                $ARTI_LEAF_COMPONENTS

                &NON_ROLE_FIELD_KEYS,

                &[
                    ${define DO_FIELD { &spec.$fname, }}
                    ${define DO_ROLE_FIELD {}}
                    ${define DO_ROLE_LITERAL {}}
                    $ARTI_PATH_COMPONENTS
                    $ARTI_LEAF_COMPONENTS
                ],
            )
        }
    }

    impl<$tgens> TryFrom<&$crate::KeyPath> for $tname
    where $twheres
    {
        type Error = $crate::KeyPathError;

        fn try_from(path: &$crate::KeyPath) -> std::result::Result<$tname, Self::Error> {
            use $crate::key_specifier_derive::*;

            static FIELD_KEYS: &[&str] = &[
                ${define DO_LITERAL {}}
                ${define DO_FIELD { stringify!($fname), }}
                $ARTI_PATH_COMPONENTS
                $ARTI_LEAF_COMPONENTS
            ];

            #[allow(unused_mut)] // not needed if there are no fields
            #[allow(unused_variables)] // not needed if there are no fields
            let mut builder =
                <$<$tname Pattern>::<$tgens> as $crate::KeySpecifierPattern>::new_any();

            ${define DO_FIELD { &mut builder.$fname, }}
            ${define DO_LITERAL { &mut $LIT, }}

            parse_key_path(
                path,
                &FIELD_KEYS,
                &mut [ $ARTI_PATH_COMPONENTS ],
                &mut [ $ARTI_LEAF_COMPONENTS ],
            )?;

            #[allow(unused_variables)] // not needed if there are no fields
            let handle_none = || internal!("bad RawKeySpecifierComponentParser impl");

            Ok($tname { $(
                $fname: builder.$fname.ok_or_else(handle_none)?,
            ) })
        }
    }

    // Register the info extractor with `KeyMgr`.
    $crate::inventory::submit!(&$< $tname InfoExtractor > as &dyn $crate::KeyInfoExtractor);
}
