//! Processing a config::Config into a validated configuration
//!
//! This module, and particularly [`resolve`], takes care of:
//!
//!   * Deserializing a [`config::Config`] into various `FooConfigBuilder`
//!   * Calling the `build()` methods to get various `FooConfig`.
//!   * Reporting unrecognised configuration keys
//!     (eg to help the user detect misspellings).
//!
//! This is step 3 of the overall config processing,
//! as described in the [crate-level documentation](crate).
//!
//! # Starting points
//!
//! To use this, you will need to:
//!
//!   * `#[derive(Builder)]` and use [`impl_standard_builder!`](crate::impl_standard_builder)
//!     for all of your configuration structures,
//!     using `#[sub_builder]` etc. sa appropriate,
//!     and making your builders [`Deserialize`](serde::Deserialize).
//!
//!   * [`impl TopLevel`](TopLevel) for your *top level* structures (only).
//!
//!   * Call [`resolve`] (or one of its variants) with a `config::Config`,
//!     to obtain your top-level configuration(s).
//!
//! # Example
//!
//! In this example the developers are embedding `arti`, `arti_client`, etc.,
//! into a program of their own.  The example code shown:
//!
//!  * Defines a configuration structure `EmbedderConfig`,
//!    for additional configuration settings for the added features.
//!  * Establishes some configuration sources
//!    (the trivial empty `ConfigSources`, to avoid clutter in the example)
//!  * Reads those sources into a single configuration taxonomy [`config::Config`].
//!  * Processes that configuration into a 3-tuple of configuration
//!    structs for the three components, namely:
//!      - `TorClientConfig`, the configuration for the `arti_client` crate's `TorClient`
//!      - `ArtiConfig`, for behaviours in the `arti` command line utility
//!      - `EmbedderConfig`.
//!  * Will report a warning to the user about config settings found in the config files,
//!    but not recognized by *any* of the three config consumers,
//!
//! ```
//! # fn main() -> Result<(), tor_config::load::ConfigResolveError> {
//! use derive_builder::Builder;
//! use tor_config::{impl_standard_builder, resolve, ConfigBuildError, ConfigurationSources};
//! use tor_config::load::TopLevel;
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Debug, Clone, Builder, Eq, PartialEq)]
//! #[builder(build_fn(error = "ConfigBuildError"))]
//! #[builder(derive(Debug, Serialize, Deserialize))]
//! struct EmbedderConfig {
//!     // ....
//! }
//! impl_standard_builder! { EmbedderConfig }
//! impl TopLevel for EmbedderConfig {
//!     type Builder = EmbedderConfigBuilder;
//! }
//! #
//! # #[derive(Debug, Clone, Builder, Eq, PartialEq)]
//! # #[builder(build_fn(error = "ConfigBuildError"))]
//! # #[builder(derive(Debug, Serialize, Deserialize))]
//! # struct TorClientConfig { }
//! # impl_standard_builder! { TorClientConfig }
//! # impl TopLevel for TorClientConfig { type Builder = TorClientConfigBuilder; }
//! #
//! # #[derive(Debug, Clone, Builder, Eq, PartialEq)]
//! # #[builder(build_fn(error = "ConfigBuildError"))]
//! # #[builder(derive(Debug, Serialize, Deserialize))]
//! # struct ArtiConfig { }
//! # impl_standard_builder! { ArtiConfig }
//! # impl TopLevel for ArtiConfig { type Builder = ArtiConfigBuilder; }
//!
//! let cfg_sources = ConfigurationSources::new_empty(); // In real program, use from_cmdline
//! let cfg = cfg_sources.load()?;
//!
//! let (tcc, arti_config, embedder_config) =
//!      tor_config::resolve::<(TorClientConfig, ArtiConfig, EmbedderConfig)>(cfg)?;
//!
//! let _: EmbedderConfig = embedder_config; // etc.
//!
//! # Ok(())
//! # }
//! ```

use std::collections::BTreeSet;
use std::fmt::{self, Display};
use std::iter;
use std::mem;

use itertools::{chain, izip, Itertools};
use serde::de::DeserializeOwned;
use thiserror::Error;
use tracing::warn;

use crate::{ConfigBuildError, ConfigurationTree};

/// Error resolving a configuration (during deserialize, or build)
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ConfigResolveError {
    /// Deserialize failed
    #[error("Config contents not as expected")]
    Deserialize(#[from] crate::ConfigError),

    /// Build failed
    #[error("Config semantically incorrect")]
    Build(#[from] ConfigBuildError),
}

impl From<config::ConfigError> for ConfigResolveError {
    fn from(err: config::ConfigError) -> Self {
        crate::ConfigError::from(err).into()
    }
}

/// A type that can be built from a builder via a build method
pub trait Builder {
    /// The type that this builder constructs
    type Built;
    /// Build into a `Built`
    ///
    /// Often shadows an inherent `build` method
    fn build(&self) -> Result<Self::Built, ConfigBuildError>;
}

/// Collection of configuration settings that can be deserialized and then built
///
/// *Do not implement directly.*
/// Instead, implement [`TopLevel`]: doing so engages the blanket impl
/// for (loosely) `TopLevel + Builder`.
///
/// Each `Resolvable` corresponds to one or more configuration consumers.
///
/// Ultimately, one `Resolvable` for all the configuration consumers in an entire
/// program will be resolved from a single configuration tree (usually parsed from TOML).
///
/// Multiple config collections can be resolved from the same configuration,
/// via the implementation of `Resolvable` on tuples of `Resolvable`s.
/// Use this rather than `#[serde(flatten)]`; the latter prevents useful introspection
/// (necessary for reporting unrecognized configuration keys, and testing).
///
/// (The `resolve` method will be called only from within the `tor_config::load` module.)
pub trait Resolvable: Sized {
    /// Deserialize and build from a configuration
    //
    // Implementations must do the following:
    //
    //  1. Deserializes the input (cloning it to be able to do this)
    //     into the `Builder`.
    //
    //  2. Having used `serde_ignored` to detect unrecognized keys,
    //     intersects those with the unrecognized keys recorded in the context.
    //
    //  3. Calls `build` on the `Builder` to get `Self`.
    //
    // We provide impls for TopLevels, and tuples of Resolvable.
    //
    // Cannot be implemented outside this module (except eg as a wrapper or something),
    // because that would somehow involve creating `Self` from `ResolveContext`
    // but `ResolveContext` is completely opaque outside this module.
    fn resolve(input: &mut ResolveContext) -> Result<Self, ConfigResolveError>;

    /// Return a list of deprecated config keys, as "."-separated strings
    fn enumerate_deprecated_keys<F>(f: &mut F)
    where
        F: FnMut(&'static [&'static str]);
}

/// Top-level configuration struct, made from a deserializable builder
///
/// One configuration consumer's configuration settings.
///
/// Implementing this trait only for top-level configurations,
/// which are to be parsed at the root level of a (TOML) config file taxonomy.
///
/// This trait exists to:
///
///  * Mark the toplevel configuration structures as suitable for use with [`resolve`]
///  * Provide the type of the `Builder` for use by Rust generic code
pub trait TopLevel {
    /// The `Builder` which can be used to make a `Self`
    ///
    /// Should satisfy `&'_ Self::Builder: Builder<Built=Self>`
    type Builder: DeserializeOwned;

    /// Deprecated config keys, as "."-separates strings
    const DEPRECATED_KEYS: &'static [&'static str] = &[];
}

/// `impl Resolvable for (A,B..) where A: Resolvable, B: Resolvable ...`
///
/// The implementation simply calls `Resolvable::resolve` for each output tuple member.
///
/// `define_for_tuples!{ A B - C D.. }`
///
/// expands to
///  1. `define_for_tuples!{ A B - }`: defines for tuple `(A,B,)`
///  2. `define_for_tuples!{ A B C - D.. }`: recurses to generate longer tuples
macro_rules! define_for_tuples {
    { $( $A:ident )* - $B:ident $( $C:ident )* } => {
        define_for_tuples!{ $($A)* - }
        define_for_tuples!{ $($A)* $B - $($C)* }
    };
    { $( $A:ident )* - } => {
        impl < $($A,)* > Resolvable for ( $($A,)* )
        where $( $A: Resolvable, )*
        {
            fn resolve(cfg: &mut ResolveContext) -> Result<Self, ConfigResolveError> {
                Ok(( $( $A::resolve(cfg)?, )* ))
            }
            fn enumerate_deprecated_keys<NF>(f: &mut NF)
            where NF: FnMut(&'static [&'static str]) {
                $( $A::enumerate_deprecated_keys(f); )*
            }
        }

    };
}
// We could avoid recursion by writing out A B C... several times (in a "triangle") but this
// would make it tiresome and error-prone to extend the impl to longer tuples.
define_for_tuples! { A - B C D E }

/// Config resolution context, not used outside `tor_config::load`
///
/// This is public only because it appears in the [`Resolvable`] trait.
/// You don't want to try to obtain one.
pub struct ResolveContext {
    /// The input
    input: ConfigurationTree,

    /// Paths unrecognized by all deserializations
    ///
    /// None means we haven't deserialized anything yet, ie means the universal set.
    ///
    /// Empty is used to disable this feature.
    unrecognized: UnrecognizedKeys,
}

/// Keys we have *not* recognized so far
///
/// Initially `AllKeys`, since we haven't recognized any.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
enum UnrecognizedKeys {
    /// No keys have yet been recognized, so everything in the config is unrecognized
    AllKeys,

    /// The keys which remain unrecognized by any consumer
    ///
    /// If this is empty, we do not (need to) do any further tracking.
    These(BTreeSet<DisfavouredKey>),
}
use UnrecognizedKeys as UK;

impl UnrecognizedKeys {
    /// Does it represent the empty set
    fn is_empty(&self) -> bool {
        match self {
            UK::AllKeys => false,
            UK::These(ign) => ign.is_empty(),
        }
    }

    /// Update in place, intersecting with `other`
    fn intersect_with(&mut self, other: BTreeSet<DisfavouredKey>) {
        match self {
            UK::AllKeys => *self = UK::These(other),
            UK::These(self_) => {
                let tign = mem::take(self_);
                *self_ = intersect_unrecognized_lists(tign, other);
            }
        }
    }
}

/// Key in config file(s) which is disfavoured (unrecognized or deprecated)
///
/// [`Display`]s in an approximation to TOML format.
/// You can use the [`to_string()`](ToString::to_string) method to obtain
/// a string containing a TOML key path.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct DisfavouredKey {
    /// Can be empty only before returned from this module
    path: Vec<PathEntry>,
}

/// Element of an DisfavouredKey
#[derive(Debug, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
enum PathEntry {
    /// Array index
    ///
    ArrayIndex(usize),
    /// Map entry
    ///
    /// string value is unquoted, needs quoting for display
    MapEntry(String),
}

/// Deserialize and build overall configuration from config sources
///
/// Inner function used by all the `resolve_*` family
fn resolve_inner<T>(
    input: ConfigurationTree,
    want_disfavoured: bool,
) -> Result<ResolutionResults<T>, ConfigResolveError>
where
    T: Resolvable,
{
    let mut deprecated = BTreeSet::new();

    if want_disfavoured {
        T::enumerate_deprecated_keys(&mut |l: &[&str]| {
            for key in l {
                match input.0.get(key) {
                    Err(_) => {}
                    Ok(serde::de::IgnoredAny) => {
                        deprecated.insert(key);
                    }
                }
            }
        });
    }

    let mut lc = ResolveContext {
        input,
        unrecognized: if want_disfavoured {
            UK::AllKeys
        } else {
            UK::These(BTreeSet::new())
        },
    };

    let value = Resolvable::resolve(&mut lc)?;

    let unrecognized = match lc.unrecognized {
        UK::AllKeys => panic!("all unrecognized, as if we had processed nothing"),
        UK::These(ign) => ign,
    }
    .into_iter()
    .filter(|ip| !ip.path.is_empty())
    .collect_vec();

    let deprecated = deprecated
        .into_iter()
        .map(|key| {
            let path = key
                .split('.')
                .map(|e| PathEntry::MapEntry(e.into()))
                .collect_vec();
            DisfavouredKey { path }
        })
        .collect_vec();

    Ok(ResolutionResults {
        value,
        unrecognized,
        deprecated,
    })
}

/// Deserialize and build overall configuration from config sources
///
/// Unrecognized config keys are reported as log warning messages.
///
/// Resolve the whole configuration in one go, using the `Resolvable` impl on `(A,B)`
/// if necessary, so that unrecognized config key processing works correctly.
///
/// This performs step 3 of the overall config processing,
/// as described in the [`tor_config` crate-level documentation](crate).
///
/// For an example, see the
/// [`tor_config::load` module-level documentation](self).
pub fn resolve<T>(input: ConfigurationTree) -> Result<T, ConfigResolveError>
where
    T: Resolvable,
{
    let ResolutionResults {
        value,
        unrecognized,
        deprecated,
    } = resolve_inner(input, true)?;
    for depr in deprecated {
        warn!("deprecated configuration key: {}", &depr);
    }
    for ign in unrecognized {
        warn!("unrecognized configuration key: {}", &ign);
    }
    Ok(value)
}

/// Deserialize and build overall configuration, reporting unrecognized keys in the return value
pub fn resolve_return_results<T>(
    input: ConfigurationTree,
) -> Result<ResolutionResults<T>, ConfigResolveError>
where
    T: Resolvable,
{
    resolve_inner(input, true)
}

/// Results of a successful `resolve_return_disfavoured`
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ResolutionResults<T> {
    /// The configuration, successfully parsed
    pub value: T,

    /// Any config keys which were found in the input, but not recognized (and so, ignored)
    pub unrecognized: Vec<DisfavouredKey>,

    /// Any config keys which were found, but have been declared deprecated
    pub deprecated: Vec<DisfavouredKey>,
}

/// Deserialize and build overall configuration, silently ignoring unrecognized config keys
pub fn resolve_ignore_warnings<T>(input: ConfigurationTree) -> Result<T, ConfigResolveError>
where
    T: Resolvable,
{
    Ok(resolve_inner(input, false)?.value)
}

impl<T> Resolvable for T
where
    T: TopLevel,
    T::Builder: Builder<Built = Self>,
{
    fn resolve(input: &mut ResolveContext) -> Result<T, ConfigResolveError> {
        let deser = input.input.clone();
        let builder: T::Builder = {
            // If input.unrecognized.is_empty() then we don't bother tracking the
            // unrecognized keys since we would intersect with the empty set.
            // That is how this tracking is disabled when we want it to be.
            let want_unrecognized = !input.unrecognized.is_empty();
            let ret = if !want_unrecognized {
                deser.0.try_deserialize()
            } else {
                let mut nign = BTreeSet::new();
                let mut recorder = |path: serde_ignored::Path<'_>| {
                    nign.insert(copy_path(&path));
                };
                let deser = serde_ignored::Deserializer::new(deser.0, &mut recorder);
                let ret = serde::Deserialize::deserialize(deser);
                if ret.is_err() {
                    // If we got an error, the config might only have been partially processed,
                    // so we might get false positives.  Disable the unrecognized tracking.
                    nign = BTreeSet::new();
                }
                input.unrecognized.intersect_with(nign);
                ret
            };
            ret?
        };
        let built = builder.build()?;
        Ok(built)
    }

    fn enumerate_deprecated_keys<NF>(f: &mut NF)
    where
        NF: FnMut(&'static [&'static str]),
    {
        f(T::DEPRECATED_KEYS);
    }
}

/// Turns a [`serde_ignored::Path`] (which is borrowed) into an owned `DisfavouredKey`
fn copy_path(mut path: &serde_ignored::Path) -> DisfavouredKey {
    use serde_ignored::Path as SiP;
    use PathEntry as PE;

    let mut descend = vec![];
    loop {
        let (new_path, ent) = match path {
            SiP::Root => break,
            SiP::Seq { parent, index } => (parent, Some(PE::ArrayIndex(*index))),
            SiP::Map { parent, key } => (parent, Some(PE::MapEntry(key.clone()))),
            SiP::Some { parent }
            | SiP::NewtypeStruct { parent }
            | SiP::NewtypeVariant { parent } => (parent, None),
        };
        descend.extend(ent);
        path = new_path;
    }
    descend.reverse();
    DisfavouredKey { path: descend }
}

/// Computes the intersection, resolving ignorances at different depths
///
/// Eg if `a` contains `application.wombat` and `b` contains `application`,
/// we need to return `application.wombat`.
///
/// # Formally
///
/// A configuration key (henceforth "key") is a sequence of `PathEntry`,
/// interpreted as denoting a place in a tree-like hierarchy.
///
/// Each input `BTreeSet` denotes a subset of the configuration key space.
/// Any key in the set denotes itself, but also all possible keys which have it as a prefix.
/// We say a s set is "minimal" if it doesn't have entries made redundant by this rule.
///
/// This function computes a minimal intersection of two minimal inputs.
/// If the inputs are not minimal, the output may not be either
/// (although `serde_ignored` gives us minimal sets, so that case is not important).
fn intersect_unrecognized_lists(
    al: BTreeSet<DisfavouredKey>,
    bl: BTreeSet<DisfavouredKey>,
) -> BTreeSet<DisfavouredKey> {
    //eprintln!("INTERSECT:");
    //for ai in &al { eprintln!("A: {}", ai); }
    //for bi in &bl { eprintln!("B: {}", bi); }

    // This function is written to never talk about "a" and "b".
    // That (i) avoids duplication of code for handling a<b vs a>b, etc.
    // (ii) make impossible bugs where a was written but b was intended, etc.
    // The price is that the result is iterator combinator soup.

    let mut inputs: [_; 2] = [al, bl].map(|input| input.into_iter().peekable());
    let mut output = BTreeSet::new();

    // The BTreeSets produce items in sort order.
    //
    // We maintain the following invariants (valid at the top of the loop):
    //
    //   For every possible key *strictly earlier* than those remaining in either input,
    //   the output contains the key iff it was in the intersection.
    //
    //   No other keys appear in the output.
    //
    // We peek at the next two items.  The possible cases are:
    //
    //   0. One or both inputs is used up.  In that case none of any remaining input
    //      can be in the intersection and we are done.
    //
    //   1. The two inputs have the same next item.  In that case the item is in the
    //      intersection.  If the inputs are minimal, no children of that item can appear
    //      in either input, so we can make our own output minimal without thinking any
    //      more about this item from the point of view of either list.
    //
    //   2. One of the inputs is a prefix of the other.  In this case the longer item is
    //      in the intersection - as are all subsequent items from the same input which
    //      also share that prefix.  Then, we must discard the shorter item (which denotes
    //      the whole subspace of which only part is in the intersection).
    //
    //   3. Otherwise, the earlier item is definitely not in the intersection and
    //      we can munch it.

    // Peek one from each, while we can.
    while let Ok(items) = {
        // Ideally we would use array::try_map but it's nightly-only
        <[_; 2]>::try_from(
            inputs
                .iter_mut()
                .flat_map(|input: &'_ mut _| input.peek()) // keep the Somes
                .collect::<Vec<_>>(), // if we had 2 Somes we can make a [_; 2] from this
        )
    } {
        let shorter_len = items.iter().map(|i| i.path.len()).min().expect("wrong #");
        let earlier_i = items
            .iter()
            .enumerate()
            .min_by_key(|&(_i, item)| *item)
            .expect("wrong #")
            .0;
        let later_i = 1 - earlier_i;

        if items.iter().all_equal() {
            // Case 0. above.
            //
            // Take the identical items off the front of both iters,
            // and put one into the output (the last will do nicely).
            //dbg!(items);
            let item = inputs
                .iter_mut()
                .map(|input| input.next().expect("but peeked"))
                .last()
                .expect("wrong #");
            output.insert(item);
            continue;
        } else if items
            .iter()
            .map(|item| &item.path[0..shorter_len])
            .all_equal()
        {
            // Case 2.  One is a prefix of the other.   earlier_i is the shorter one.
            let shorter_item = items[earlier_i];
            let prefix = shorter_item.path.clone(); // borrowck can't prove disjointness

            // Keep copying items from the side with the longer entries,
            // so long as they fall within (have the prefix of) the shorter entry.
            //dbg!(items, shorter_item, &prefix);
            while let Some(longer_item) = inputs[later_i].peek() {
                if !longer_item.path.starts_with(&prefix) {
                    break;
                }
                let longer_item = inputs[later_i].next().expect("but peeked");
                output.insert(longer_item);
            }
            // We've "used up" the shorter item.
            let _ = inputs[earlier_i].next().expect("but peeked");
        } else {
            // Case 3.  The items are just different.  Eat the earlier one.
            //dbg!(items, earlier_i);
            let _ = inputs[earlier_i].next().expect("but peeked");
        }
    }
    // Case 0.  At least one of the lists is empty, giving Err() from the array

    //for oi in &ol { eprintln!("O: {}", oi); }
    output
}

impl Display for DisfavouredKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use PathEntry as PE;
        if self.path.is_empty() {
            // shouldn't happen with calls outside this module, and shouldn't be used inside
            // but handle it anyway
            write!(f, r#""""#)?;
        } else {
            let delims = chain!(iter::once(""), iter::repeat("."));
            for (delim, ent) in izip!(delims, self.path.iter()) {
                match ent {
                    PE::ArrayIndex(index) => write!(f, "[{}]", index)?,
                    PE::MapEntry(s) => {
                        if ok_unquoted(s) {
                            write!(f, "{}{}", delim, s)?;
                        } else {
                            write!(f, "{}{:?}", delim, s)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// Would `s` be OK to use unquoted as a key in a TOML file?
fn ok_unquoted(s: &str) -> bool {
    let mut chars = s.chars();
    if let Some(c) = chars.next() {
        c.is_ascii_alphanumeric()
            && chars.all(|c| c == '_' || c == '-' || c.is_ascii_alphanumeric())
    } else {
        false
    }
}

#[cfg(test)]
#[allow(unreachable_pub)] // impl_standard_builder wants to make pub fns
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use crate::*;
    use derive_builder::Builder;
    use serde::{Deserialize, Serialize};

    fn parse_test_set(l: &[&str]) -> BTreeSet<DisfavouredKey> {
        l.iter()
            .map(|s| DisfavouredKey {
                path: s
                    .split('.')
                    .map(|s| PathEntry::MapEntry(s.into()))
                    .collect_vec(),
            })
            .collect()
    }

    #[test]
    #[rustfmt::skip] // preserve the layout so we can match vertically by eye
    fn test_intersect_unrecognized_list() {
        let chk = |a, b, exp| {
            let got = intersect_unrecognized_lists(parse_test_set(a), parse_test_set(b));
            let exp = parse_test_set(exp);
            assert_eq! { got, exp };

            let got = intersect_unrecognized_lists(parse_test_set(b), parse_test_set(a));
            assert_eq! { got, exp };
        };

        chk(&[ "a", "b",     ],
            &[ "a",      "c" ],
            &[ "a" ]);

        chk(&[ "a", "b",      "d" ],
            &[ "a",      "c", "d" ],
            &[ "a",           "d" ]);

        chk(&[ "x.a", "x.b",     ],
            &[ "x.a",      "x.c" ],
            &[ "x.a" ]);

        chk(&[ "t", "u", "v",          "w"     ],
            &[ "t",      "v.a", "v.b",     "x" ],
            &[ "t",      "v.a", "v.b",         ]);

        chk(&[ "t",      "v",              "x" ],
            &[ "t", "u", "v.a", "v.b", "w"     ],
            &[ "t",      "v.a", "v.b",         ]);
    }

    #[test]
    #[allow(clippy::bool_assert_comparison)] // much clearer this way IMO
    fn test_ok_unquoted() {
        assert_eq! { false, ok_unquoted("") };
        assert_eq! { false, ok_unquoted("_") };
        assert_eq! { false, ok_unquoted(".") };
        assert_eq! { false, ok_unquoted("-") };
        assert_eq! { false, ok_unquoted("_a") };
        assert_eq! { false, ok_unquoted(".a") };
        assert_eq! { false, ok_unquoted("-a") };
        assert_eq! { false, ok_unquoted("a.") };
        assert_eq! { true, ok_unquoted("a") };
        assert_eq! { true, ok_unquoted("1") };
        assert_eq! { true, ok_unquoted("z") };
        assert_eq! { true, ok_unquoted("aa09_-") };
    }

    #[test]
    fn test_display_key() {
        let chk = |exp, path: &[PathEntry]| {
            assert_eq! { DisfavouredKey { path: path.into() }.to_string(), exp };
        };
        let me = |s: &str| PathEntry::MapEntry(s.into());
        use PathEntry::ArrayIndex as AI;

        chk(r#""""#, &[]);
        chk(r#""@""#, &[me("@")]);
        chk(r#""\\""#, &[me(r#"\"#)]);
        chk(r#"foo"#, &[me("foo")]);
        chk(r#"foo.bar"#, &[me("foo"), me("bar")]);
        chk(r#"foo[10]"#, &[me("foo"), AI(10)]);
        chk(r#"[10].bar"#, &[AI(10), me("bar")]); // weird
    }

    #[derive(Debug, Clone, Builder, Eq, PartialEq)]
    #[builder(build_fn(error = "ConfigBuildError"))]
    #[builder(derive(Debug, Serialize, Deserialize))]
    struct TestConfigA {
        #[builder(default)]
        a: String,
    }
    impl_standard_builder! { TestConfigA }
    impl TopLevel for TestConfigA {
        type Builder = TestConfigABuilder;
    }

    #[derive(Debug, Clone, Builder, Eq, PartialEq)]
    #[builder(build_fn(error = "ConfigBuildError"))]
    #[builder(derive(Debug, Serialize, Deserialize))]
    struct TestConfigB {
        #[builder(default)]
        b: String,

        #[builder(default)]
        old: bool,
    }
    impl_standard_builder! { TestConfigB }
    impl TopLevel for TestConfigB {
        type Builder = TestConfigBBuilder;
        const DEPRECATED_KEYS: &'static [&'static str] = &["old"];
    }

    #[test]
    fn test_resolve() {
        let test_data = r#"
            wombat = 42
            a = "hi"
            old = true
        "#;
        let cfg = {
            let mut sources = crate::ConfigurationSources::new_empty();
            sources.push_source(
                crate::ConfigurationSource::from_verbatim(test_data.to_string()),
                crate::sources::MustRead::MustRead,
            );
            sources.load().unwrap()
        };

        let _: (TestConfigA, TestConfigB) = resolve_ignore_warnings(cfg.clone()).unwrap();

        let resolved: ResolutionResults<(TestConfigA, TestConfigB)> =
            resolve_return_results(cfg).unwrap();
        let (a, b) = resolved.value;

        let mk_strings =
            |l: Vec<DisfavouredKey>| l.into_iter().map(|ik| ik.to_string()).collect_vec();

        let ign = mk_strings(resolved.unrecognized);
        let depr = mk_strings(resolved.deprecated);

        assert_eq! { &a, &TestConfigA { a: "hi".into() } };
        assert_eq! { &b, &TestConfigB { b: "".into(), old: true } };
        assert_eq! { ign, &["wombat"] };
        assert_eq! { depr, &["old"] };

        let _ = TestConfigA::builder();
        let _ = TestConfigB::builder();
    }

    #[derive(Debug, Clone, Builder, Eq, PartialEq)]
    #[builder(build_fn(error = "ConfigBuildError"))]
    #[builder(derive(Debug, Serialize, Deserialize))]
    struct TestConfigC {
        #[builder(default)]
        c: u32,
    }
    impl_standard_builder! { TestConfigC }
    impl TopLevel for TestConfigC {
        type Builder = TestConfigCBuilder;
    }

    #[test]
    fn build_error() {
        // Make sure that errors are propagated correctly.
        let test_data = r#"
            # wombat is not a number.
            c = "wombat"
            # this _would_ be unrecognized, but for the errors.
            persimmons = "sweet"
        "#;
        // suppress a dead-code warning.
        let _b = TestConfigC::builder();

        let cfg = {
            let mut sources = crate::ConfigurationSources::new_empty();
            sources.push_source(
                crate::ConfigurationSource::from_verbatim(test_data.to_string()),
                crate::sources::MustRead::MustRead,
            );
            sources.load().unwrap()
        };

        {
            // First try "A", then "C".
            let res1: Result<ResolutionResults<(TestConfigA, TestConfigC)>, _> =
                resolve_return_results(cfg.clone());
            assert!(res1.is_err());
            assert!(matches!(res1, Err(ConfigResolveError::Deserialize(_))));
        }
        {
            // Now the other order: first try "C", then "A".
            let res2: Result<ResolutionResults<(TestConfigC, TestConfigA)>, _> =
                resolve_return_results(cfg.clone());
            assert!(res2.is_err());
            assert!(matches!(res2, Err(ConfigResolveError::Deserialize(_))));
        }
        // Try manually, to make sure unrecognized fields are removed.
        let mut ctx = ResolveContext {
            input: cfg,
            unrecognized: UnrecognizedKeys::AllKeys,
        };
        let _res3 = TestConfigA::resolve(&mut ctx);
        // After resolving A, some fields are unrecognized.
        assert!(matches!(&ctx.unrecognized, UnrecognizedKeys::These(k) if !k.is_empty()));
        {
            let res4 = TestConfigC::resolve(&mut ctx);
            assert!(matches!(res4, Err(ConfigResolveError::Deserialize(_))));
        }
        {
            // After resolving C with an error, the unrecognized-field list is cleared.
            assert!(matches!(&ctx.unrecognized, UnrecognizedKeys::These(k) if k.is_empty()));
        }
    }
}
