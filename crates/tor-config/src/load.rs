//! Processing a config::Config into a validated configuration
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), anyhow::Error> {
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

use itertools::{chain, izip, Itertools};
use serde::de::DeserializeOwned;
use thiserror::Error;
use tracing::warn;

use crate::ConfigBuildError;

/// Error resolveing a configuration (during deserialize, or build)
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ConfigResolveError {
    /// Deserialize failed
    #[error("config contents not as expected: {0}")]
    Deserialize(#[from] config::ConfigError),

    /// Build failed
    #[error("config semantically incorrect: {0}")]
    Build(#[from] ConfigBuildError),
}

/// A type that can be built from a builder via a build method
pub trait Builder {
    ///
    type Built;
    /// Build into a `Built`
    ///
    /// Often shadows an inherent `build` method
    fn build(&self) -> Result<Self::Built, ConfigBuildError>;
}

/// Collection of configuration settings that can be deseriealized and then built
///
/// *Do not implement directly.*
/// Instead, implement [`TopLevel`]: this engages the blanket impl
/// for (loosely) `TopLevel + Builder`.
///
/// Each `Resolvable` corresponds to one or more configuration consumers.
///
/// Ultimately, one `Resolvable` for all the configuration consumers in an entire
/// program will be resolved from a single configuration tree (usually parsed from TOML).
///
/// Multiple config collections can be resolved from the same configuartion,
/// via the implementation of `Resolvable` on tuples of `Resolvable`s.
/// Use this rather than `#[serde(flatten)]`; the latter prevents useful introspection
/// (necessary for reporting ignored configuration keys, and testing).
///
/// (The `resolve` method will be called only from within the `tor_config::load` module.)
pub trait Resolvable: Sized {
    /// Deserialize and build from a configuration
    fn resolve(input: &mut ResolveContext) -> Result<Self, ConfigResolveError>;
}

/// Top-level configuration struct, made from a deserializable builder
///
/// One configuration consumer's configuration settings.
///
/// Implementing this trait only for top-level configurations,
/// which are to be parsed at the root level of a (TOML) config file taxonomy.
pub trait TopLevel {
    /// The `Builder` which can be used to make a `Self`
    ///
    /// Should satisfy `&'_ Self::Builder: Builder<Built=Self>`
    type Builder: DeserializeOwned;
}

/// `define_for_tuples!{ A B - C D.. }`
///
/// expands to
///  1. `define_for_tuples!{ A B - }`: defines for tuple `(A,B,)`
///  2. `define_for_tuples!{ A B C - D.. }`: recurses to geenrate longer tuples
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
        }

    };
}
define_for_tuples! { A - B C D E }

/// Config resolultion context, not used outside `tor_config::load`
///
/// This is public only because it appears in the [`Resolvable`] trait.
/// You don't want to try to obtain one.
pub struct ResolveContext {
    ///
    input: config::Config,

    /// Paths ignored by all deserializations
    ///
    /// None means we haven't deserialized anything yet, ie means the universal set.
    ///
    /// Empty is used to disable this feature.
    ignored: Option<BTreeSet<IgnoredKey>>,
}

/// Key in config file(s) ignored by all Resolvables we obtained
///
/// `Display`s in an approximation to TOML format.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct IgnoredKey {
    /// Can be empty only before returned from this module
    path: Vec<PathEntry>,
}

/// Element of an IgnoredKey
#[derive(Debug, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
enum PathEntry {
    ///
    ArrayIndex(usize),
    /// string value is unquoted, needs quoting for display
    MapEntry(String),
}

///
fn resolve_inner<T>(
    input: config::Config,
    want_ignored: bool,
) -> Result<(T, Vec<IgnoredKey>), ConfigResolveError>
where
    T: Resolvable,
{
    let mut lc = ResolveContext {
        input,
        ignored: if want_ignored {
            None
        } else {
            Some(BTreeSet::new())
        },
    };
    let val = Resolvable::resolve(&mut lc)?;
    let ign = lc
        .ignored
        .expect("all ignored, as if we had processed nothing")
        .into_iter()
        .filter(|ip| !ip.path.is_empty())
        .collect_vec();
    Ok((val, ign))
}

/// Deserialize and build overall configuration from config sources
///
/// Ignored config keys are reported as log warning messages.
///
/// Resolve the whole configuration in one go, using the `Resolvable` impl on `(A,B)`
/// if necessary, so that ignored config key processing works correctly.
pub fn resolve<T>(input: config::Config) -> Result<T, ConfigResolveError>
where
    T: Resolvable,
{
    let (val, ign) = resolve_inner(input, true)?;
    for ign in ign {
        warn!("ignored configuration key: {}", &ign);
    }
    Ok(val)
}

/// Deserialize and build overall configuration, reporting ignored keys in the return value
pub fn resolve_and_ignored<T>(
    input: config::Config,
) -> Result<(T, Vec<IgnoredKey>), ConfigResolveError>
where
    T: Resolvable,
{
    resolve_inner(input, true)
}

/// Deserialize and build overall configuration, silently ignoring ignored config keys
pub fn resolve_without_ignored<T>(input: config::Config) -> Result<T, ConfigResolveError>
where
    T: Resolvable,
{
    Ok(resolve_inner(input, false)?.0)
}

impl<T> Resolvable for T
where
    T: TopLevel,
    T::Builder: Builder<Built = Self>,
{
    fn resolve(input: &mut ResolveContext) -> Result<T, ConfigResolveError> {
        let deser = input.input.clone();
        let builder: T::Builder = {
            // Recall that input.ignored == None
            // conceptually means "all keys have been ignored, up to now".
            // If input.ignored == Some(default()) then we don't bother tracking the
            // ignored keys since we would intersect with the empty set.
            // That is how this tracking is disabled when we want it to be.
            let want_ignored = if let Some(oign) = &input.ignored {
                !oign.is_empty()
            } else {
                true
            };
            let ret = if !want_ignored {
                deser.try_deserialize()
            } else {
                let mut nign = BTreeSet::new();
                let mut recorder = |path: serde_ignored::Path<'_>| {
                    nign.insert(copy_path(&path));
                };
                let deser = serde_ignored::Deserializer::new(deser, &mut recorder);
                let ret = serde::Deserialize::deserialize(deser);
                if ret.is_err() {
                    // If we got an error, tbe config might only have been partially processed,
                    // so we might get false positives.  Disable the ignored tracking.
                    nign = BTreeSet::new();
                }
                input.ignored = Some(if let Some(oign) = input.ignored.take() {
                    intersect_ignored_lists(oign, nign)
                } else {
                    // input.ignored = universal set, so the intersection is nign
                    nign
                });
                ret
            };
            ret?
        };
        let built = (&builder).build()?;
        Ok(built)
    }
}

/// Turns a [`serde_ignored::Path`] (which is borrowed) into an owned `IgnoredKey`
fn copy_path(mut path: &serde_ignored::Path) -> IgnoredKey {
    use serde_ignored::Path as SiP;
    use PathEntry as PE;

    let mut descend = vec![];
    loop {
        let ent;
        (path, ent) = match path {
            SiP::Root => break,
            SiP::Seq { parent, index } => (parent, Some(PE::ArrayIndex(*index))),
            SiP::Map { parent, key } => (parent, Some(PE::MapEntry(key.clone()))),
            SiP::Some { parent }
            | SiP::NewtypeStruct { parent }
            | SiP::NewtypeVariant { parent } => (parent, None),
        };
        descend.extend(ent);
    }
    descend.reverse();
    IgnoredKey { path: descend }
}

/// Computes the intersection, resolving ignorances at different depths
///
/// Eg if `a` contains `application.wombat` and `b` contains `application`,
/// we need to return `application.wombat`.
fn intersect_ignored_lists(
    al: BTreeSet<IgnoredKey>,
    bl: BTreeSet<IgnoredKey>,
) -> BTreeSet<IgnoredKey> {
    //eprintln!("INTERSECT:");
    //for ai in &al { eprintln!("A: {}", ai); }
    //for bi in &bl { eprintln!("B: {}", bi); }

    // This function is written to never talk about "a" and "b".
    // That (i) avoids duplication of code for handling a<b vs a>b, etc.
    // (ii) make impossible bugs where a was written but b was intended, etc.
    // The price is that the result is iterator combinator soup.

    let mut inputs: [_; 2] = [al, bl].map(|input| input.into_iter().peekable());
    let mut output = BTreeSet::new();

    // The BTreeSets produce items in sort order.  Peek one from each, while we can.
    while let Ok(items) = {
        // Ideally we would use array::try_map but it's nightly-only
        <[_; 2]>::try_from(
            inputs
                .iter_mut()
                .map(|input: &'_ mut _| input.peek())
                .into_iter()
                .flatten()
                .collect::<Vec<_>>(),
        )
    } {
        let prefix_len = items.iter().map(|i| i.path.len()).min().expect("wrong #");
        let earlier_i = items
            .iter()
            .enumerate()
            .min_by_key(|&(_i, item)| *item)
            .expect("wrong #")
            .0;
        let later_i = 1 - earlier_i;

        if items.iter().all_equal() {
            // Take the identical items off the front of both iters,
            // and put one into the output (the last will do nicely).
            //dbg!(items);
            let item = inputs
                .iter_mut()
                .map(|input| input.next().expect("but peekedr"))
                .last()
                .expect("wrong #");
            output.insert(item);
            continue;
        } else if items
            .iter()
            .map(|item| &item.path[0..prefix_len])
            .all_equal()
        {
            // They both have the same prefix.   earlier_i is the shorter one.
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
            // The items are just different.  Eat the earlier one.
            //dbg!(items, earlier_i);
            let _ = inputs[earlier_i].next().expect("but peeked");
        }
    }

    //for oi in &ol { eprintln!("O: {}", oi); }
    output
}

impl Display for IgnoredKey {
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
#[allow(clippy::unwrap_used)] // OK in tests
mod test {
    use super::*;
    use crate::*;
    use derive_builder::Builder;
    use serde::{Deserialize, Serialize};

    fn parse_test_set(l: &[&str]) -> BTreeSet<IgnoredKey> {
        l.iter()
            .map(|s| IgnoredKey {
                path: s
                    .split('.')
                    .map(|s| PathEntry::MapEntry(s.into()))
                    .collect_vec(),
            })
            .collect()
    }

    #[test]
    #[rustfmt::skip] // preserve the layout so we can match vertically by eye
    fn test_intersect_ignored_list() {
        let chk = |a, b, exp| {
            let got = intersect_ignored_lists(parse_test_set(a), parse_test_set(b));
            let exp = parse_test_set(exp);
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
            assert_eq! { IgnoredKey { path: path.into() }.to_string(), exp };
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
    }
    impl_standard_builder! { TestConfigB }
    impl TopLevel for TestConfigB {
        type Builder = TestConfigBBuilder;
    }

    #[test]
    fn test_resolve() {
        let test_data = r#"
            wombat = 42
            a = "hi"
        "#;
        let source = config::File::from_str(test_data, config::FileFormat::Toml);

        let cfg = config::Config::builder()
            .add_source(source)
            .build()
            .unwrap();

        let _: (TestConfigA, TestConfigB) = resolve_without_ignored(cfg.clone()).unwrap();

        let ((a, b), ign): ((TestConfigA, TestConfigB), _) = resolve_and_ignored(cfg).unwrap();

        let ign = ign.into_iter().map(|ik| ik.to_string()).collect_vec();

        assert_eq! { &a, &TestConfigA { a: "hi".into() } };
        assert_eq! { &b, &TestConfigB { b: "".into() } };
        assert_eq! { ign, &["wombat"] };

        let _ = TestConfigA::builder();
        let _ = TestConfigB::builder();
    }
}
