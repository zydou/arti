//! Processing a config::Config into a validated configuration

#![allow(dead_code)] // Will go away in a moment

use std::collections::BTreeSet;
use std::fmt::{self, Display};
use std::iter;

use itertools::{chain, izip, Itertools};
use serde::de::DeserializeOwned;
use thiserror::Error;

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
pub struct ResolveContext(config::Config);

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

/// Deserialize and build overall configuration from config sources
pub fn resolve<T>(input: config::Config) -> Result<T, ConfigResolveError>
where
    T: Resolvable,
{
    let mut lc = ResolveContext(input);
    Resolvable::resolve(&mut lc)
}

impl<T> Resolvable for T
where
    T: TopLevel,
    T::Builder: Builder<Built = Self>,
{
    fn resolve(input: &mut ResolveContext) -> Result<T, ConfigResolveError> {
        let builder: T::Builder = input.0.clone().try_deserialize()?;
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
