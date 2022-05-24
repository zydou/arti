//! Processing a config::Config into a validated configuration

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
