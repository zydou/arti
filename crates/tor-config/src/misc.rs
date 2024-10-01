//! Miscellaneous types used in configuration
//!
//! This module contains types that need to be shared across various crates
//! and layers, but which don't depend on specific elements of the Tor system.

use std::borrow::Cow;
use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use strum::{Display, EnumString, IntoStaticStr};

/// Boolean, but with additional `"auto"` option
//
// This slightly-odd interleaving of derives and attributes stops rustfmt doing a daft thing
#[derive(Clone, Copy, Hash, Debug, Default, Ord, PartialOrd, Eq, PartialEq)]
#[allow(clippy::exhaustive_enums)] // we will add variants very rarely if ever
#[derive(Serialize, Deserialize)]
#[serde(try_from = "BoolOrAutoSerde", into = "BoolOrAutoSerde")]
pub enum BoolOrAuto {
    #[default]
    /// Automatic
    Auto,
    /// Explicitly specified
    Explicit(bool),
}

impl BoolOrAuto {
    /// Returns the explicitly set boolean value, or `None`
    ///
    /// ```
    /// use tor_config::BoolOrAuto;
    ///
    /// fn calculate_default() -> bool { //...
    /// # false }
    /// let bool_or_auto: BoolOrAuto = // ...
    /// # Default::default();
    /// let _: bool = bool_or_auto.as_bool().unwrap_or_else(|| calculate_default());
    /// ```
    pub fn as_bool(self) -> Option<bool> {
        match self {
            BoolOrAuto::Auto => None,
            BoolOrAuto::Explicit(v) => Some(v),
        }
    }
}

/// How we (de) serialize a [`BoolOrAuto`]
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum BoolOrAutoSerde {
    /// String (in snake case)
    String(Cow<'static, str>),
    /// bool
    Bool(bool),
}

impl From<BoolOrAuto> for BoolOrAutoSerde {
    fn from(boa: BoolOrAuto) -> BoolOrAutoSerde {
        use BoolOrAutoSerde as BoAS;
        boa.as_bool()
            .map(BoAS::Bool)
            .unwrap_or_else(|| BoAS::String("auto".into()))
    }
}

/// Boolean or `"auto"` configuration is invalid
#[derive(thiserror::Error, Debug, Clone)]
#[non_exhaustive]
#[error(r#"Invalid value, expected boolean or "auto""#)]
pub struct InvalidBoolOrAuto {}

impl TryFrom<BoolOrAutoSerde> for BoolOrAuto {
    type Error = InvalidBoolOrAuto;

    fn try_from(pls: BoolOrAutoSerde) -> Result<BoolOrAuto, Self::Error> {
        use BoolOrAuto as BoA;
        use BoolOrAutoSerde as BoAS;
        Ok(match pls {
            BoAS::Bool(v) => BoA::Explicit(v),
            BoAS::String(s) if s == "false" => BoA::Explicit(false),
            BoAS::String(s) if s == "true" => BoA::Explicit(true),
            BoAS::String(s) if s == "auto" => BoA::Auto,
            _ => return Err(InvalidBoolOrAuto {}),
        })
    }
}

/// A macro that implements [`NotAutoValue`] for your type.
///
/// This macro generates:
///   * a [`NotAutoValue`] impl for `ty`
///   * a test module with a test that ensures "auto" cannot be deserialized as `ty`
///
/// ## Example
///
/// ```rust
/// # use tor_config::{impl_not_auto_value, ExplicitOrAuto};
/// # use serde::{Serialize, Deserialize};
//  #
/// #[derive(Serialize, Deserialize)]
/// struct Foo;
///
/// impl_not_auto_value!(Foo);
///
/// #[derive(Serialize, Deserialize)]
/// struct Bar;
///
/// fn main() {
///    let _foo: ExplicitOrAuto<Foo> = ExplicitOrAuto::Auto;
///
///    // Using a type that does not implement NotAutoValue is an error:
///    // let _bar: ExplicitOrAuto<Bar> = ExplicitOrAuto::Auto;
/// }
/// ```
#[macro_export]
macro_rules! impl_not_auto_value {
    ($ty:ty) => {
        $crate::deps::paste! {
            impl $crate::NotAutoValue for $ty {}

            #[cfg(test)]
            #[allow(non_snake_case)]
            mod [<test_not_auto_value_ $ty>] {
                #[allow(unused_imports)]
                use super::*;

                #[test]
                fn [<auto_is_not_a_valid_value_for_ $ty>]() {
                    let res = $crate::deps::serde_value::Value::String(
                        "auto".into()
                    ).deserialize_into::<$ty>();

                    assert!(
                        res.is_err(),
                        concat!(
                            stringify!($ty), " is not a valid NotAutoValue type: ",
                            "NotAutoValue types should not be deserializable from \"auto\""
                        ),
                    );
                }
            }
        }
    };
}

/// A serializable value, or auto.
///
/// Used for implementing configuration options that can be explicitly initialized
/// with a placeholder for their "default" value using the
/// [`Auto`](ExplicitOrAuto::Auto) variant.
///
/// Unlike `#[serde(default)] field: T` or `#[serde(default)] field: Option<T>`,
/// fields of this type can be present in the serialized configuration
/// without being assigned a concrete value.
///
/// **Important**: the underlying type must implement [`NotAutoValue`].
/// This trait should be implemented using the [`impl_not_auto_value`],
/// and only for types that do not serialize to the same value as the
/// [`Auto`](ExplicitOrAuto::Auto) variant.
///
/// ## Example
///
/// In the following serialized TOML config
///
/// ```toml
///  foo = "auto"
/// ```
///
/// `foo` is set to [`Auto`](ExplicitOrAuto::Auto), which indicates the
/// implementation should use a default (but not necessarily [`Default::default`])
/// value for the `foo` option.
///
/// For example, f field `foo` defaults to `13` if feature `bar` is enabled,
/// and `9000` otherwise, a configuration with `foo` set to `"auto"` will
/// behave in the "default" way regardless of which features are enabled.
///
/// ```rust,ignore
/// struct Foo(usize);
///
/// impl Default for Foo {
///     fn default() -> Foo {
///         if cfg!(feature = "bar") {
///             Foo(13)
///         } else {
///             Foo(9000)
///         }
///     }
/// }
///
/// impl Foo {
///     fn from_explicit_or_auto(foo: ExplicitOrAuto<Foo>) -> Self {
///         match foo {
///             // If Auto, choose a sensible default for foo
///             ExplicitOrAuto::Auto => Default::default(),
///             ExplicitOrAuto::Foo(foo) => foo,
///         }
///     }
/// }
///
/// struct Config {
///    foo: ExplicitOrAuto<Foo>,
/// }
/// ```
#[derive(Clone, Copy, Hash, Debug, Default, Ord, PartialOrd, Eq, PartialEq)]
#[allow(clippy::exhaustive_enums)] // we will add variants very rarely if ever
#[derive(Serialize, Deserialize)]
pub enum ExplicitOrAuto<T: NotAutoValue> {
    /// Automatic
    #[default]
    #[serde(rename = "auto")]
    Auto,
    /// Explicitly specified
    #[serde(untagged)]
    Explicit(T),
}

impl<T: NotAutoValue> ExplicitOrAuto<T> {
    /// Returns the explicitly set value, or `None`.
    ///
    /// ```
    /// use tor_config::ExplicitOrAuto;
    ///
    /// fn calculate_default() -> usize { //...
    /// # 2 }
    /// let explicit_or_auto: ExplicitOrAuto<usize> = // ...
    /// # Default::default();
    /// let _: usize = explicit_or_auto.into_value().unwrap_or_else(|| calculate_default());
    /// ```
    pub fn into_value(self) -> Option<T> {
        match self {
            ExplicitOrAuto::Auto => None,
            ExplicitOrAuto::Explicit(v) => Some(v),
        }
    }

    /// Returns a reference to the explicitly set value, or `None`.
    ///
    /// Like [`ExplicitOrAuto::into_value`], except it returns a reference to the inner type.
    pub fn as_value(&self) -> Option<&T> {
        match self {
            ExplicitOrAuto::Auto => None,
            ExplicitOrAuto::Explicit(v) => Some(v),
        }
    }
}

/// A marker trait for types that do not serialize to the same value as [`ExplicitOrAuto::Auto`].
///
/// **Important**: you should not implement this trait manually.
/// Use the [`impl_not_auto_value`] macro instead.
///
/// This trait should be implemented for types that can be stored in [`ExplicitOrAuto`].
pub trait NotAutoValue {}

/// A helper for calling [`impl_not_auto_value`] for a number of types.
macro_rules! impl_not_auto_value_for_types {
    ($($ty:ty)*) => {
        $(impl_not_auto_value!($ty);)*
    }
}

// Implement `NotAutoValue` for various primitive types.
impl_not_auto_value_for_types!(
    i8 i16 i32 i64 i128 isize
    u8 u16 u32 u64 u128 usize
    f32 f64
    char
    bool
);

// TODO implement `NotAutoValue` for other types too

/// Padding enablement - rough amount of padding requested
///
/// Padding is cover traffic, used to help mitigate traffic analysis,
/// obscure traffic patterns, and impede router-level data collection.
///
/// This same enum is used to control padding at various levels of the Tor system.
/// (TODO: actually we don't do circuit padding yet.)
//
// This slightly-odd interleaving of derives and attributes stops rustfmt doing a daft thing
#[derive(Clone, Copy, Hash, Debug, Ord, PartialOrd, Eq, PartialEq)]
#[allow(clippy::exhaustive_enums)] // we will add variants very rarely if ever
#[derive(Serialize, Deserialize)]
#[serde(try_from = "PaddingLevelSerde", into = "PaddingLevelSerde")]
#[derive(Display, EnumString, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
#[derive(Default)]
pub enum PaddingLevel {
    /// Disable padding completely
    None,
    /// Reduced padding (eg for mobile)
    Reduced,
    /// Normal padding (the default)
    #[default]
    Normal,
}

/// How we (de) serialize a [`PaddingLevel`]
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum PaddingLevelSerde {
    /// String (in snake case)
    ///
    /// We always serialize this way
    String(Cow<'static, str>),
    /// bool
    Bool(bool),
}

impl From<PaddingLevel> for PaddingLevelSerde {
    fn from(pl: PaddingLevel) -> PaddingLevelSerde {
        PaddingLevelSerde::String(<&str>::from(&pl).into())
    }
}

/// Padding level configuration is invalid
#[derive(thiserror::Error, Debug, Clone)]
#[non_exhaustive]
#[error("Invalid padding level")]
struct InvalidPaddingLevel {}

impl TryFrom<PaddingLevelSerde> for PaddingLevel {
    type Error = InvalidPaddingLevel;

    fn try_from(pls: PaddingLevelSerde) -> Result<PaddingLevel, Self::Error> {
        Ok(match pls {
            PaddingLevelSerde::String(s) => {
                s.as_ref().try_into().map_err(|_| InvalidPaddingLevel {})?
            }
            PaddingLevelSerde::Bool(false) => PaddingLevel::None,
            PaddingLevelSerde::Bool(true) => PaddingLevel::Normal,
        })
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

    #[derive(Debug, Default, Deserialize, Serialize)]
    struct TestConfigFile {
        #[serde(default)]
        something_enabled: BoolOrAuto,

        #[serde(default)]
        padding: PaddingLevel,

        #[serde(default)]
        auto_or_usize: ExplicitOrAuto<usize>,

        #[serde(default)]
        auto_or_bool: ExplicitOrAuto<bool>,
    }

    #[test]
    fn bool_or_auto() {
        use BoolOrAuto as BoA;

        let chk = |pl, s| {
            let tc: TestConfigFile = toml::from_str(s).expect(s);
            assert_eq!(pl, tc.something_enabled, "{:?}", s);
        };

        chk(BoA::Auto, "");
        chk(BoA::Auto, r#"something_enabled = "auto""#);
        chk(BoA::Explicit(true), r#"something_enabled = true"#);
        chk(BoA::Explicit(true), r#"something_enabled = "true""#);
        chk(BoA::Explicit(false), r#"something_enabled = false"#);
        chk(BoA::Explicit(false), r#"something_enabled = "false""#);

        let chk_e = |s| {
            let tc: Result<TestConfigFile, _> = toml::from_str(s);
            let _ = tc.expect_err(s);
        };

        chk_e(r#"something_enabled = 1"#);
        chk_e(r#"something_enabled = "unknown""#);
        chk_e(r#"something_enabled = "True""#);
    }

    #[test]
    fn padding_level() {
        use PaddingLevel as PL;

        let chk = |pl, s| {
            let tc: TestConfigFile = toml::from_str(s).expect(s);
            assert_eq!(pl, tc.padding, "{:?}", s);
        };

        chk(PL::None, r#"padding = "none""#);
        chk(PL::None, r#"padding = false"#);
        chk(PL::Reduced, r#"padding = "reduced""#);
        chk(PL::Normal, r#"padding = "normal""#);
        chk(PL::Normal, r#"padding = true"#);
        chk(PL::Normal, "");

        let chk_e = |s| {
            let tc: Result<TestConfigFile, _> = toml::from_str(s);
            let _ = tc.expect_err(s);
        };

        chk_e(r#"padding = 1"#);
        chk_e(r#"padding = "unknown""#);
        chk_e(r#"padding = "Normal""#);
    }

    #[test]
    fn explicit_or_auto() {
        use ExplicitOrAuto as EOA;

        let chk = |eoa: EOA<usize>, s| {
            let tc: TestConfigFile = toml::from_str(s).expect(s);
            assert_eq!(
                format!("{:?}", eoa),
                format!("{:?}", tc.auto_or_usize),
                "{:?}",
                s
            );
        };

        chk(EOA::Auto, r#"auto_or_usize = "auto""#);
        chk(EOA::Explicit(20), r#"auto_or_usize = 20"#);

        let chk_e = |s| {
            let tc: Result<TestConfigFile, _> = toml::from_str(s);
            let _ = tc.expect_err(s);
        };

        chk_e(r#"auto_or_usize = """#);
        chk_e(r#"auto_or_usize = []"#);
        chk_e(r#"auto_or_usize = {}"#);

        let chk = |eoa: EOA<bool>, s| {
            let tc: TestConfigFile = toml::from_str(s).expect(s);
            assert_eq!(
                format!("{:?}", eoa),
                format!("{:?}", tc.auto_or_bool),
                "{:?}",
                s
            );
        };

        // ExplicitOrAuto<bool> works just like BoolOrAuto
        chk(EOA::Auto, r#"auto_or_bool = "auto""#);
        chk(EOA::Explicit(false), r#"auto_or_bool = false"#);

        chk_e(r#"auto_or_bool= "not bool or auto""#);

        let mut config = TestConfigFile::default();
        let toml = toml::to_string(&config).unwrap();
        assert_eq!(
            toml,
            r#"something_enabled = "auto"
padding = "normal"
auto_or_usize = "auto"
auto_or_bool = "auto"
"#
        );

        config.auto_or_bool = ExplicitOrAuto::Explicit(true);
        let toml = toml::to_string(&config).unwrap();
        assert_eq!(
            toml,
            r#"something_enabled = "auto"
padding = "normal"
auto_or_usize = "auto"
auto_or_bool = true
"#
        );
    }
}
