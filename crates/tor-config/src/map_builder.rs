//! Helper for defining sub-builders that map a serializable type (typically String)
//! to a configuration type.

/// Define a map type, and an associated builder struct, suitable for use in a configuration object.
///
/// We use this macro when we want a configuration structure to contain a key-to-value map,
/// and therefore we want its associated builder structure to contain
/// a map from the same key type to a value-builder type.
///
/// The key of the map type must implement `Serialize`, `Clone`, and `Debug`.
/// The value of the map type must have an associated "Builder"
/// type formed by appending `Builder` to its name.
/// This Builder type must implement `Serialize`, `Deserialize`, `Clone`, and `Debug`,
/// and it must have a `build(&self)` method returning `Result<value, ConfigBuildError>`.
///
/// # Syntax and behavior
///
/// ```ignore
/// define_map_builder! {
///     BuilderAttributes
///     pub struct BuilderName =>
///
///     MapAttributes
///     pub type MapName = ContainerType<KeyType, ValueType>;
/// }
/// ```
///
/// In the example above,
///
/// * BuilderName, MapName, and ContainerType may be replaced with any identifier;
/// * BuilderAttributes and MapAttributes can be replaced with any set of attributes
///   (such sa doc comments, `#derive`, and so on);
/// * The `pub`s may be replaced with any visibility;
/// * and `KeyType` and `ValueType` may be replaced with any appropriate types.
///
/// Given this syntax, this macro will define "MapType" as an alias for
/// `Container<KeyType,ValueType>`,
/// and "BuilderName" as a builder type for that container.
///
/// "BuilderName" will implement:
///  * `Deref` and `DerefMut` with a target type of `Container<KeyType, ValueTypeBuilder>`
///  * `Default`, `Clone`, and `Debug`.
///  * `Serialize` and `Deserialize`
///  * A `build()` function that invokes `build()` on every value in its contained map.
///
/// (Note that in order to work as a sub-builder within our configuration system,
/// "BuilderName" should be the same as "MapName" concatenated with "Builder.")
///
/// # Example
///
/// ```
/// # use derive_builder::Builder;
/// # use derive_deftly::Deftly;
/// # use std::collections::BTreeMap;
/// # use tor_config::{ConfigBuildError, define_map_builder, derive_deftly_template_ExtendBuilder};
/// # use serde::{Serialize, Deserialize};
/// #[derive(Clone, Debug, Builder)]
/// #[builder(build_fn(error = "ConfigBuildError"))]
/// #[builder(derive(Debug, Serialize, Deserialize))]
/// pub struct StampCollectionConfig {
///     #[builder(sub_builder)]
///     stamps: StampMap
/// }
///
/// define_map_builder! {
///     pub struct StampMapBuilder =>
///     pub type StampMap = BTreeMap<String, StampConfig>;
/// }
///
/// #[derive(Clone, Debug, Builder, Deftly)]
/// #[derive_deftly(ExtendBuilder)]
/// #[builder(build_fn(error = "ConfigBuildError"))]
/// #[builder(derive(Debug, Serialize, Deserialize))]
/// pub struct StampConfig {
///     description: String,
///     year: u32,
/// }
/// ```
///
/// # Notes and rationale
///
/// We use this macro, instead of using a Map directly in our configuration object,
/// so that we can have a separate Builder type with a reasonable build() implementation.
///
/// XXXX Describe default behavior here once we have it implemented.
///
/// We don't support complicated keys; instead we require that the keys implement Deserialize.
/// If we ever need to support keys with their own builders,
/// we'll have to define a new macro.
#[macro_export]
macro_rules! define_map_builder {
    {
        $(#[ $b_m:meta ])*
        $b_v:vis struct $btype:ident =>
        $(#[ $m:meta ])*
        $v:vis type $maptype:ident = $coltype:ident < $keytype:ty , $valtype: ty >;
    } =>
    {paste::paste!{
        $(#[ $m ])*
        $v type $maptype = $coltype < $keytype , $valtype > ;

        $(#[ $b_m ])*
        #[derive(Clone,Debug,$crate::deps::serde::Deserialize, $crate::deps::serde::Serialize, $crate::deps::educe::Educe)]
        #[educe(Deref, DerefMut, Default)]
        #[serde(transparent)]
        $b_v struct $btype( $coltype < $keytype, [<$valtype Builder>] > );

        impl $btype {
            $b_v fn build(&self) -> ::std::result::Result<$maptype, $crate::ConfigBuildError> {
                self.0
                    .iter()
                    .map(|(k,v)| Ok((k.clone(), v.build()?)))
                    .collect()
            }
        }
    }}
}
// XXXX: Need a way to make an initial value for serde and for Default.
// Options:
//   - Use our "stacked config" logic for serde, and duplicate the default in Default.
//   - Define a fancy Deserialize that works by updating our default.

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

    use crate::ConfigBuildError;
    use derive_builder::Builder;
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

    #[derive(Clone, Debug, Eq, PartialEq, Builder)]
    #[builder(derive(Deserialize, Serialize, Debug))]
    #[builder(build_fn(error = "ConfigBuildError"))]
    struct Outer {
        #[builder(sub_builder(fn_name = "build"))]
        #[builder_field_attr(serde(default))]
        things: ThingMap,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Builder)]
    #[builder(derive(Deserialize, Serialize, Debug))]
    #[builder(build_fn(error = "ConfigBuildError"))]
    struct Inner {
        #[builder(default)]
        fun: bool,
        #[builder(default)]
        explosive: bool,
    }

    define_map_builder! {
        struct ThingMapBuilder =>
        type ThingMap = BTreeMap<String, Inner>;
    }

    #[test]
    fn parse_and_build() {
        let builder: OuterBuilder = toml::from_str(
            r#"
[things.x]
fun = true
explosive = false

[things.yy]
explosive = true
fun = true
"#,
        )
        .unwrap();

        let built = builder.build().unwrap();
        assert_eq!(
            built.things.get("x").unwrap(),
            &Inner {
                fun: true,
                explosive: false
            }
        );
        assert_eq!(
            built.things.get("yy").unwrap(),
            &Inner {
                fun: true,
                explosive: true
            }
        );
    }

    #[test]
    fn build_directly() {
        let mut builder = OuterBuilder::default();
        let mut bld = InnerBuilder::default();
        bld.fun(true);
        builder.things().insert("x".into(), bld);
        let built = builder.build().unwrap();
        assert_eq!(
            built.things.get("x").unwrap(),
            &Inner {
                fun: true,
                explosive: false
            }
        );
    }
}
