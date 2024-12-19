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
///
///     defaults: defaults_func(); // <--- this line is optional
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
///    * `ValueType` must have a corresponding `ValueTypeBuilder`.
///    * `ValueTypeBuilder` must implement
///      [`ExtendBuilder`](crate::extend_builder::ExtendBuilder).
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
/// The `defaults_func()`, if provided, must be
/// a function returning `ContainerType<KeyType, ValueType>`.
/// The values returned by `default_func()` map are used to implement
/// `Default` and `Deserialize` for `BuilderName`,
/// extending from the defaults with `ExtendStrategy::ReplaceLists`.
/// If no `defaults_func` is given, `ContainerType::default()` is used.
///
/// # Example
///
/// ```
/// # use derive_builder::Builder;
/// # use derive_deftly::Deftly;
/// # use std::collections::BTreeMap;
/// # use tor_config::{ConfigBuildError, define_map_builder, derive_deftly_template_ExtendBuilder};
/// # use serde::{Serialize, Deserialize};
/// # use tor_config::extend_builder::{ExtendBuilder,ExtendStrategy};
/// #[derive(Clone, Debug, Builder, Deftly, Eq, PartialEq)]
/// #[derive_deftly(ExtendBuilder)]
/// #[builder(build_fn(error = "ConfigBuildError"))]
/// #[builder(derive(Debug, Serialize, Deserialize))]
/// pub struct ConnectionsConfig {
///     #[builder(sub_builder)]
///     #[deftly(extend_builder(sub_builder))]
///     conns: ConnectionMap
/// }
///
/// define_map_builder! {
///     pub struct ConnectionMapBuilder =>
///     pub type ConnectionMap = BTreeMap<String, ConnConfig>;
/// }
///
/// #[derive(Clone, Debug, Builder, Deftly, Eq, PartialEq)]
/// #[derive_deftly(ExtendBuilder)]
/// #[builder(build_fn(error = "ConfigBuildError"))]
/// #[builder(derive(Debug, Serialize, Deserialize))]
/// pub struct ConnConfig {
///     #[builder(default="true")]
///     enabled: bool,
///     port: u16,
/// }
///
/// let defaults: ConnectionsConfigBuilder = toml::from_str(r#"
/// [conns."socks"]
/// enabled = true
/// port = 9150
///
/// [conns."http"]
/// enabled = false
/// port = 1234
///
/// [conns."wombat"]
/// port = 5050
/// "#).unwrap();
/// let user_settings: ConnectionsConfigBuilder = toml::from_str(r#"
/// [conns."http"]
/// enabled = false
/// [conns."quokka"]
/// enabled = true
/// port = 9999
/// "#).unwrap();
///
/// let mut cfg = defaults.clone();
/// cfg.extend_from(user_settings, ExtendStrategy::ReplaceLists);
/// let cfg = cfg.build().unwrap();
/// assert_eq!(cfg, ConnectionsConfig {
///     conns: vec![
///         ("http".into(), ConnConfig { enabled: false, port: 1234}),
///         ("quokka".into(), ConnConfig { enabled: true, port: 9999}),
///         ("socks".into(), ConnConfig { enabled: true, port: 9150}),
///         ("wombat".into(), ConnConfig { enabled: true, port: 5050}),
///     ].into_iter().collect(),
/// });
/// ```
///
/// In the example above, the `derive_map_builder` macro expands to something like:
///
/// ```ignore
/// pub type ConnectionMap = BTreeMap<String, ConnConfig>;
///
/// #[derive(Clone,Debug,Serialize,Educe)]
/// #[educe(Deref,DerefMut)]
/// pub struct ConnectionMapBuilder(BTreeMap<String, ConnConfigBuilder);
///
/// impl ConnectionMapBuilder {
///     fn build(&self) -> Result<ConnectionMap, ConfigBuildError> {
///         ...
///     }
/// }
/// impl Default for ConnectionMapBuilder { ... }
/// impl Deserialize for ConnectionMapBuilder { ... }
/// impl ExtendBuilder for ConnectionMapBuilder { ... }
/// ```
///
/// # Notes and rationale
///
/// We use this macro, instead of using a Map directly in our configuration object,
/// so that we can have a separate Builder type with a reasonable build() implementation.
///
/// We don't support complicated keys; instead we require that the keys implement Deserialize.
/// If we ever need to support keys with their own builders,
/// we'll have to define a new macro.
///
/// We use `ExtendBuilder` to implement Deserialize with defaults,
/// so that the provided configuration options can override
/// only those parts of the default configuration tree
/// that they actually replace.
#[macro_export]
macro_rules! define_map_builder {
    {
        $(#[ $b_m:meta ])*
        $b_v:vis struct $btype:ident =>
        $(#[ $m:meta ])*
        $v:vis type $maptype:ident = $coltype:ident < $keytype:ty , $valtype: ty >;
        $( defaults: $defaults:expr; )?
    } =>
    {paste::paste!{
        $(#[ $m ])*
        $v type $maptype = $coltype < $keytype , $valtype > ;

        $(#[ $b_m ])*
        #[derive(Clone,Debug,$crate::deps::serde::Serialize, $crate::deps::educe::Educe)]
        #[educe(Deref, DerefMut)]
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
        $(
            // This section is expanded when we have a defaults_fn().
            impl ::std::default::Default for $btype {
                fn default() -> Self {
                    Self($defaults)
                }
            }
            impl<'de> $crate::deps::serde::Deserialize<'de> for $btype {
                fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: $crate::deps::serde::Deserializer<'de> {
                        // To deserialize into this type, we create a builder holding the defaults,
                        // and we create a builder holding the values from the deserializer.
                        // We then use ExtendBuilder to extend the defaults with the deserialized values.
                        let deserialized = $coltype::<$keytype, [<$valtype Builder>]>::deserialize(deserializer)?;
                        let mut defaults = $btype::default();
                        $crate::extend_builder::ExtendBuilder::extend_from(
                            &mut defaults,
                            Self(deserialized),
                            $crate::extend_builder::ExtendStrategy::ReplaceLists);
                        Ok(defaults)
                    }
            }
        )?
        $crate::define_map_builder!{@if_empty { $($defaults)? } {
            // This section is expanded when we don't have a defaults_fn().
            impl ::std::default::Default for $btype {
                fn default() -> Self {
                    Self(Default::default())
                }
            }
            // We can't conditionally derive() here, since Rust doesn't like macros that expand to
            // attributes.
            impl<'de> $crate::deps::serde::Deserialize<'de> for $btype {
                fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: $crate::deps::serde::Deserializer<'de> {
                    Ok(Self($coltype::deserialize(deserializer)?))
                }
            }
        }}
        impl $crate::extend_builder::ExtendBuilder for $btype
        {
            fn extend_from(&mut self, other: Self, strategy: $crate::extend_builder::ExtendStrategy) {
                $crate::extend_builder::ExtendBuilder::extend_from(&mut self.0, other.0, strategy);
            }
        }
    }};
    {@if_empty {} {$($x:tt)*}} => {$($x)*};
    {@if_empty {$($y:tt)*} {$($x:tt)*}} => {};
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

    use crate::ConfigBuildError;
    use derive_builder::Builder;
    use derive_deftly::Deftly;
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

    #[derive(Clone, Debug, Eq, PartialEq, Builder, Deftly)]
    #[derive_deftly(ExtendBuilder)]
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

    define_map_builder! {
        struct ThingMap2Builder =>
        type ThingMap2 = BTreeMap<String, Inner>;
        defaults: thingmap2_default();
    }
    fn thingmap2_default() -> BTreeMap<String, InnerBuilder> {
        let mut map = BTreeMap::new();
        {
            let mut bld = InnerBuilder::default();
            bld.fun(true);
            map.insert("x".to_string(), bld);
        }
        {
            let mut bld = InnerBuilder::default();
            bld.explosive(true);
            map.insert("y".to_string(), bld);
        }
        map
    }
    #[test]
    fn with_defaults() {
        let mut tm2 = ThingMap2Builder::default();
        tm2.get_mut("x").unwrap().explosive(true);
        let mut bld = InnerBuilder::default();
        bld.fun(true);
        tm2.insert("zz".into(), bld);
        let built = tm2.build().unwrap();

        assert_eq!(
            built.get("x").unwrap(),
            &Inner {
                fun: true,
                explosive: true
            }
        );
        assert_eq!(
            built.get("y").unwrap(),
            &Inner {
                fun: false,
                explosive: true
            }
        );
        assert_eq!(
            built.get("zz").unwrap(),
            &Inner {
                fun: true,
                explosive: false
            }
        );

        let tm2: ThingMap2Builder = toml::from_str(
            r#"
            [x]
            explosive = true
            [zz]
            fun = true
            "#,
        )
        .unwrap();
        let built2 = tm2.build().unwrap();
        assert_eq!(built, built2);
    }
}
