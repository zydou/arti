//! Similar to `#[serde(flatten)]` but works with [`serde_ignored`]
//!
//! Our approach to deserialize a [`Flatten`] is as follows:
//!
//!  * We tell the input data format (underlying deserializer) that we want a map.
//!  * In our visitor, we visit each key in the map in order
//!  * For each key, we consult `Flattenable::has_field` to find out which child it's in
//!    (fields in T shadow fields in U, as with serde),
//!    and store the key and the value in the appropriate [`Portion`].
//!    (We must store the value as a [`serde_value::Value`]
//!    since we don't know what type it should be,
//!    and can't know until we are ready to enter T and U's [`Deserialize`] impls.)
//!  * If it's in neither T nor U, we explicitly ignore the value
//!  * When we've processed all the fields, we call the actual deserialisers for T and U:
//!    we take on the role of the data format, giving each of T and U a map.
//!
//! From the point of view of T and U, we each offer them a subset of the fields,
//! having already rendered the keys to strings and the values to `Value`.
//!
//! From the point of view of the data format (which might be a `serde_ignored` proxy)
//! we consume the union of the fields, and ignore the rest.
//!
//! ### Rationale and alternatives
//!
//! The key difficulty is this:
//! we want to call [`Deserializer::deserialize_ignored_any`]
//! on our input data format for precisely the fields which neither T nor U want.
//! We must achieve this somehow using information from T or U.
//! If we tried to use only the [`Deserialize`] impls,
//! the only way to detect this is to call their `deserialize` methods
//! and watch to see if they in turn call `deserialize_ignored_any`.
//! But we need to be asking each of T and U this question for each field:
//! the shape of [`MapAccess`] puts the data structure in charge of sequencing.
//! So we would need to somehow suspend `T`'s deserialisation,
//! and call `U`'s, and then suspend `U`s, and go back to `T`.
//!
//! Other possibilities that seemed worse:
//!
//!  * Use threads.
//!    We could spawn a thread for each of `T` and `U`,
//!    allowing us to run them in parallel and control their execution flow.
//!
//!  * Use coroutines eg. [corosensei](https://lib.rs/crates/corosensei)
//!    (by Amanieu, author of hashbrown etc.)
//!
//!  * Instead of suspending and restarting `T` and `U`'s deserialisation,
//!    discard the partially-deserialised `T` and `U` and restart them each time
//!    (with cloned copies of the `Value`s).  This is O(n^2) and involves much boxing.
//!
//! # References
//!
//!  * Tickets against `serde-ignored`:
//!    <https://github.com/dtolnay/serde-ignored/issues/17>
//!    <https://github.com/dtolnay/serde-ignored/issues/10>
//!
//!  * Workaround with `HashMap` that doesn't quite work right:
//!    <https://github.com/dtolnay/serde-ignored/issues/10#issuecomment-1044058310>
//!    <https://github.com/serde-rs/serde/issues/2176>
//!
//!  * Discussion in Tor Project gitlab re Arti configuration:
//!    <https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1599#note_2944510>

use std::collections::VecDeque;
use std::fmt::{self, Display};
use std::marker::PhantomData;
use std::mem;

use derive_adhoc::{define_derive_adhoc, derive_adhoc, Adhoc};
use paste::paste;
use serde::de::{self, DeserializeSeed, Deserializer, Error as _, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use serde_value::Value;
use thiserror::Error;

// Must come first so we can refer to it in docs
define_derive_adhoc! {
    /// Derives [`Flattenable`] for a struct
    ///
    /// # Limitations
    ///
    /// Some serde attributes might not be supported.
    /// For example, ones which make the type no longer deserialize as a named fields struct.
    /// This will be detected by a macro-generated always-failing test case.
    ///
    /// Most serde attributes (eg field renaming and ignoring) will be fine.
    ///
    /// # Example
    ///
    /// ```
    /// use serde::{Serialize, Deserialize};
    /// use derive_adhoc::Adhoc;
    /// use tor_config::derive_adhoc_template_Flattenable;
    ///
    /// #[derive(Serialize, Deserialize, Debug, Adhoc)]
    /// #[derive_adhoc(Flattenable)]
    /// struct A {
    ///     a: i32,
    /// }
    /// ```
    //
    // Note re semver:
    //
    // We re-export derive-adhoc's template engine, in the manner discussed by the d-a docs.
    // See
    //  https://docs.rs/derive-adhoc/latest/derive_adhoc/macro.define_derive_adhoc.html#exporting-a-template-for-use-by-other-crates
    //
    // The semantic behaviour of the template *does* have semver implications.
    pub Flattenable for struct, expect items =

    impl tor_config::Flattenable for $ttype {
        fn has_field(s: &str) -> bool {
            let fnames = tor_config::flattenable_extract_fields::<'_, Self>();
            IntoIterator::into_iter(fnames).any(|f| *f == s)

        }
    }

    // Detect if flattenable_extract_fields panics
    #[test]
    fn $<flattenable_test_ ${snake_case $tname}>() {
        // Using $ttype::has_field avoids writing out again
        // the call to flattenable_extract_fields, with all its generics,
        // and thereby ensures that we didn't have a mismatch that
        // allows broken impls to slip through.
        // (We know the type is at least similar because we go via the Flattenable impl.)
        let _: bool = <$ttype as tor_config::Flattenable>::has_field("");
    }
}

/// Helper for flattening deserialisation, compatible with [`serde_ignored`]
///
/// A combination of two structs `T` and `U`.
///
/// The serde representation flattens both structs into a single, larger, struct.
///
/// Furthermore, unlike plain use of `#[serde(flatten)]`,
/// `serde_ignored` will still detect fields which appear in serde input
/// but which form part of neither `T` nor `U`.
///
/// `T` and `U` must both be [`Flattenable`].
/// Usually that trait should be derived with
/// the [`Flattenable macro`](derive_adhoc_template_Flattenable).
///
/// If it's desired to combine more than two structs, `Flatten` can be nested.
///
/// # Limitations
///
/// Field name overlaps are not detected.
/// Fields which appear in both structs
/// will be processed as part of `T` during deserialization.
/// They will be internally presented as duplicate fields during serialization,
/// with the outcome depending on the data format implementation.
///
/// # Example
///
/// ```
/// use serde::{Serialize, Deserialize};
/// use derive_adhoc::Adhoc;
/// use tor_config::{Flatten, derive_adhoc_template_Flattenable};
///
/// #[derive(Serialize, Deserialize, Debug, Adhoc, Eq, PartialEq)]
/// #[derive_adhoc(Flattenable)]
/// struct A {
///     a: i32,
/// }
///
/// #[derive(Serialize, Deserialize, Debug, Adhoc, Eq, PartialEq)]
/// #[derive_adhoc(Flattenable)]
/// struct B {
///     b: String,
/// }
///
/// let combined: Flatten<A,B> = toml::from_str(r#"
///     a = 42
///     b = "hello"
/// "#).unwrap();
///
/// assert_eq!(
///    combined,
///    Flatten(A { a: 42 }, B { b: "hello".into() }),
/// );
/// ```
//
// We derive Adhoc on Flatten itself so we can use
// truly-adhoc derive_adhoc! to iterate over Flatten's two fields.
// This avoids us accidentally (for example) checking T's fields for passing to U.
#[derive(Adhoc, Debug, Clone, Copy, Hash, Ord, PartialOrd, Eq, PartialEq, Default)]
#[allow(clippy::exhaustive_structs)]
pub struct Flatten<T, U>(pub T, pub U);

/// Types that can be used with [`Flatten`]
///
/// Usually, derived with
/// the [`Flattenable derive-adhoc macro`](derive_adhoc_template_Flattenable).
pub trait Flattenable {
    /// Does this type have a field named `s` ?
    fn has_field(f: &str) -> bool;
}

//========== local helper macros ==========

/// Implement `deserialize_$what` as a call to `deserialize_any`.
///
/// `$args`, if provided, are any other formal arguments, not including the `Visitor`
macro_rules! call_any { { $what:ident $( $args:tt )* } => { paste!{
    fn [<deserialize_ $what>]<V>(self $( $args )*, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_any(visitor)
    }
} } }

/// Implement most `deserialize_*` as calls to `deserialize_any`.
///
/// The exceptions are the ones we need to handle specially in any of our types,
/// namely `any` itself and `struct`.
macro_rules! call_any_for_rest { {} => {
    call_any!(map);
    call_any!(bool);
    call_any!(byte_buf);
    call_any!(bytes);
    call_any!(char);
    call_any!(f32);
    call_any!(f64);
    call_any!(i128);
    call_any!(i16);
    call_any!(i32);
    call_any!(i64);
    call_any!(i8);
    call_any!(identifier);
    call_any!(ignored_any);
    call_any!(option);
    call_any!(seq);
    call_any!(str);
    call_any!(string);
    call_any!(u128);
    call_any!(u16);
    call_any!(u32);
    call_any!(u64);
    call_any!(u8);
    call_any!(unit);

    call_any!(enum, _: &'static str, _: FieldList);
    call_any!(newtype_struct, _: &'static str );
    call_any!(tuple, _: usize );
    call_any!(tuple_struct, _: &'static str, _: usize );
    call_any!(unit_struct, _: &'static str );
} }

//========== Implementations of Serialize and Flattenable ==========

derive_adhoc! {
    Flatten expect items:

    impl<T, U> Serialize for Flatten<T, U>
    where $( $ftype: Serialize, )
    {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
        {
            /// version of outer `Flatten` containing references
            ///
            /// We give it the same name because the name is visible via serde
            ///
            /// The problems with `#[serde(flatten)]` don't apply to serialisation,
            /// because we're not trying to track ignored fields.
            /// But we can't just apply `#[serde(flatten)]` to `Flatten`
            /// since it doesn't work with tuple structs.
            #[derive(Serialize)]
            struct Flatten<'r, T, U> {
              $(
                #[serde(flatten)]
                $fpatname: &'r $ftype,
              )
            }

            Flatten {
              $(
                $fpatname: &self.$fname,
              )
            }
            .serialize(serializer)
        }
    }

    /// `Flatten` may be nested
    impl<T, U> Flattenable for Flatten<T, U>
    where $( $ftype: Flattenable, )
    {
        fn has_field(f: &str) -> bool {
            $(
                $ftype::has_field(f)
                    ||
              )
                false
        }
    }
}

//========== Deserialize implementation ==========

/// The keys and values we are to direct to a particular child
///
/// See the module-level comment for the algorithm.
#[derive(Default)]
struct Portion(VecDeque<(String, Value)>);

/// [`de::Visitor`] for `Flatten`
struct FlattenVisitor<T, U>(PhantomData<(T, U)>);

/// Wrapper for a field name, impls [`de::Deserializer`]
struct Key(String);

/// Type alias for reified error
///
/// [`serde_value::DeserializerError`] has one variant
/// for each of the constructors of [`de::Error`].
type FlattenError = serde_value::DeserializerError;

//----- part 1: disassembly -----

derive_adhoc! {
    Flatten expect items:

    // where constraint on the Deserialize impl
    ${define FLATTENABLE $( $ftype: Deserialize<'de> + Flattenable, )}

    impl<'de, T, U> Deserialize<'de> for Flatten<T, U>
    where $FLATTENABLE
    {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
        {
            deserializer.deserialize_map(FlattenVisitor(PhantomData))
        }
    }

    impl<'de, T, U> Visitor<'de> for FlattenVisitor<T,U>
    where $FLATTENABLE
    {
        type Value = Flatten<T, U>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "map (for struct)")
        }

        fn visit_map<A>(self, mut mapa: A) -> Result<Self::Value, A::Error>
        where A: MapAccess<'de>
        {
            // See the module-level comment for an explanation.

            // $P is a local variable named after T/U: `p_t` or `p_u`, as appropriate
            ${define P $<p_ $fname>}

            ${for fields { let mut $P = Portion::default(); }}

            #[allow(clippy::suspicious_else_formatting)] // this is the least bad layout
            while let Some(k) = mapa.next_key::<String>()? {
              $(
                 if $ftype::has_field(&k) {
                    let v: Value = mapa.next_value()?;
                    $P.0.push_back((k, v));
                    continue;
                }
                else
              )
                {
                     let _: IgnoredAny = mapa.next_value()?;
                }
            }

            Flatten::assemble( ${for fields { $P, }} )
                .map_err(A::Error::custom)
        }
    }
}

//----- part 2: reassembly -----

derive_adhoc! {
    Flatten expect items:

    impl<'de, T, U> Flatten<T, U>
    where $( $ftype: Deserialize<'de>, )
    {
        /// Assemble a `Flatten` out of the partition of its keys and values
        ///
        /// Uses `Portion`'s `Deserializer` impl and T and U's `Deserialize`
        fn assemble(
          $(
            $fpatname: Portion,
          )
        ) -> Result<Self, FlattenError> {
            Ok(Flatten(
              $(
                $ftype::deserialize($fpatname)?,
              )
            ))
        }
    }
}

impl<'de> Deserializer<'de> for Portion {
    type Error = FlattenError;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_map(self)
    }

    call_any!(struct, _: &'static str, _: FieldList);
    call_any_for_rest!();
}

impl<'de> MapAccess<'de> for Portion {
    type Error = FlattenError;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
    where
        K: DeserializeSeed<'de>,
    {
        let Some(entry) = self.0.get_mut(0) else {
            return Ok(None);
        };
        let k = mem::take(&mut entry.0);
        let k: K::Value = seed.deserialize(Key(k))?;
        Ok(Some(k))
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
    where
        V: DeserializeSeed<'de>,
    {
        let v = self
            .0
            .pop_front()
            .expect("next_value called inappropriately")
            .1;
        let r = seed.deserialize(v)?;
        Ok(r)
    }
}

impl<'de> Deserializer<'de> for Key {
    type Error = FlattenError;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_string(self.0)
    }

    call_any!(struct, _: &'static str, _: FieldList);
    call_any_for_rest!();
}

//========== Field extractor ==========

/// List of fields, appears in several APIs here
type FieldList = &'static [&'static str];

/// Stunt "data format" which we use for extracting fields for derived `Flattenable` impls
///
/// The field extraction works as follows:
///  * We ask serde to deserialize `$ttype` from a `FieldExtractor`
///  * We expect the serde-macro-generated `Deserialize` impl to call `deserialize_struct`
///  * We return the list of fields to match up as an error
struct FieldExtractor;

/// Error resulting from successful operation of a [`FieldExtractor`]
///
/// Existence of this error is a *success*.
/// Unexpected behaviour by the type's serde implementation causes panics, not errors.
#[derive(Error, Debug)]
#[error("Flattenable macro test gave error, so test passed successfully")]
struct FieldExtractorSuccess(FieldList);

/// Extract fields of a struct, as viewed by `serde`
///
/// # Performance
///
/// In release builds, is very fast - all the serde nonsense boils off.
/// In debug builds, maybe a hundred instructions, so not ideal,
/// but it is at least O(1) since it doesn't have any loops.
///
/// # STABILITY WARNING
///
/// This function is `pub` but it is `#[doc(hidden)]`.
/// The only legitimate use is via the `Flattenable` macro.
/// There are **NO SEMVER GUARANTEES**
///
/// # Panics
///
/// Will panic on types whose serde field list cannot be simply extracted via serde,
/// which will include things that aren't named fields structs,
/// might include types decorated with unusual serde annotations.
pub fn flattenable_extract_fields<'de, T: Deserialize<'de>>() -> FieldList {
    let notional_input = FieldExtractor;
    let FieldExtractorSuccess(fields) = T::deserialize(notional_input)
        .map(|_| ())
        .expect_err("unexpected success deserializing from FieldExtractor!");
    fields
}

impl de::Error for FieldExtractorSuccess {
    fn custom<E>(e: E) -> Self
    where
        E: Display,
    {
        panic!("Flattenable macro test failed - some *other* serde error: {e}");
    }
}

impl<'de> Deserializer<'de> for FieldExtractor {
    type Error = FieldExtractorSuccess;

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        fields: FieldList,
        _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(FieldExtractorSuccess(fields))
    }

    fn deserialize_any<V>(self, _: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        panic!("test failed: Flattennable misimplemented by macros!");
    }

    call_any_for_rest!();
}

//========== tests ==========

#[cfg(test)]
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
    use crate as tor_config; // for the benefit of the macros

    use std::collections::HashMap;

    #[derive(Serialize, Deserialize, Debug, Adhoc, Eq, PartialEq)]
    #[derive_adhoc(Flattenable)]
    struct A {
        a: i32,
        m: HashMap<String, String>,
    }

    #[derive(Serialize, Deserialize, Debug, Adhoc, Eq, PartialEq)]
    #[derive_adhoc(Flattenable)]
    struct B {
        b: i32,
        v: Vec<String>,
    }

    #[derive(Serialize, Deserialize, Debug, Adhoc, Eq, PartialEq)]
    #[derive_adhoc(Flattenable)]
    struct C {
        c: HashMap<String, String>,
    }

    const TEST_INPUT: &str = r#"
        a = 42

        m.one = "unum"
        m.two = "bis"

        b = 99
        v = ["hi", "ho"]

        spurious = 66

        c.zed = "final"
    "#;

    fn test_input() -> toml::Value {
        toml::from_str(TEST_INPUT).unwrap()
    }
    fn simply<'de, T: Deserialize<'de>>() -> T {
        test_input().try_into().unwrap()
    }
    fn with_ignored<'de, T: Deserialize<'de>>() -> (T, Vec<String>) {
        let mut ignored = vec![];
        let f = serde_ignored::deserialize(
            test_input(), //
            |path| ignored.push(path.to_string()),
        )
        .unwrap();
        (f, ignored)
    }

    #[test]
    fn plain() {
        let f: Flatten<A, B> = test_input().try_into().unwrap();
        assert_eq!(f, Flatten(simply(), simply()));
    }

    #[test]
    fn ignored() {
        let (f, ignored) = with_ignored::<Flatten<A, B>>();
        assert_eq!(f, simply());
        assert_eq!(ignored, ["c", "spurious"]);
    }

    #[test]
    fn nested() {
        let (f, ignored) = with_ignored::<Flatten<A, Flatten<B, C>>>();
        assert_eq!(f, simply());
        assert_eq!(ignored, ["spurious"]);
    }

    #[test]
    fn ser() {
        let f: Flatten<A, Flatten<B, C>> = simply();

        assert_eq!(
            serde_json::to_value(f).unwrap(),
            serde_json::json!({
                "a": 42,
                "m": {
                    "one": "unum",
                    "two": "bis"
                },
                "b": 99,
                "v": [
                    "hi",
                    "ho"
                ],
                "c": {
                    "zed": "final"
                }
            }),
        );
    }

    /// This function exists only so we can disassemble it.
    ///
    /// To see what the result looks like in a release build:
    ///
    ///  * `RUSTFLAGS=-g cargo test -p tor-config --all-features --release -- --nocapture flattenable_extract_fields_a_test`
    ///  * Observe the binary that's run, eg `Running unittests src/lib.rs (target/release/deps/tor_config-d4c4f29c45a0a3f9)`
    ///  * Disassemble it `objdump -d target/release/deps/tor_config-d4c4f29c45a0a3f9`
    ///  * Search for this function: `less +/'28flattenable_extract_fields_a.*:'`
    ///
    /// At the time of writing, the result is three instructions:
    /// load the address of the list, load a register with the constant 2 (the length),
    /// return.
    fn flattenable_extract_fields_a() -> FieldList {
        flattenable_extract_fields::<'_, A>()
    }

    #[test]
    fn flattenable_extract_fields_a_test() {
        use std::hint::black_box;
        let f: fn() -> _ = black_box(flattenable_extract_fields_a);
        eprintln!("{:?}", f());
    }
}
