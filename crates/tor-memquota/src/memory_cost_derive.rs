//! Deriving `HasMemoryCost`

use crate::internal_prelude::*;

//---------- main public items ----------

/// Types whose `HasMemoryCost` is derived structurally
///
/// Usually implemented using
/// [`#[derive_deftly(HasMemoryCost)]`](crate::derive_deftly_template_HasMemoryCost).
///
/// For `Copy` types, it can also be implemented with
/// `memory_cost_structural_copy!`.
///
/// When this trait is implemented, a blanket impl provides [`HasMemoryCost`].
///
/// ### Structural memory cost
///
/// We call the memory cost "structural"
/// when it is derived from the type's structure.
///
/// The memory cost of a `HasMemoryCostStructural` type is:
///
/// - The number of bytes in its own size [`size_of`]; plus
///
/// - The (structural) memory cost of all the out-of-line data that it owns;
///   that's what's returned by
///   [`indirect_memory_cost`](HasMemoryCostStructural::indirect_memory_cost)
///
/// For example, `String`s out-of-line memory cost is just its capacity,
/// so its memory cost is the size of its three word layout plus its capacity.
///
/// This calculation is performed by the blanket impl of `HasMemoryCost`.
///
/// ### Shared data - non-`'static` types, `Arc`
///
/// It is probably a mistake to implement this trait (or `HasMemoryCost`)
/// for types with out-of-line data that they don't exclusively own.
/// After all, the memory cost must be known and fixed,
/// and if there is shared data it's not clear how it should be accounted.
pub trait HasMemoryCostStructural {
    /// Memory cost of data stored out-of-line
    ///
    /// The total memory cost is the cost of the layout of `self` plus this.
    fn indirect_memory_cost(&self, _: EnabledToken) -> usize;
}

/// (Internal) wrapper for to help implement `MemoryCostStructural` for `Copy` types and fields
///
/// So instead, when we have `Copy` types or fields, we wrap them in this.
///
/// (We could just hardcode a `0` at the use sites of this struct,
/// but that wouldn't prove that our preconditions - `Copy + 'static` - were met.
#[allow(clippy::exhaustive_structs)]
pub struct MemoryCostStructuralCopy<'r, T: Copy + 'static>(pub &'r T);

impl<'r, T: Copy + 'static> HasMemoryCostStructural for MemoryCostStructuralCopy<'r, T> {
    fn indirect_memory_cost(&self, _: EnabledToken) -> usize {
        0
    }
}

impl<T: HasMemoryCostStructural> HasMemoryCost for T {
    fn memory_cost(&self, et: EnabledToken) -> usize {
        size_of::<T>() //
            .saturating_add(
                //
                <T as HasMemoryCostStructural>::indirect_memory_cost(self, et),
            )
    }
}

//---------- specific implementations ----------

/// Implement [`HasMemoryCostStructural`] for `Copy` types
///
/// The [`indirect_memory_cost`](HasMemoryCostStructural::indirect_memory_cost)
/// of a `Copy + 'static` type is zero.
///
/// This macro implements that.
///
/// Ideally, we would `impl <T: Copy + 'static> MemoryCostStructural for T`.
/// But that falls foul of trait coherence rules.
/// So instead we provide `memory_cost_structural_copy!`
/// and the `#[deftly(has_memory_cost(copy))]` attribute.
///
/// This macro can only be used within `tor-memquota`, or for types local to your crate.
/// For other types, use `#[deftly(has_memory_cost(copy))]` on each field of that type.
//
// Unfortunately we can't provide a blanket impl of `HasMemoryCostStructural`
// for all `Copy` types, because we want to provide `HasMemoryCostStructural`
// for `Vec` and `Box` -
// and rustic thinks that those might become `Copy` in the future.
#[macro_export]
macro_rules! memory_cost_structural_copy { { $($ty:ty),* $(,)? } => { $(
    impl $crate::HasMemoryCostStructural for $ty {
        fn indirect_memory_cost(&self, et: $crate::EnabledToken) -> usize {
            $crate::HasMemoryCostStructural::indirect_memory_cost(
                &$crate::MemoryCostStructuralCopy(self),
                et,
            )
        }
    }
)* } }

memory_cost_structural_copy! {
    u8, u16, u32, u64, usize,
    i8, i16, i32, i64, isize,
    // TODO MSRV use std::num::NonZero<_> and avoid all these qualified names
    std::num::NonZeroU8, std::num::NonZeroU16, std::num::NonZeroU32, std::num::NonZeroU64,
    std::num::NonZeroI8, std::num::NonZeroI16, std::num::NonZeroI32, std::num::NonZeroI64,
    std::num::NonZeroUsize,
    std::num::NonZeroIsize,
    std::net::IpAddr, std::net::Ipv4Addr, std::net::Ipv6Addr,
}

/// Implement HasMemoryCost for tuples
macro_rules! memory_cost_structural_tuples { {
    // Recursive case: do base case for this input, and then the next inputs
    $($T:ident)* - $U0:ident $($UN:ident)*
} => {
    memory_cost_structural_tuples! { $($T)* - }
    memory_cost_structural_tuples! { $($T)* $U0 - $($UN)* }
}; {
    // Base case, implement for the tuple with contents types $T
    $($T:ident)* -
} => { paste! {
    impl < $(
        $T: HasMemoryCostStructural,
    )* > HasMemoryCostStructural for ( $(
        $T,
    )* ) {
        fn indirect_memory_cost(&self, #[allow(unused)] et: EnabledToken) -> usize {
            let ( $(
                [< $T:lower >],
            )* ) = self;
            0_usize $(
                .saturating_add([< $T:lower >].indirect_memory_cost(et))
            )*
        }
    }
} } }
memory_cost_structural_tuples! { - A B C D E F G H I J K L M N O P Q R S T U V W X Y Z }

impl<T: HasMemoryCostStructural> HasMemoryCostStructural for Option<T> {
    fn indirect_memory_cost(&self, et: EnabledToken) -> usize {
        if let Some(t) = self {
            <T as HasMemoryCostStructural>::indirect_memory_cost(t, et)
        } else {
            0
        }
    }
}

impl<T: HasMemoryCostStructural, const N: usize> HasMemoryCostStructural for [T; N] {
    fn indirect_memory_cost(&self, et: EnabledToken) -> usize {
        self.iter()
            .map(|t| t.indirect_memory_cost(et))
            .fold(0, usize::saturating_add)
    }
}

impl<T: HasMemoryCostStructural> HasMemoryCostStructural for Box<T> {
    fn indirect_memory_cost(&self, et: EnabledToken) -> usize {
        <T as HasMemoryCost>::memory_cost(&**self, et)
    }
}

impl<T: HasMemoryCostStructural> HasMemoryCostStructural for Vec<T> {
    fn indirect_memory_cost(&self, et: EnabledToken) -> usize {
        chain!(
            [size_of::<T>().saturating_mul(self.capacity())],
            self.iter().map(|t| t.indirect_memory_cost(et)),
        )
        .fold(0, usize::saturating_add)
    }
}

impl HasMemoryCostStructural for String {
    fn indirect_memory_cost(&self, _et: EnabledToken) -> usize {
        self.capacity()
    }
}

//------------------- derive macro ----------

define_derive_deftly! {
    /// Derive `HasMemoryCost`
    ///
    /// Each field must implement [`HasMemoryCostStructural`].
    ///
    /// Valid for structs and enums.
    ///
    /// ### Top-level attributes
    ///
    ///  * **`#[deftly(has_memory_cost(bounds = "BOUNDS"))]`**:
    ///    Additional bounds to apply to the implementation.
    ///
    /// ### Field attributes
    ///
    ///  * **`#[deftly(has_memory_cost(copy))]`**:
    ///    This field is `Copy + 'static` so does not reference any data that should be accounted.
    ///  * **`#[deftly(has_memory_cost(indirect_fn = "FUNCTION"))]`**:
    ///    `FUNCTION` is a function with the signature and semantics of
    ///    [`HasMemoryCostStructural::indirect_memory_cost`],
    ///  * **`#[deftly(has_memory_cost(indirect_size = "EXPR"))]`**:
    ///    `EXPR` is an expression of type usize with the semantics of a return value from
    ///    [`HasMemoryCostStructural::indirect_memory_cost`].
    ///
    /// With one of these, the field doesn't need to implement `HasMemoryCostStructural`.
    ///
    /// # Example
    ///
    /// ```
    /// use derive_deftly::Deftly;
    /// use std::mem::size_of;
    /// use tor_memquota::{HasMemoryCost, HasMemoryCostStructural};
    /// use tor_memquota::derive_deftly_template_HasMemoryCost;
    ///
    /// #[derive(Deftly)]
    /// #[derive_deftly(HasMemoryCost)]
    /// #[deftly(has_memory_cost(bounds = "Data: HasMemoryCostStructural"))]
    /// struct Struct<Data> {
    ///     data: Data,
    ///
    ///     #[deftly(has_memory_cost(indirect_size = "0"))] // this is a good guess
    ///     num: serde_json::Number,
    ///
    ///     #[deftly(has_memory_cost(copy))]
    ///     msg: &'static str,
    ///
    ///     #[deftly(has_memory_cost(indirect_fn = "|info, _et| String::capacity(info)"))]
    ///     info: safelog::Sensitive<String>,
    /// }
    ///
    /// let s = Struct {
    ///     data: String::with_capacity(33),
    ///     num: serde_json::Number::from_f64(0.0).unwrap(),
    ///     msg: "hello",
    ///     info: String::with_capacity(12).into(),
    /// };
    ///
    /// let Some(et) = tor_memquota::EnabledToken::new_if_compiled_in() else { return };
    ///
    /// assert_eq!(
    ///     s.memory_cost(et),
    ///     size_of::<Struct<String>>() + 33 + 12,
    /// );
    /// ```
    export HasMemoryCost expect items:

    impl<$tgens> $crate::HasMemoryCostStructural for $ttype
    where $twheres ${if tmeta(has_memory_cost(bounds)) {
              ${tmeta(has_memory_cost(bounds)) as token_stream}
    }}
    {
        fn indirect_memory_cost(&self, #[allow(unused)] et: $crate::EnabledToken) -> usize {
            ${define F_INDIRECT_COST {
                ${select1
                    fmeta(has_memory_cost(copy)) {
                        $crate::HasMemoryCostStructural::indirect_memory_cost(
                            &$crate::MemoryCostStructuralCopy::<$ftype>(&$fpatname),
                            et,
                        )
                    }
                    fmeta(has_memory_cost(indirect_fn)) {
                        ${fmeta(has_memory_cost(indirect_fn)) as expr}(&$fpatname, et)
                    }
                    fmeta(has_memory_cost(indirect_size)) {
                        ${fmeta(has_memory_cost(indirect_size)) as expr}
                    }
                    else {
     <$ftype as $crate::HasMemoryCostStructural>::indirect_memory_cost(&$fpatname, et)
                    }
                }
            }}

            match self {
                $(
                    $vpat => {
                        0_usize
                            ${for fields {
                                .saturating_add( $F_INDIRECT_COST )
                            }}
                    }
                )
            }
        }
    }
}

#[cfg(all(test, feature = "memquota"))]
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
    #![allow(clippy::arithmetic_side_effects)] // don't mind potential panicking ops in tests

    use super::*;

    #[derive(Deftly)]
    #[derive_deftly(HasMemoryCost)]
    enum E {
        U(usize),
        B(Box<u32>),
    }

    #[derive(Deftly, Default)]
    #[derive_deftly(HasMemoryCost)]
    struct S {
        u: usize,
        b: Box<u32>,
        v: Vec<u32>,
        ev: Vec<E>,
    }

    const ET: EnabledToken = EnabledToken::new();

    // The size of a u32 is always 4 bytes, so we just write "4" rather than u32::SIZE.

    #[test]
    fn structs() {
        assert_eq!(S::default().memory_cost(ET), size_of::<S>() + 4);
        assert_eq!(E::U(0).memory_cost(ET), size_of::<E>());
        assert_eq!(E::B(Box::default()).memory_cost(ET), size_of::<E>() + 4);
    }

    #[test]
    fn values() {
        let mut v: Vec<u32> = Vec::with_capacity(10);
        v.push(1);

        let s = S {
            u: 0,
            b: Box::new(42),
            v,
            ev: vec![],
        };

        assert_eq!(
            s.memory_cost(ET),
            size_of::<S>() + 4 /* b */ + 10 * 4, /* v buffer */
        );
    }

    #[test]
    #[allow(clippy::identity_op)]
    fn nest() {
        let mut ev = Vec::with_capacity(10);
        ev.push(E::U(42));
        ev.push(E::B(Box::new(42)));

        let s = S { ev, ..S::default() };

        assert_eq!(
            s.memory_cost(ET),
            size_of::<S>() + 4 /* b */ + 0 /* v */ + size_of::<E>() * 10 /* ev buffer */ + 4 /* E::B */
        );
    }
}
