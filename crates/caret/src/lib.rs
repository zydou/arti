#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![allow(renamed_and_removed_lints)] // @@REMOVE_WHEN(ci_arti_stable)
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_duration_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
#![allow(clippy::needless_lifetimes)] // See arti#1765
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

/// Declare an integer type with some named elements.
///
/// This macro declares a struct that wraps an integer
/// type, and allows any integer type as a value.  Some values of this type
/// have names, and others do not, but they are all allowed.
///
/// This macro is suitable for protocol implementations that accept
/// any integer on the wire, and have definitions for some of those
/// integers.  For example, Tor cell commands are 8-bit integers, but
/// not every u8 is a currently recognized Tor command.
///
/// # Examples
/// ```
/// use caret::caret_int;
/// caret_int! {
///     pub struct FruitID(u8) {
///         AVOCADO = 7,
///         PERSIMMON = 8,
///         LONGAN = 99
///     }
/// }
///
/// // Known fruits work the way we would expect...
/// let a_num: u8 = FruitID::AVOCADO.into();
/// assert_eq!(a_num, 7);
/// let a_fruit: FruitID = 8.into();
/// assert_eq!(a_fruit, FruitID::PERSIMMON);
/// assert_eq!(format!("I'd like a {}", FruitID::PERSIMMON),
///            "I'd like a PERSIMMON");
///
/// // And we can construct unknown fruits, if we encounter any.
/// let weird_fruit: FruitID = 202.into();
/// assert_eq!(format!("I'd like a {}", weird_fruit),
///            "I'd like a 202");
/// ```
#[macro_export]
macro_rules! caret_int {
    {
       $(#[$meta:meta])*
       $v:vis struct $name:ident ( $numtype:ty ) {
           $(
               $(#[$item_meta:meta])*
               $id:ident = $num:literal
           ),*
           $(,)?
      }
    } => {
        #[derive(PartialEq,Eq,Copy,Clone)]
        $(#[$meta])*
        $v struct $name($numtype);

        impl From<$name> for $numtype {
            fn from(val: $name) -> $numtype { val.0 }
        }
        impl From<$numtype> for $name {
            fn from(num: $numtype) -> $name { $name(num) }
        }
        impl $name {
            $(
                $( #[$item_meta] )*
                pub const $id: $name = $name($num) ; )*
            fn to_str(self) -> Option<&'static str> {
                match self {
                    $( $name::$id => Some(stringify!($id)), )*
                    _ => None,
                }
            }
            /// Return true if this value is one that we recognize.
            $v fn is_recognized(self) -> bool {
                match self {
                    $( $name::$id  => true, )*
                    _ => false
                }
            }
            /// Try to convert this value from one of the recognized names.
            $v fn from_name(name: &str) -> Option<Self> {
                match name {
                    $( stringify!($id) => Some($name::$id), )*
                    _ => None
                }
            }
            /// Return the underlying integer that this value represents.
            fn get(self) -> $numtype {
                self.into()
            }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self.to_str() {
                    Some(s) => write!(f, "{}", s),
                    None => write!(f, "{}", self.0),
                }
            }
        }
        // `#[educe(Debug)]` could do this for us, but let's not deepen this macrology
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({})", stringify!($name), self)
            }
        }
    };

}
