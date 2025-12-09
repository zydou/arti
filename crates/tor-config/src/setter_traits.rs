//! Traits to allow the setter functions on our builders
//! to accept the specific set of types we want.

use std::num::NonZero;

/// Module used to seal the traits declared here.
mod seal {
    /// A type to seal most of the traits here.
    pub trait Sealed {}
    /// A type to seal `PossiblyOption<T>`. (This one has to be generic.)
    pub trait SealedPossiblyOption<T> {}
}

/// A trait implemented by `String` and `&str`.
///
/// This is more specific than `AsRef<str>`, which can accidentally include
/// many other undesired types.
pub trait StringOrStr: seal::Sealed {
    /// Convert this object to a String.
    fn to_string(self) -> String;
}
impl seal::Sealed for String {}
impl<'a> seal::Sealed for &'a str {}

impl StringOrStr for String {
    fn to_string(self) -> String {
        self
    }
}
impl<'a> StringOrStr for &'a str {
    fn to_string(self) -> String {
        self.to_owned()
    }
}

/// A trait implemented by `String`, `&str`, `Option<String>`, and `Option<&str>`
pub trait OptionStringOrStr: seal::Sealed {
    /// Convert this object to an `Option<String>`.
    fn to_option_string(self) -> Option<String>;
}

impl<S> OptionStringOrStr for S
where
    S: StringOrStr,
{
    fn to_option_string(self) -> Option<String> {
        Some(self.to_string())
    }
}
impl<S> seal::Sealed for Option<S> where S: StringOrStr {}
impl<S> OptionStringOrStr for Option<S>
where
    S: StringOrStr,
{
    fn to_option_string(self) -> Option<String> {
        self.map(StringOrStr::to_string)
    }
}

/// A trait implemented by `N` and `NonZero<N>`, where N is an integer type.
pub trait PossiblyBoundsChecked<N>: seal::Sealed {
    /// Convert this object to an instance of `N`.
    fn to_unchecked(self) -> N;
}
/// A trait implemented by `N`, `NonZero<N>`, `Option<N>`, and `Option<NonZero<N>>`, where N is an
/// integer type.
pub trait OptionPossiblyBoundsChecked<N>: seal::Sealed {
    /// Convert this object to an instance of `Option<N>`.
    fn to_option_unchecked(self) -> Option<N>;
}

/// Implement [`PossiblyBoundsChecked`] and [`OptionPossiblyBoundsChecked`]
/// for a space-separated list of integer types.
macro_rules! impl_possibly_bounds_checked {
    { $($num:ty)+ } => {
        $(
            impl seal::Sealed for $num {}
            impl seal::Sealed for NonZero<$num> {}
            impl seal::Sealed for Option<$num> {}
            impl seal::Sealed for Option<NonZero<$num>> {}

            impl PossiblyBoundsChecked<$num> for $num {
                fn to_unchecked(self) -> $num {
                    self
                }
            }
            impl PossiblyBoundsChecked<$num> for NonZero<$num> {
                fn to_unchecked(self) -> $num {
                    self.get()
                }
            }
            impl OptionPossiblyBoundsChecked<$num> for $num {
                fn to_option_unchecked(self) -> Option<$num> {
                    Some(self)
                }
            }
            impl OptionPossiblyBoundsChecked<$num> for Option<$num> {
                fn to_option_unchecked(self) -> Option<$num> {
                    self
                }
            }
            impl OptionPossiblyBoundsChecked<$num> for NonZero<$num> {
                fn to_option_unchecked(self) -> Option<$num> {
                    Some(self.get())
                }
            }
            impl OptionPossiblyBoundsChecked<$num> for Option<NonZero<$num>> {
                fn to_option_unchecked(self) -> Option<$num> {
                    self.map(|v| v.get())
                }
            }
         )+
    }
}
impl_possibly_bounds_checked! { u8 u16 u32 u64 u128 }

/// A trait implemented by `T` and `Option<T>`.
pub trait PossiblyOption<T>: seal::SealedPossiblyOption<T> {
    /// Convert this object into an `Option<T>`
    fn to_option(self) -> Option<T>;
}
impl<T> seal::SealedPossiblyOption<T> for T {}
impl<T> seal::SealedPossiblyOption<T> for Option<T> {}

impl<T> PossiblyOption<T> for T {
    fn to_option(self) -> Option<T> {
        Some(self)
    }
}
impl<T> PossiblyOption<T> for Option<T> {
    fn to_option(self) -> Option<T> {
        self
    }
}
