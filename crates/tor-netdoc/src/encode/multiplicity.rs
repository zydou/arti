//! Multiplicity for encoding netdoc elements, via ad-hoc deref specialisation.
//!
//! This module supports type-based handling of multiplicity,
//! of Items (within Documents) and Arguments (in Item keyword lines).
//!
//! It is **for use by macros**, rather than directly.
//!
//! See also `parse2::multiplicity` which is the corresponding module for parsing.
//!
//! # Explanation
//!
//! We use autoref specialisation to allow macros to dispatch to
//! trait impls for `Vec<T>`, `Option<T>` etc. as well as simply unadorned `T`.
//!
//! When methods on `MultiplicitySelector` are called, the compiler finds
//! the specific implementation for `MultiplicitySelector<Option<_>>` or `..Vec<_>`,
//! or, failing that, derefs and finds the blanket impl on `&MultiplicitySelector<T>`.
//!
//! For Objects, where only `T` and `Option<T>` are allowed,
//! we use `OptionalityMethods`.
//!
//! We implement traits on helper types `struct `[`MultiplicitySelector<Field>`],
//! [`DeterminedMultiplicitySelector`] and [`SingletonMultiplicitySelector`].
//!
//! The three selector types allow us to force the compiler to nail down the multiplicity,
//! during type inference, before considering whether the "each" type implements the
//! required trait.
//!
//! This is done by calling the `.selector()` method:
//! deref specialisation and inherent method vs trait method priority selects
//! the appropriate `.selector()` method, giving *another* selector,
//! so that the compiler only considers other selector's `MultiplicityMethods`,
//! when `.check_...` methods are used.
//! Otherwise, when a field has type (say) `Vec<NotItemValueParseable>`,
//! a call to `.check_item_value_encodable` could be resolved by autoref
//! so the compiler reports that **`Vec<..>`** doesn't implement the needed trait.
//! We prevent this by having
//! [`MultiplicitySelector::<Vec<_>>::default().selector()`](MultiplicitySelector::<Vec<T>>::selector)
//! be an inherent method returning [`DeterminedMultiplicitySelector`].
//!
//! `SingletonMultiplicitySelector` is used explicitly in the derive when we
//! know that we want to encode exactly one element:
//! for example, a document's intro item cannot be repeated or omitted.

use super::*;

/// Helper type that allows us to select an impl of `MultiplicityMethods`
///
/// **For use by macros**.
///
/// This is distinct from `parse2::MultiplicitySelector`,
/// principally because it has the opposite variance.
#[derive(Educe)]
#[educe(Clone, Copy, Default)]
pub struct MultiplicitySelector<Field>(PhantomData<fn(Field)>);

/// Helper type implementing `MultiplicityMethods`, after the multiplicity is determined
///
/// **For use by macros**.
#[derive(Educe)]
#[educe(Clone, Copy, Default)]
pub struct DeterminedMultiplicitySelector<Field>(PhantomData<fn(Field)>);

/// Helper type implementing `MultiplicityMethods`, when a field is statically a singleton
///
/// **For use by macros**.
#[derive(Educe)]
#[educe(Clone, Copy, Default)]
pub struct SingletonMultiplicitySelector<Field>(PhantomData<fn(Field)>);

/// Methods for handling some multiplicity of netdoc elements, during encoding
///
/// **For use by macros**.
///
/// Each multiplicity impl allows us to iterate over the element(s).
///
/// Methods are also provided for typechecking, which are used by the derive macro to
/// produce reasonable error messages when a trait impl is missing.
//
// When adding features here, for example by implementing this trait,
// update the documentation in the `NetdocEncodable` and `ItemValueEncodable` derives.
pub trait MultiplicityMethods<'f>: Copy + Sized {
    /// The value for each thing.
    type Each: Sized + 'f;

    /// The input type: the type of the field in the netdoc or item struct.
    type Field: Sized;

    /// Return the appropriate implementor of `MultiplicityMethods`
    fn selector(self) -> Self {
        self
    }

    /// Yield the items, in a stable order
    fn iter_ordered(self, f: &'f Self::Field) -> impl Iterator<Item = &'f Self::Each> + 'f;

    /// Cause a compiler error if the element is not `NetdocEncodable`
    fn check_netdoc_encodable(self)
    where
        Self::Each: NetdocEncodable,
    {
    }
    /// Cause a compiler error if the element is not `ItemValueEncodable`
    fn check_item_value_encodable(self)
    where
        Self::Each: ItemValueEncodable,
    {
    }
    /// Cause a compiler error if the element is not `ItemArgument`
    fn check_item_argument_encodable(self)
    where
        Self::Each: ItemArgument,
    {
    }
    /// Cause a compiler error if the element is not `ItemObjectEncodable`
    fn check_item_object_encodable(self)
    where
        Self::Each: ItemObjectEncodable,
    {
    }
}

impl<T> MultiplicitySelector<Vec<T>> {
    /// Return the appropriate implementor of `MultiplicityMethods`
    ///
    /// This is an inherent method so that it doesn't need the `EncodeOrd` bounds:
    /// that way if `EncodeOrd` is not implemented, we get a message about that,
    /// rather than a complaint that `ItemValueEncodable` isn't impl for `Vec<T>`.
    pub fn selector(self) -> DeterminedMultiplicitySelector<Vec<T>> {
        DeterminedMultiplicitySelector::default()
    }
}
impl<'f, T: EncodeOrd + 'f> MultiplicityMethods<'f> for DeterminedMultiplicitySelector<Vec<T>> {
    type Each = T;
    type Field = Vec<T>;
    fn iter_ordered(self, f: &'f Self::Field) -> impl Iterator<Item = &'f Self::Each> {
        let mut v = f.iter().collect_vec();
        v.sort_by(|a, b| a.encode_cmp(*b));
        v.into_iter()
    }
}
impl<'f, T: 'f> MultiplicityMethods<'f> for MultiplicitySelector<BTreeSet<T>> {
    type Each = T;
    type Field = BTreeSet<T>;
    fn iter_ordered(self, f: &'f Self::Field) -> impl Iterator<Item = &'f Self::Each> {
        f.iter()
    }
}
impl<'f, T: 'f> MultiplicityMethods<'f> for MultiplicitySelector<Option<T>> {
    type Each = T;
    type Field = Option<T>;
    fn iter_ordered(self, f: &'f Self::Field) -> impl Iterator<Item = &'f Self::Each> + 'f {
        f.iter()
    }
}
impl<'f, T: 'f> MultiplicityMethods<'f> for &'_ MultiplicitySelector<T> {
    type Each = T;
    type Field = T;
    fn iter_ordered(self, f: &'f Self::Field) -> impl Iterator<Item = &'f Self::Each> + 'f {
        iter::once(f)
    }
}
impl<'f, T: 'f> MultiplicityMethods<'f> for SingletonMultiplicitySelector<T> {
    type Each = T;
    type Field = T;
    fn iter_ordered(self, f: &'f Self::Field) -> impl Iterator<Item = &'f Self::Each> + 'f {
        iter::once(f)
    }
}

/// Methods for handling optionality of a netdoc Object, during encoding
///
// This could be used for things other than Object, if there were any thing
// that supported Option but not Vec.
//
/// **For use by macros**.
///
/// Each impl allows us to visit an optional element.
pub trait OptionalityMethods: Copy + Sized {
    /// The possibly-present element.
    type Each: Sized + 'static;

    /// The input type: the type of the field in the item struct.
    type Field: Sized;

    /// Yield the elemnet, if there is one
    fn as_option<'f>(self, f: &'f Self::Field) -> Option<&'f Self::Each>;
}
impl<T: 'static> OptionalityMethods for MultiplicitySelector<Option<T>> {
    type Each = T;
    type Field = Option<T>;
    fn as_option<'f>(self, f: &'f Self::Field) -> Option<&'f Self::Each> {
        f.as_ref()
    }
}
impl<T: 'static> OptionalityMethods for &'_ MultiplicitySelector<T> {
    type Each = T;
    type Field = T;
    fn as_option<'f>(self, f: &'f Self::Field) -> Option<&'f Self::Each> {
        Some(f)
    }
}
