//! Casting objects to trait pointers.
//!
//! Rust supports Any-to-Concrete downcasting via Any;
//! and the `downcast_rs` crate supports Trait-to-Concrete downcasting.
//! This module adds `Trait-to-Trait` downcasting for the Object trait.

use std::{
    any::{Any, TypeId},
    collections::HashMap,
};

use once_cell::sync::Lazy;

use crate::Object;

/// A collection of functions to downcast `&dyn Object` references for some
/// particular concrete type into various `&dyn Trait` references.
///
/// You shouldn't construct this on your own: instead use
/// [`crate::decl_object!`].
///
/// You shouldn't use this directly; instead use
/// [`ObjectRefExt`](super::ObjectRefExt).
#[derive(Default)]
pub struct CastTable {
    /// A mapping from target TypeId for some trait to a function that can
    /// convert this table's type into a trait pointer to that trait.
    ///
    /// Assuming that the concrete type associated with this `CastTable` is `S`,
    /// every entry in this table must contain:
    ///
    ///   * A key that is `typeid::of::<&'static dyn Tr>()` for some trait `Tr`.
    ///   * A function of type `fn(&dyn Object) -> &dyn Tr` for the same trait
    ///     `Tr`. This function must accept a `&dyn Object` whose concrete type
    ///     is actually `S`, and it SHOULD panic for other input types.
    ///
    /// Note that we use `Box` here in order to support generic types: you can't
    /// get a `&'static` reference to a function that takes a generic type in
    /// current rust.
    table: HashMap<TypeId, Box<dyn Any + Send + Sync>>,
}

impl CastTable {
    /// Add a new entry to this `CastTable` for downcasting to TypeId.
    ///
    /// You should not call this yourself; instead use the
    /// [`crate::decl_object!`] macro.
    ///
    /// # Requirements
    ///
    /// `type_id` must be the identity of `&'static dyn Tr` for some trait `Tr`.
    ///
    /// `Tr` must be `'static`.
    ///
    /// `func` must be a fn `fn(&dyn Object) -> &dyn Tr`.  The function SHOULD
    /// panic if the concrete type of its argument is not the concrete type
    /// associated with this `CastTable`.
    ///
    /// # Panics
    ///
    /// Panics if called twice on the same `CastTable` with the same `type_id`.
    pub fn insert(&mut self, type_id: TypeId, func: Box<dyn Any + Send + Sync>) {
        let old_val = self.table.insert(type_id, func);
        assert!(
            old_val.is_none(),
            "Tried to insert a duplicate entry in a cast table.",
        );
    }

    /// Try to downcast a reference to an object whose concrete type is
    /// associated with this `CastTable` to some target type `T`.
    ///
    /// `T` should be `dyn Tr`.
    /// If `T` is not one of the `dyn Tr` for which `insert` was called,
    /// returns `None`.
    /// # Panics
    ///
    /// Panics if the concrete type of `obj` does not match the type associated
    /// with this `CastTable`.
    ///
    /// May panic if any of the Requirements for [`CastTable::insert`] were
    /// violated.
    pub fn cast_object_to<'a, T: 'static + ?Sized>(&self, obj: &'a dyn Object) -> Option<&'a T> {
        let target_type = TypeId::of::<&'static T>();
        let caster = self.table.get(&target_type)?.as_ref();
        let caster: &fn(&dyn Object) -> &T = caster
            .downcast_ref()
            .expect("Incorrect cast-function type found in cast table!");
        Some(caster(obj))
    }
}

/// Static cast table that doesn't support casting anything to anything.
///
/// Because this table doesn't support any casting, it is okay to use it with
/// any concrete type.
pub(super) static EMPTY_CAST_TABLE: Lazy<CastTable> = Lazy::new(|| CastTable {
    table: HashMap::new(),
});

/// Helper macro: Add a private `make_cast_table()` method to a given object.
///
/// This macro is not part of `tor-rpcbase`'s public API, and is not covered
/// by semver guarantees.
#[doc(hidden)]
#[macro_export]
macro_rules! decl_make_cast_table {
    {
        // The name of the type that should get a make_cast_table() function.
        $thisname:path
        // The name of the type, plus any generic parameters.
        [ $thistype:ty ]
        // A list of generic parameters.
        [$($generics:ident),*]
        // A list of `where` constraints.
        [$($wheres:tt)*]
        // A list of the traits to implement downcasting for.
        [$($traitname:path),*]
    } => {
        impl<$($generics),*> $thistype
        where $($wheres)*
        {
            /// Construct a new `CastTable` for this type.
            ///
            /// This is a function so that we can call it multiple times as
            /// needed if the type is generic.
            ///
            /// Don't invoke this yourself; instead use `decl_object!`.
            #[doc(hidden)]
            fn make_cast_table() -> $crate::CastTable {
                #[allow(unused_mut)]
                let mut table = $crate::CastTable::default();
                $({
                    // `f` is the actual function that does the downcasting.
                    // It works by downcasting with Any to the concrete type, and then
                    // upcasting from the concrete type to &dyn Trait.
                    let f: fn(&dyn $crate::Object) -> &(dyn $traitname + 'static) = |self_| {
                        let self_: &$thistype  = self_.downcast_ref().unwrap();
                        let self_: &dyn $traitname = self_ as _;
                        self_
                    };
                    table.insert(
                        std::any::TypeId::of::<&'static dyn $traitname>(),
                        Box::new(f)
                    );
                })*
                table
            }
        }
    }
}

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
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;

    struct Generic<T>(T);

    trait Tr1: 'static {}
    trait Tr2: 'static {}
    impl<T: 'static> Tr1 for Generic<T> {}
    impl<T: 'static> Tr2 for Generic<T> {}
    impl<T: Send + Sync + 'static> Object for Generic<T> {}

    decl_make_cast_table! {
        Generic [Generic<T>] [T] [T: Send + Sync + 'static] [Tr1, Tr2]
    }

    #[test]
    fn check_if_it_works() {
        let gen: Generic<&'static str> = Generic("foo");
        let tab = Generic::<&'static str>::make_cast_table();
        let obj: &dyn Object = &gen;
        let _cast: &(dyn Tr1 + 'static) = tab.cast_object_to(obj).expect("cast failed");
    }
}
