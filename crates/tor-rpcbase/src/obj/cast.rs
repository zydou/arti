//! Casting objects to trait pointers.
//!
//! Rust supports Any-to-Concrete downcasting via Any;
//! and the `downcast_rs` crate supports Trait-to-Concrete downcasting.
//! This module adds `Trait-to-Trait` downcasting for the Object trait.

use std::{
    any::{Any, TypeId},
    collections::HashMap,
    sync::Arc,
};

use once_cell::sync::Lazy;

use crate::Object;

/// A collection of functions to downcast `&dyn Object` references for some
/// particular concrete object type `O` into various `&dyn Trait` references.
///
/// You shouldn't construct this on your own: instead use
/// `derive_deftly(Object)`.
///
/// You shouldn't use this directly; instead use
/// [`ObjectArcExt`](super::ObjectArcExt).
///
/// Note that the concrete object type `O`
/// is *not* represented in the type of `CastTable`;
/// `CastTable`s are obtained and used at runtime, as part of dynamic dispatch,
/// so the type `O` is erased.  We work with `TypeId`s and various `&dyn ...`.
#[derive(Default)]
pub struct CastTable {
    /// A mapping from target TypeId for some trait to a function that can
    /// convert this table's type into a trait pointer to that trait.
    ///
    /// Every entry in this table must contain:
    ///
    ///   * A key that is `typeid::of::<&'static dyn Tr>()` for some trait `Tr`.
    ///   * A [`Caster`] whose functions are suitable for casting objects from this table's
    ///     type to `dyn Tr`.
    table: HashMap<TypeId, Caster>,
}

/// A single entry in a `CastTable`.
///
/// Each `Caster` exists for one concrete object type "`O`", and one trait type "`Tr`".
///
/// Note that we use `Box` here in order to support generic types: you can't
/// get a `&'static` reference to a function that takes a generic type in
/// current rust.
struct Caster {
    /// Actual type: `fn(Arc<dyn Object>) -> Arc<dyn Tr>`
    ///
    /// Panics if Object does not have the expected type (`O`).
    cast_to_ref: Box<dyn Any + Send + Sync>,
    /// Actual type: `fn(Arc<dyn Object>) -> Arc<dyn Tr>`
    ///
    /// Panics if Object does not have the expected type (`O`).
    cast_to_arc: Box<dyn Any + Send + Sync>,
}

impl CastTable {
    /// Add a new entry to this `CastTable` for downcasting to TypeId.
    ///
    /// You should not call this yourself; instead use
    /// [`derive_deftly(Object)`](crate::templates::derive_deftly_template_Object)
    ///
    /// # Requirements
    ///
    /// `T` must be `dyn Tr` for some trait `Tr`.
    /// (Not checked by the compiler.)
    ///
    /// `cast_to_ref` is a downcaster from `&dyn Object` to `&dyn Tr`.
    ///
    /// `cast_to_arc` is a downcaster from `Arc<dyn Object>` to `Arc<dyn Tr>`.
    ///
    /// These functions SHOULD
    /// panic if the concrete type of its argument is not the concrete type `O`
    /// associated with this `CastTable`.
    ///
    /// `O` must be `'static`.
    /// (Checked by the compiler.)
    ///
    /// # Panics
    ///
    /// Panics if called twice on the same `CastTable` with the same `Tr`.
    //
    // `TypeId::of::<dyn SomeTrait + '_>` exists, but is not the same as
    // `TypeId::of::<dyn SomeTrait + 'static>` (unless `SomeTrait: 'static`).
    //
    // We avoid a consequent bug with non-'static traits as follows:
    // We insert and look up by `TypeId::of::<&'static dyn SomeTrait>`,
    // which must mean `&'static (dyn SomeTrait + 'static)`
    // since a 'static reference to anything non-'static is an ill-formed type.
    pub fn insert<T: 'static + ?Sized>(
        &mut self,
        cast_to_ref: fn(&dyn Object) -> &T,
        cast_to_arc: fn(Arc<dyn Object>) -> Arc<T>,
    ) {
        let type_id = TypeId::of::<&'static T>();
        let caster = Caster {
            cast_to_ref: Box::new(cast_to_ref),
            cast_to_arc: Box::new(cast_to_arc),
        };
        self.insert_erased(type_id, caster);
    }

    /// Implementation for adding an entry to the `CastTable`
    ///
    /// Broken out for clarity and to reduce monomorphisation.
    ///
    /// ### Requirements
    ///
    /// Like `insert`, but less compile-time checking.
    /// `type_id` is the identity of `&'static dyn Tr`,
    /// and `func` has been boxed and type-erased.
    fn insert_erased(&mut self, type_id: TypeId, caster: Caster) {
        let old_val = self.table.insert(type_id, caster);
        assert!(
            old_val.is_none(),
            "Tried to insert a duplicate entry in a cast table.",
        );
    }

    /// Try to downcast a reference to an object whose concrete type is
    /// `O` (the type associated with this `CastTable`)
    /// to some target type `T`.
    ///
    /// `T` should be `dyn Tr`.
    /// If `T` is not one of the `dyn Tr` for which `insert` was called,
    /// returns `None`.
    ///
    /// # Panics
    ///
    /// Panics if the concrete type of `obj` does not match `O`.
    ///
    /// May panic if any of the Requirements for [`CastTable::insert`] were
    /// violated.
    pub fn cast_object_to<'a, T: 'static + ?Sized>(&self, obj: &'a dyn Object) -> Option<&'a T> {
        let target_type = TypeId::of::<&'static T>();
        let caster = self.table.get(&target_type)?;
        let caster: &fn(&dyn Object) -> &T = caster
            .cast_to_ref
            .downcast_ref()
            .expect("Incorrect cast-function type found in cast table!");
        Some(caster(obj))
    }

    /// As [`cast_object_to`](CastTable::cast_object_to), but returns an `Arc<dyn Tr>`.
    ///
    /// If `T` is not one of the `dyn Tr` types for which `insert_arc` was called,
    /// return `Err(obj)`.
    ///
    /// # Panics
    ///
    /// Panics if the concrete type of `obj` does not match `O`.
    ///
    /// May panic if any of the Requirements for [`CastTable::insert`] were
    /// violated.
    pub fn cast_object_to_arc<T: 'static + ?Sized>(
        &self,
        obj: Arc<dyn Object>,
    ) -> Result<Arc<T>, Arc<dyn Object>> {
        let target_type = TypeId::of::<&'static T>();
        let caster = match self.table.get(&target_type) {
            Some(c) => c,
            None => return Err(obj),
        };
        let caster: &fn(Arc<dyn Object>) -> Arc<T> = caster
            .cast_to_arc
            .downcast_ref()
            .expect("Incorrect cast-function type found in cast table!");
        Ok(caster(obj))
    }
}

/// Static cast table that doesn't support casting anything to anything.
///
/// Because this table doesn't support any casting, it is okay to use it with
/// any concrete type.
pub(super) static EMPTY_CAST_TABLE: Lazy<CastTable> = Lazy::new(|| CastTable {
    table: HashMap::new(),
});

/// Helper for HasCastTable to work around derive-deftly#36.
///
/// Defines the body for a private make_cast_table() method.
///
/// This macro is not part of `tor-rpcbase`'s public API, and is not covered
/// by semver guarantees.
#[doc(hidden)]
#[macro_export]
macro_rules! cast_table_deftness_helper{
    // Note: We have to use tt here, since $ty can't be used in $(dyn .)
    { $( $traitname:tt ),* } => {
                #[allow(unused_mut)]
                let mut table = $crate::CastTable::default();
                $({
                    use std::sync::Arc;
                    // These are the actual functions that does the downcasting.
                    // It works by downcasting with Any to the concrete type, and then
                    // upcasting from the concrete type to &dyn Trait.
                    let cast_to_ref: fn(&dyn $crate::Object) -> &(dyn $traitname + 'static) = |self_| {
                        let self_: &Self = self_.downcast_ref().unwrap();
                        let self_: &dyn $traitname = self_ as _;
                        self_
                    };
                    let cast_to_arc: fn(Arc<dyn $crate::Object>) -> Arc<dyn $traitname> = |self_| {
                        let self_: Arc<Self> = self_
                            .downcast_arc()
                            .ok()
                            .expect("used with incorrect type");
                        let self_: Arc<dyn $traitname> = self_ as _;
                        self_
                    };
                    table.insert::<dyn $traitname>(cast_to_ref, cast_to_arc);
                })*
                table
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
    use crate::templates::*;
    use derive_deftly::Deftly;

    trait Tr1 {}
    trait Tr2: 'static {}

    #[derive(Deftly)]
    #[derive_deftly(Object)]
    #[deftly(rpc(downcastable_to = "Tr1"))]
    struct Simple;
    impl Tr1 for Simple {}

    #[test]
    fn check_simple() {
        let concrete = Simple;
        let tab = Simple::make_cast_table();
        let obj: &dyn Object = &concrete;
        let _cast: &(dyn Tr1 + '_) = tab.cast_object_to(obj).expect("cast failed");

        let arc = Arc::new(Simple);
        let arc_obj: Arc<dyn Object> = arc.clone();
        let _cast: Arc<dyn Tr1> = tab.cast_object_to_arc(arc_obj).ok().expect("cast failed");
    }

    #[derive(Deftly)]
    #[derive_deftly(Object)]
    #[deftly(rpc(downcastable_to = "Tr1, Tr2"))]
    struct Generic<T: Send + Sync + 'static>(T);

    impl<T: Send + Sync + 'static> Tr1 for Generic<T> {}
    impl<T: Send + Sync + 'static> Tr2 for Generic<T> {}

    #[test]
    fn check_generic() {
        let gen: Generic<&'static str> = Generic("foo");
        let tab = Generic::<&'static str>::make_cast_table();
        let obj: &dyn Object = &gen;
        let _cast: &(dyn Tr1 + '_) = tab.cast_object_to(obj).expect("cast failed");

        let arc = Arc::new(Generic("bar"));
        let arc_obj: Arc<dyn Object> = arc.clone();
        let _cast: Arc<dyn Tr2> = tab.cast_object_to_arc(arc_obj).ok().expect("cast failed");
    }
}
