//! Object type for our RPC system.

pub(crate) mod cast;

use downcast_rs::DowncastSync;
use serde::{Deserialize, Serialize};

use self::cast::CastTable;

/// An object in our RPC system to which methods can be addressed.
///
/// You shouldn't implement this trait yourself; instead, use the
/// [`decl_object`](crate::decl_object) macro.
///
/// See the documentation for [`decl_object`](crate::decl_object)
/// for examples of how to declare and
/// downcast `Object`s.
pub trait Object: DowncastSync {
    /// Return true if this object should be given an identifier that allows it
    /// to be used outside of the session that generated it.
    ///
    /// Currently, the only use for such IDs in arti is identifying stream
    /// contexts in when opening a SOCKS connection: When an application opens a
    /// stream, it needs to declare what RPC context (like a `TorClient`) it's
    /// using, which requires that some identifier for that context exist
    /// outside of the RPC session that owns it.
    //
    // TODO RPC: It would be neat if this were automatically set to true if and
    // only if there were any "out-of-session psuedomethods" defined on the
    // object.
    fn expose_outside_of_session(&self) -> bool {
        false
    }

    /// Return a [`CastTable`] that can be used to downcast a `dyn Object` of
    /// this type into various kinds of `dyn Trait` references.
    ///
    /// The default implementation of this method declares that the `Object`
    /// can't be downcast into any traits.
    ///
    /// You should not implement this method yourself; instead use the
    /// [`decl_object`](crate::decl_object) macro.
    fn get_cast_table(&self) -> &CastTable {
        &cast::EMPTY_CAST_TABLE
    }
}
downcast_rs::impl_downcast!(sync Object);

/// An identifier for an Object within the context of a Session.
///
/// These are opaque from the client's perspective.
#[derive(Debug, Eq, PartialEq, Hash, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObjectId(
    // (We use Box<str> to save a word here, since these don't have to be
    // mutable ever.)
    Box<str>,
);

impl AsRef<str> for ObjectId {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl<T> From<T> for ObjectId
where
    T: Into<Box<str>>,
{
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

/// Extension trait for `dyn Object` and similar to support convenient
/// downcasting to `dyn Trait`.
///
/// You don't need to use this for downcasting to an object's concrete
/// type; for that, use [`downcast_rs::DowncastSync`].
///
/// # Examples
///
/// ```
/// use tor_rpcbase::{decl_object, Object, ObjectRefExt};
/// use std::sync::Arc;
/// pub struct Frog {}
/// pub trait HasFeet {
///     fn num_feet(&self) -> usize;
/// }
/// impl HasFeet for Frog {
///     fn num_feet(&self) -> usize { 4 }
/// }
/// // Have `Frog` implement Object and declare that it can be
/// // downcast to HasFeet.
/// decl_object!{ Frog : [HasFeet] }
///
/// /// If `obj` is a HasFeet, return how many feet it has.
/// /// Otherwise, return 0.
/// fn check_feet(obj: Arc<dyn Object + 'static>) -> usize {
///     let maybe_has_feet: Option<&dyn HasFeet> = obj.cast_to_trait();
///     match maybe_has_feet {
///         Some(foot_haver) => foot_haver.num_feet(),
///         None => 0,
///     }
/// }
///
/// assert_eq!(check_feet(Arc::new(Frog{})), 4);
/// ```
pub trait ObjectRefExt {
    /// Try to cast this `Object` to a `T`.  On success, return a reference to
    /// T; on failure, return None.
    fn cast_to_trait<T: ?Sized + 'static>(&self) -> Option<&T>;
}

impl ObjectRefExt for dyn Object {
    fn cast_to_trait<T: ?Sized + 'static>(&self) -> Option<&T> {
        let table = self.get_cast_table();
        table.cast_object_to(self)
    }
}

impl ObjectRefExt for std::sync::Arc<dyn Object> {
    fn cast_to_trait<T: ?Sized + 'static>(&self) -> Option<&T> {
        self.as_ref().cast_to_trait()
    }
}

/// Declare that one or more space-separated types should be considered as
/// RPC objects.
///
/// This macro implements `Object` (and other necessary traits) for the
/// target type, and can be used to cause objects to participate in the trait
/// downcasting system.
///
/// You can provide multiple objects in one invocation of this macro;
/// just separate them with a semicolon (`;`).
///
/// # Examples
///
/// ## Simple case, just implements `Object`.
///
/// ```
/// use tor_rpcbase as rpc;
///
/// #[derive(Default)]
/// struct Houseplant {
///    oxygen_per_sec: f64,
///    benign_neglect: u8
/// }
///
/// rpc::decl_object!{Houseplant}
///
/// // You can downcast an Object to a concrete type.
/// use downcast_rs::DowncastSync;
/// use std::sync::Arc;
/// let plant_obj: Arc<dyn rpc::Object> = Arc::new(Houseplant::default());
/// let as_plant: Arc<Houseplant> = plant_obj.downcast_arc().ok().unwrap();
/// ```
///
/// ## With trait downcasting
///
/// By default, you can use [`downcast_rs`] to downcast a `dyn Object` to its
/// concrete type.  If you also need to be able to downcast a `dyn Object` to a given
/// trait that it implements, you can use this syntax for `decl_object` to have
/// it participate in trait downcasting:
///
/// ```
/// use tor_rpcbase as rpc;
///
/// struct Frobnitz {}
/// trait Gizmo {}
/// trait Doodad {}
/// impl Gizmo for Frobnitz {}
/// impl Doodad for Frobnitz {}
///
/// rpc::decl_object!{Frobnitz: [Gizmo, Doodad]}
///
/// use std::sync::Arc;
/// use rpc::ObjectRefExt; // for the cast_to method.
/// let frob_obj: Arc<dyn rpc::Object> = Arc::new(Frobnitz {});
/// let gizmo: &dyn Gizmo = frob_obj.cast_to_trait().unwrap();
/// let doodad: &dyn Doodad = frob_obj.cast_to_trait().unwrap();
/// ```
///
/// ## With generic objects
///
/// Right now, a generic object can't participate in our method lookup system,
/// but it _can_ participate in trait downcasting.  We'll try to remove this
/// limitation in the future.
///
/// The current syntax is pretty ugly; we may try to improve it in the future.
///
/// ```
/// use tor_rpcbase as rpc;
///
/// struct Generic<T,U> where T:Clone, U:PartialEq {
///     t: T,
///     u: U,
/// }
/// trait ExampleTrait {}
/// impl<T:Clone,U:PartialEq> ExampleTrait for Generic<T,U> {}
/// rpc::decl_object!{
///     Generic
///             // First, list the generic parameters.
///             [T,U]
///             // Then give the contents of the where clause.
///             // They will need to be `Send + Sync + 'static` or else you
///             // won't be able to implement `Object`.
///             [ T:Clone + Send + Sync + 'static,
///               U:PartialEq + Send + Sync + 'static]
///             // Finally, list the traits you want to downcast into.
///             : [ExampleTrait]
/// }
///
/// use std::sync::Arc;
/// use rpc::ObjectRefExt; // for the cast_to method.
/// let obj: Arc<dyn rpc::Object> = Arc::new(Generic { t: 42_u8, u: 42_u8 });
/// let tr: &dyn ExampleTrait = obj.cast_to_trait().unwrap();
/// ```
///
/// ## Making an object "exposed outside of the session"
///
/// You flag any kind of Object so that its identifiers will be exported
/// outside of the local RPC session.  (Arti uses this for Objects whose
/// ObjectId needs to be used as a SOCKS identifier.)  To do so,
/// add `@expose` before the object's name:
///
/// ```
/// use tor_rpcbase as rpc;
///
/// struct Visible {}
///
/// rpc::decl_object!{@expose Visible}

/// ```
#[macro_export]
macro_rules! decl_object {
    {$(@ $flag:ident)* $id:ident $( ; $($rest:tt)* )? }
    =>
    {

        $crate::impl_const_type_id!{$id}
        impl $crate::Object for $id {
            $( $crate::decl_object!{@@extra_method $flag} )*
        }

        $( $crate::decl_object!{$($rest)*} )?
    };
    {$(@ $flag:ident)* $id:ident : [$($traitname:path),*] $( ; $($rest:tt)* )? } =>
    {
        $crate::impl_const_type_id!{$id}
        $crate::decl_make_cast_table!{$id [$id] [] [] [$($traitname),*] }
        impl $crate::Object for $id {
            $( $crate::decl_object!{@@extra_method $flag} )*

            fn get_cast_table(&self) -> &$crate::CastTable {
                // For non-generic types, we only ever have a single CastTable,
                // so we can just construct it once and return it.
                use $crate::once_cell::sync::Lazy;
                static TABLE: Lazy<$crate::CastTable> = Lazy::new(|| $id::make_cast_table());
                &TABLE
            }
        }

        $( $crate::decl_object!{$($rest)*} )?
    };
    {$(@ $flag:ident)* $id:ident [$($param:ident),*] [$($wheres:tt)*] : [$($traitname:path),*] $( ; $($rest:tt)* )? } =>
    {
        // No const_type_id is possible here.  That means we can't yet put these
        // in our dispatch table. So sad.
        // TODO RPC: See arti#837 for work on this.
        $crate::decl_make_cast_table!{ $id [$id<$($param),*>] [$($param),*] [$($wheres)*] [$($traitname)*]  }
        impl<$($param),*> $crate::Object for $id<$($param),*>
        where $($wheres)*
        {
            $( $crate::decl_object!{@@extra_method $flag} )*

            fn get_cast_table(&self) -> &$crate::CastTable {
                // For generic types, we have a potentially unbounded number
                // of CastTables: one for each instantiation of the type.
                // Therefore we keep a mutable add-only HashMap of CastTables.

                use $crate::once_cell::sync::Lazy;
                use std::sync::RwLock;
                use std::collections::HashMap;
                use std::any::TypeId;
                // Map from concrete type to CastTable.
                //
                // Note that we use `&'static CastTable` here, not
                // `Box<CastTable>`: If we used Box<>, the borrow checker would
                // worry that our `CastTable`s might get freed after we returned
                // a reference to them.  Using `&'static` guarantees that the CastTable
                // references are safe to return.
                //
                // In order to get a `&'static`, we need to use Box::leak().
                // That's fine, since we only create one CastTable per
                // instantiation of the type.
                static TABLES: Lazy<RwLock<HashMap<TypeId, &'static $crate::CastTable>>> =
                Lazy::new(|| RwLock::new(HashMap::new()));
                {
                    let tables_r = TABLES.read().expect("poisoned lock");
                    if let Some(table) = tables_r.get(&TypeId::of::<Self>()) {
                        // Fast case: we already had a CastTable for this instantiation.
                        table
                    } else {
                        // We didn't find a CastTable.
                        drop(tables_r); // prevent deadlock.
                        TABLES
                         .write()
                         .expect("poisoned lock")
                         .entry(TypeId::of::<Self>())
                         // We use `or_insert_with` here to avoid a race
                         // condition: we only want to call make_cast_table if
                         // one didn't already exist.
                         .or_insert_with(|| Box::leak(Box::new(Self::make_cast_table())))
                    }
                }
            }
        }
        $( $crate::decl_object!{$($rest)*} )?
    };

    {@@extra_method expose} => {
        fn expose_outside_of_session(&self) -> bool { true }
    };

    // This production allows a terminating ; to appear in a decl_object call.
    { } => {};
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

    struct Bicycle {}
    trait HasWheels {
        fn num_wheels(&self) -> usize;
    }
    impl HasWheels for Bicycle {
        fn num_wheels(&self) -> usize {
            2
        }
    }
    decl_object! { Bicycle: [HasWheels]; }

    #[test]
    fn standard_cast() {
        let bike = Bicycle {};
        let erased_bike: &dyn Object = &bike;
        let has_wheels: &dyn HasWheels = erased_bike.cast_to_trait().unwrap();
        assert_eq!(has_wheels.num_wheels(), 2);
    }

    struct Crowd<T: HasWheels> {
        members: Vec<T>,
    }
    impl<T: HasWheels> HasWheels for Crowd<T> {
        fn num_wheels(&self) -> usize {
            self.members.iter().map(T::num_wheels).sum()
        }
    }

    decl_object! {
        Crowd [T] [T:HasWheels+Send + Sync + 'static] : [HasWheels]
    }

    #[test]
    fn generic_cast() {
        let bikes = Crowd {
            members: vec![Bicycle {}, Bicycle {}],
        };
        let erased_bikes: &dyn Object = &bikes;
        let has_wheels: &dyn HasWheels = erased_bikes.cast_to_trait().unwrap();
        assert_eq!(has_wheels.num_wheels(), 4);
    }
}
