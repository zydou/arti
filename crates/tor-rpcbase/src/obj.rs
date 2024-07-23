//! Object type for our RPC system.

pub(crate) mod cast;

use std::sync::Arc;

use derive_deftly::define_derive_deftly;
use downcast_rs::DowncastSync;
use serde::{Deserialize, Serialize};

use self::cast::CastTable;

/// An object in our RPC system to which methods can be addressed.
///
/// You shouldn't implement this trait yourself; instead, use the
/// [`derive_deftly(Object)`].
///
/// See the documentation for [`derive_deftly(Object)`]
/// for examples of how to declare and
/// downcast `Object`s.
///
/// [`derive_deftly(Object)`]: crate::templates::derive_deftly_template_Object
pub trait Object: DowncastSync + Send + Sync + 'static {
    /// Return true if this object should be given an identifier that allows it
    /// to be used outside of the session that generated it.
    ///
    /// Currently, the only use for such IDs in arti is identifying stream
    /// contexts in when opening a SOCKS connection: When an application opens a
    /// stream, it needs to declare what RPC context (like a `TorClient`) it's
    /// using, which requires that some identifier for that context exist
    /// outside of the RPC session that owns it.
    fn expose_outside_of_session(&self) -> bool {
        false
    }

    /// Return a [`CastTable`] that can be used to downcast a `dyn Object` of
    /// this type into various kinds of `dyn Trait` references.
    ///
    /// The default implementation of this method declares that the `Object`
    /// can't be downcast into any traits.
    ///
    /// You should not implement this method yourself; instead use
    /// [`derive_deftly(Object)`](crate::templates::derive_deftly_template_Object).
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

/// Extension trait for `Arc<dyn Object>` to support convenient
/// downcasting to `dyn Trait`.
///
/// You don't need to use this for downcasting to an object's concrete
/// type; for that, use [`downcast_rs::DowncastSync`].
///
/// # Examples
///
/// ```
/// use tor_rpcbase::{Object, ObjectArcExt, templates::*};
/// use derive_deftly::Deftly;
/// use std::sync::Arc;
///
/// #[derive(Deftly)]
/// #[derive_deftly(Object)]
/// #[deftly(rpc(downcastable_to = "HasFeet"))]
/// pub struct Frog {}
/// pub trait HasFeet {
///     fn num_feet(&self) -> usize;
/// }
/// impl HasFeet for Frog {
///     fn num_feet(&self) -> usize { 4 }
/// }
///
/// /// If `obj` is a HasFeet, return how many feet it has.
/// /// Otherwise, return 0.
/// fn check_feet(obj: Arc<dyn Object>) -> usize {
///     let maybe_has_feet: Option<&dyn HasFeet> = obj.cast_to_trait();
///     match maybe_has_feet {
///         Some(foot_haver) => foot_haver.num_feet(),
///         None => 0,
///     }
/// }
///
/// assert_eq!(check_feet(Arc::new(Frog{})), 4);
/// ```
pub trait ObjectArcExt {
    /// Try to cast this `Arc<dyn Object>` to a `T`.  On success, return a reference to
    /// T; on failure, return None.
    fn cast_to_trait<T: ?Sized + 'static>(&self) -> Option<&T>;

    /// Try to cast this `Arc<dyn Object>` to an `Arc<T>`.
    fn cast_to_arc_trait<T: ?Sized + 'static>(self) -> Result<Arc<T>, Arc<dyn Object>>;
}

impl dyn Object {
    /// Try to cast this `Object` to a `T`.  On success, return a reference to
    /// T; on failure, return None.
    ///
    /// This method is only for casting to `&dyn Trait`;
    /// see [`ObjectArcExt`] for limitations.
    pub fn cast_to_trait<T: ?Sized + 'static>(&self) -> Option<&T> {
        let table = self.get_cast_table();
        table.cast_object_to(self)
    }
}

impl ObjectArcExt for Arc<dyn Object> {
    fn cast_to_trait<T: ?Sized + 'static>(&self) -> Option<&T> {
        let obj: &dyn Object = self.as_ref();
        obj.cast_to_trait()
    }
    fn cast_to_arc_trait<T: ?Sized + 'static>(self) -> Result<Arc<T>, Arc<dyn Object>> {
        let table = self.get_cast_table();
        table.cast_object_to_arc(self.clone())
    }
}

define_derive_deftly! {
/// Allow a type to participate as an Object in the RPC system.
///
/// This template implements `Object` for the
/// target type, and can be used to cause objects to participate in the trait
/// downcasting system.
///
/// # Examples
///
/// ## Simple case, just implements `Object`.
///
/// ```
/// use tor_rpcbase::{self as rpc, templates::*};
/// use derive_deftly::Deftly;
///
/// #[derive(Default, Deftly)]
/// #[derive_deftly(Object)]
/// struct Houseplant {
///    oxygen_per_sec: f64,
///    benign_neglect: u8
/// }
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
/// trait that it implements, you can use the `downcastable_to` attributes for `Object` to have
/// it participate in trait downcasting:
///
/// ```
/// use tor_rpcbase::{self as rpc, templates::*};
/// use derive_deftly::Deftly;
///
/// #[derive(Deftly)]
/// #[derive_deftly(Object)]
/// #[deftly(rpc(downcastable_to = "Gizmo, Doodad"))]
/// struct Frobnitz {}
///
/// trait Gizmo {}
/// trait Doodad {}
/// impl Gizmo for Frobnitz {}
/// impl Doodad for Frobnitz {}
///
/// use std::sync::Arc;
/// use rpc::ObjectArcExt; // for the cast_to method.
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
/// ```
/// use tor_rpcbase::{self as rpc, templates::*};
/// use derive_deftly::Deftly;
///
/// #[derive(Deftly)]
/// #[derive_deftly(Object)]
/// #[deftly(rpc(downcastable_to = "ExampleTrait"))]
/// struct Generic<T,U> where T:Clone, U:PartialEq {
///     t: T,
///     u: U,
/// }
///
/// trait ExampleTrait {}
/// impl<T:Clone,U:PartialEq> ExampleTrait for Generic<T,U> {}
///
/// use std::sync::Arc;
/// use rpc::ObjectArcExt; // for the cast_to method.
/// let obj: Arc<dyn rpc::Object> = Arc::new(Generic { t: 42_u8, u: 42_u8 });
/// let tr: &dyn ExampleTrait = obj.cast_to_trait().unwrap();
/// ```
///
/// ## Making an object "exposed outside of the session"
///
/// You flag any kind of Object so that its identifiers will be exported
/// outside of the local RPC session.  (Arti uses this for Objects whose
/// ObjectId needs to be used as a SOCKS identifier.)  To do so,
/// use the `expose_outside_session` attribute:
///
/// ```
/// use tor_rpcbase::{self as rpc, templates::*};
/// use derive_deftly::Deftly;
///
/// #[derive(Deftly)]
/// #[derive_deftly(Object)]
/// #[deftly(rpc(expose_outside_of_session))]
/// struct Visible {}
/// ```
    export Object expect items:

    impl<$tgens> $ttype where
        // We need this restriction in case there are generics
        // that might not impl these traits.
        $ttype: Send + Sync + 'static,
        $twheres
    {
        /// Construct a new `CastTable` for this type.
        ///
        /// This is a function so that we can call it multiple times as
        /// needed if the type is generic.
        ///
        /// Don't invoke this yourself; instead use `decl_object!`.
        #[doc(hidden)]
        fn make_cast_table() -> $crate::CastTable {
            ${if tmeta(rpc(downcastable_to)) {
                $crate::cast_table_deftness_helper!{
                    // TODO ideally we would support multiple downcastable_to rather
                    // than a single list, and use `as ty`
                    ${tmeta(rpc(downcastable_to)) as token_stream}
                }
            } else {
                $crate::CastTable::default()
            }}
        }
    }

    impl<$tgens> $crate::Object for $ttype where
        // We need this restriction in case there are generics
        // that might not impl these traits.
        $ttype: Send + Sync + 'static,
        $twheres
    {
        ${if tmeta(rpc(expose_outside_of_session)) {
            fn expose_outside_of_session(&self) -> bool {
                true
            }
        }}

        fn get_cast_table(&self) -> &$crate::CastTable {
            // TODO RPC: Is there a better way to check "is this a generic type"?
            // See derive-deftly#37
            ${if not(approx_equal({$tgens}, {})) {
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
            } else {
                // For non-generic types, we only ever have a single CastTable,
                // so we can just construct it once and return it.
                use $crate::once_cell::sync::Lazy;
                static TABLE: Lazy<$crate::CastTable> = Lazy::new(|| $ttype::make_cast_table());
                &TABLE
            }}
        }
    }
}
pub use derive_deftly_template_Object;

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
    use derive_deftly::Deftly;

    #[derive(Deftly)]
    #[derive_deftly(Object)]
    #[deftly(rpc(downcastable_to = "HasWheels"))]
    struct Bicycle {}
    trait HasWheels {
        fn num_wheels(&self) -> usize;
    }
    impl HasWheels for Bicycle {
        fn num_wheels(&self) -> usize {
            2
        }
    }

    #[derive(Deftly)]
    #[derive_deftly(Object)]
    struct Opossum {}

    #[test]
    fn standard_cast() {
        let bike = Bicycle {};
        let erased_bike: &dyn Object = &bike;
        let has_wheels: &dyn HasWheels = erased_bike.cast_to_trait().unwrap();
        assert_eq!(has_wheels.num_wheels(), 2);

        let pogo = Opossum {};
        let erased_pogo: &dyn Object = &pogo;
        let has_wheels: Option<&dyn HasWheels> = erased_pogo.cast_to_trait();
        assert!(has_wheels.is_none());
    }

    #[derive(Deftly)]
    #[derive_deftly(Object)]
    #[deftly(rpc(downcastable_to = "HasWheels"))]
    struct Crowd<T: HasWheels + Send + Sync + 'static> {
        members: Vec<T>,
    }
    impl<T: HasWheels + Send + Sync> HasWheels for Crowd<T> {
        fn num_wheels(&self) -> usize {
            self.members.iter().map(T::num_wheels).sum()
        }
    }

    #[test]
    fn generic_cast() {
        let bikes = Crowd {
            members: vec![Bicycle {}, Bicycle {}],
        };
        let erased_bikes: &dyn Object = &bikes;
        let has_wheels: &dyn HasWheels = erased_bikes.cast_to_trait().unwrap();
        assert_eq!(has_wheels.num_wheels(), 4);

        let arc_bikes = Arc::new(bikes);
        let erased_arc_bytes: Arc<dyn Object> = arc_bikes.clone();
        let arc_has_wheels: Arc<dyn HasWheels> =
            erased_arc_bytes.clone().cast_to_arc_trait().ok().unwrap();
        assert_eq!(arc_has_wheels.num_wheels(), 4);

        let ref_has_wheels: &dyn HasWheels = erased_arc_bytes.cast_to_trait().unwrap();
        assert_eq!(ref_has_wheels.num_wheels(), 4);

        trait SomethingElse {}
        let arc_something_else: Result<Arc<dyn SomethingElse>, _> =
            erased_arc_bytes.clone().cast_to_arc_trait();
        let err_arc = arc_something_else.err().unwrap();
        assert!(Arc::ptr_eq(&err_arc, &erased_arc_bytes));
    }
}
