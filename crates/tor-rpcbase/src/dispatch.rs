//! A multiple-argument dispatch system for our RPC system.
//!
//! Our RPC functionality is polymorphic in Methods (what we're told to do) and
//! Objects (the things that we give the methods to); we want to be able to
//! provide different implementations for each method, on each object.

use std::any;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use futures::future::BoxFuture;
use futures::Sink;

use crate::typeid::ConstTypeId_;
use crate::{Context, DynMethod, Object, RpcError, SendUpdateError};

/// A type-erased serializable value.
#[doc(hidden)]
pub type RpcValue = Box<dyn erased_serde::Serialize + Send + 'static>;

/// The return type from an RPC function.
#[doc(hidden)]
pub type RpcResult = Result<RpcValue, RpcError>;

/// The return type from sending an update.
#[doc(hidden)]
pub type RpcSendResult = Result<RpcValue, SendUpdateError>;

/// A boxed future holding the result of an RPC method.
type RpcResultFuture = BoxFuture<'static, RpcResult>;

/// A type-erased RPC-method invocation function.
///
/// This function takes `Arc`s rather than a reference, so that it can return a
/// `'static` future.
type ErasedInvokeFn =
    fn(Arc<dyn Object>, Box<dyn DynMethod>, Box<dyn Context>, BoxedUpdateSink) -> RpcResultFuture;

/// A boxed sink on which updates can be sent.
pub type BoxedUpdateSink = Pin<Box<dyn Sink<RpcValue, Error = SendUpdateError> + Send>>;

/// An entry for our dynamic dispatch code.
///
/// These are generated using [`inventory`] by our `static_rpc_invoke_fn` macro;
/// they are later collected into a more efficient data structure.
#[doc(hidden)]
pub struct InvokeEntry_ {
    obj_id: ConstTypeId_,
    method_id: ConstTypeId_,
    func: ErasedInvokeFn,
}

// Note that using `inventory` here means that _anybody_ can define new
// methods!  This may not be the greatest property.
inventory::collect!(InvokeEntry_);

impl InvokeEntry_ {
    /// Create a new `InvokeEntry_`.
    #[doc(hidden)]
    pub const fn new(obj_id: ConstTypeId_, method_id: ConstTypeId_, func: ErasedInvokeFn) -> Self {
        InvokeEntry_ {
            obj_id,
            method_id,
            func,
        }
    }
}

/// Declare an RPC function that will be used to call a single type of [`Method`](crate::Method) on a
/// single type of [`Object`].
///
/// # Example
///
/// ```
/// use tor_rpcbase::{self as rpc, templates::*};
/// use derive_deftly::Deftly;
///
/// use futures::sink::{Sink, SinkExt};
/// use std::sync::Arc;
///
/// #[derive(Debug, Deftly)]
/// #[derive_deftly(Object)]
/// struct ExampleObject {}
/// #[derive(Debug, Deftly)]
/// #[derive_deftly(Object)]
/// struct ExampleObject2 {}
///
/// #[derive(Debug,serde::Deserialize, Deftly)]
/// #[derive_deftly(DynMethod)]
/// #[deftly(rpc(method_name = "arti:x-example"))]
/// struct ExampleMethod {}
/// impl rpc::Method for ExampleMethod {
///     type Output = ExampleResult;
///     type Update = Progress;
/// }
///
/// #[derive(serde::Serialize)]
/// struct ExampleResult {
///    text: String,
/// }
///
/// #[derive(serde::Serialize)]
/// struct Progress(f64);
///
/// // Note that the types of this function are very constrained:
/// //  - `obj` must be an Arc<O> for some `Object` type.
/// //  - `mth` must be Box<M> for some `Method` type.
/// //  - `ctx` must be Box<dyn rpc::Context>.
/// //  - The function must be async.
/// //  - The return type must be a Result.
/// //  - The OK variant of the result must M::Output.
/// //  - The Err variant of the result must implement Into<rpc::RpcError>.
/// async fn example(obj: Arc<ExampleObject>,
///                  method: Box<ExampleMethod>,
///                  ctx: Box<dyn rpc::Context>) -> Result<ExampleResult, rpc::RpcError> {
///     println!("Running example method!");
///     Ok(ExampleResult { text: "here is your result".into() })
/// }
///
/// rpc::static_rpc_invoke_fn!{
///     example(ExampleObject, ExampleMethod);
/// }
///
/// // You can declare an example that produces updates as well:
/// // - The fourth argument must be `impl Sink<M::Update> + Unpin`.
/// async fn example2(obj: Arc<ExampleObject2>,
///                   method: Box<ExampleMethod>,
///                   ctx: Box<dyn rpc::Context>,
///                   mut updates: impl Sink<Progress, Error=rpc::SendUpdateError> + Unpin
/// ) -> Result<ExampleResult, rpc::RpcError> {
///     updates.send(Progress(0.90)).await?;
///     Ok(ExampleResult { text: "that was fast, wasn't it?".to_string() })
/// }
///
/// rpc::static_rpc_invoke_fn! {
///     example2(ExampleObject2, ExampleMethod) [Updates];
/// }
/// ```
//
// TODO RPC: After #838 succeeds (or fails) document the syntax of this macro.
#[macro_export]
macro_rules! static_rpc_invoke_fn {
    {
        $funcname:ident($objtype:ty, $methodtype:ty $(,)?) $([ $($flag:ident),* $(,)?])?;
        $( $($more:tt)+ )?
    } => {$crate::paste::paste!{
        $crate::decl_rpc_invoke_fn!{@imp-expand $funcname, $objtype, $methodtype, [$($($flag)*)?] }
        $crate::inventory::submit!{
            $crate::dispatch::InvokeEntry_::new(
                $objtype::CONST_TYPE_ID_,
                $methodtype::CONST_TYPE_ID_,
                [<_typeerased_ $funcname >]
            )
        }
        $($crate::static_rpc_invoke_fn!{$($more)*})?
    }};
}

/// Declare a group of RPC functions to call one or more [`Method`](crate::Method)s on a
/// single type of [`Object`], and a function to install them in a dispatch table.
///
/// This approach is used for registering methods on a generic object.
/// If the object type is not generic, it's probably better to use `static_rpc_invoke_fn`.
///
/// # Example
///
/// ```
/// # use std::sync::Arc;
/// # use derive_deftly::Deftly;
/// // Declare a generic object type.
/// use tor_rpcbase as rpc;
/// #[derive(Deftly)]
/// #[derive_deftly(rpc::Object)]
/// pub struct Tuple<A, B>(A,B)
/// where A: Send + Sync + 'static, B: Send + Sync + 'static;
///
/// // Declare a method.
/// #[derive(Deftly, serde::Deserialize, Debug)]
/// #[derive_deftly(rpc::DynMethod)]
/// #[deftly(rpc(method_name = "x-example:mymethod"))]
/// struct MyMethod;
/// impl rpc::Method for MyMethod {
///     type Output = Outcome;
///     type Update = rpc::NoUpdates;
/// }
///
/// #[derive(Debug,serde::Serialize)]
/// struct Outcome {}
///
/// // Declare a function to implement that method for our Tuple.
/// async fn mymethod_for_tuple<A,B>(
///     obj: Arc<Tuple<A,B>>,
///     method: Box<MyMethod>,
///     ctx: Box<dyn rpc::Context>
/// ) -> Result<Outcome, rpc::RpcError>
/// where A: Send + Sync + 'static,
///       B: Send + Sync + 'static
/// {
///     // ..
///     Ok(Outcome {})
/// }
///
/// // Now, declare "install_mymethod::<A,B>(&mut DispatchTable)" as a function to
/// // install the implementation above for a given A,B pair.
/// rpc::installable_rpc_invoke_fn! {
///     pub install_mymethod for Tuple
///     [A,B; where A: Send + Sync + 'static, B: Send + Sync + 'static]
///     {
///         mymethod_for_tuple(MyMethod);
///         // you can list more methods here.
///     }
/// }
///
/// // Now before you use this method, you need to call `install_mymethod` on
/// // your DispatchTable.
/// let mut table = rpc::DispatchTable::from_inventory();
/// install_mymethod::<u64,u64>(&mut table);
/// install_mymethod::<String,f32>(&mut table);
/// ```
///
/// TODO: The syntax here is somewhat awkward, due to the difficulty
/// of handling generics in macro_rules.
//
// TODO RPC: After #838 succeeds (or fails) document the syntax of this macro.
//
// TODO RPC: Look for ways to make it so the caller doesn't (usually) need to name the install
// function.
// See https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2079#note_3018118
#[macro_export]
macro_rules! installable_rpc_invoke_fn {
    {
        $ivis:vis $installfn:ident for $objname:ident
        $gen:tt
        {
            $(
                $funcname:ident($methodtype:ty $(,)?) $([ $($flag:ident),* $(,)?])?
            );+
            $(;)?
        }
    } => {
        $(
            $crate::decl_rpc_invoke_fn!{ @imp-expand $funcname, $objname $gen, $methodtype, [$($($flag)*)?] }
        )+
        $crate::installable_rpc_invoke_fn!{
            @installer
            $ivis $installfn for $objname $gen $( $funcname($methodtype) $gen );+
        }
    };
    {
        @installer $ivis:vis $installfn:ident for $objname:ident
        [$($tgens:ident),*; where $($twheres:tt)*]
        $(
            $funcname:ident($methodtype:ty)
            // This is a hack, to avoid "no expression repeating at this depth."
            [$($tgens2:ident),*; where $($twheres2:tt)*]
        );+
    } => {$crate::paste::paste!{
        $ivis fn $installfn <$($tgens),*> (table: &mut $crate::DispatchTable)
        where $($twheres)*
        {
            let obj_type = std::any::TypeId::of::<$objname <$($tgens),*>> ();
            $(
                table.insert(
                    obj_type,
                    std::any::TypeId::of::<$methodtype>(),
                    [<_typeerased_ $funcname>]::<$($tgens2),*>
                );
            )+
        }
    }}
}

/// Helper: Declare a single type-erased RPC invocation function, but do not
/// register it or give it a means to register it.
#[macro_export]
#[doc(hidden)]
macro_rules! decl_rpc_invoke_fn{
    {
        @imp-expand $funcname:ident, $objname:ident $([$($gen:tt)*])?, $methodtype:ty, []
    } => {
        $crate::decl_rpc_invoke_fn!{@final $funcname, $objname $([$($gen)*])?, $methodtype, }
    };
    {
        @imp-expand $funcname:ident, $objname:ident $([$($gen:tt)*])?, $methodtype:ty, [Updates]
    } => {
        $crate::decl_rpc_invoke_fn!{@final $funcname, $objname $([$($gen)*])?, $methodtype, sink }
    };
    {
        @final $funcname:ident, $objname:ident $([$($tgens:ident),*; where $($twheres:tt)*])?, $methodtype:ty, $($sinkvar:ident)?
    } => {$crate::paste::paste!{
        // We declare a type-erased version of the function that takes Arc<dyn> and Box<dyn> arguments, and returns
        // a boxed future.
        #[doc(hidden)]
        fn [<_typeerased_ $funcname>] $(<$($tgens),*>)? (obj: std::sync::Arc<dyn $crate::Object>,
                                  method: Box<dyn $crate::DynMethod>,
                                  ctx: Box<dyn $crate::Context>,
                                  #[allow(unused)]
                                  sink: $crate::dispatch::BoxedUpdateSink)
        -> $crate::futures::future::BoxFuture<'static, $crate::RpcResult>
            $(where $($twheres)* )?
        {
            type Output = <$methodtype as $crate::Method>::Output;
            use $crate::futures::FutureExt;
            #[allow(unused)]
            use $crate::{
                tor_async_utils::SinkExt as _
            };
            let obj = obj
                .downcast_arc::<$objname $(<$($tgens),*>)? >()
                .unwrap_or_else(|_| panic!());
            let method = method
                .downcast::<$methodtype>()
                .unwrap_or_else(|_| panic!());
            $(
                let $sinkvar = sink.with_fn(|update|
                    $crate::dispatch::RpcSendResult::Ok(Box::new(update))
                );
            )?
            $funcname(obj, method, ctx $(, $sinkvar)?).map(|r| {
                let r: $crate::RpcResult = match r {
                    Ok(v) => Ok(Box::new(Output::from(v))),
                    Err(e) => Err($crate::RpcError::from(e))
                };
                r
            }).boxed()
        }
    }}
}

/// Actual types to use when looking up a function in our HashMap.
#[derive(Eq, PartialEq, Clone, Debug, Hash)]
struct FuncType {
    /// The type of object to which this function applies.
    obj_id: any::TypeId,
    /// The type of method to which this function applies.
    method_id: any::TypeId,
}

/// A collection of method implementations for different method and object types.
///
/// A DispatchTable is constructed at run-time from entries registered with
/// [`static_rpc_invoke_fn!`].
///
/// There is one for each `arti-rpcserver::RpcMgr`, shared with each `arti-rpcserver::Connection`.
#[derive(Debug, Clone)]
pub struct DispatchTable {
    /// An internal HashMap used to look up the correct function for a given
    /// method/object pair.
    map: HashMap<FuncType, ErasedInvokeFn>,
}

impl DispatchTable {
    /// Construct a `DispatchTable` from the entries registered statically via
    /// [`static_rpc_invoke_fn!`].
    ///
    /// # Panics
    ///
    /// Panics if two entries are found for the same (method,object) types.
    pub fn from_inventory() -> Self {
        // We want to assert that there are no duplicates, so we can't use "collect"
        let mut map = HashMap::new();
        for ent in inventory::iter::<InvokeEntry_>() {
            let InvokeEntry_ {
                obj_id,
                method_id,
                func,
            } = *ent;
            let old_val = map.insert(
                FuncType {
                    obj_id: obj_id.into(),
                    method_id: method_id.into(),
                },
                func,
            );
            assert!(
                old_val.is_none(),
                "Tried to register two RPC functions with the same type IDs!"
            );
        }
        Self { map }
    }

    /// Add a new entry to this DispatchTable.
    pub fn insert(&mut self, obj_id: any::TypeId, method_id: any::TypeId, func: ErasedInvokeFn) {
        // TODO RPC: Make this call idempotent; complain if the old func is not the same as the new func.
        self.map.insert(FuncType { obj_id, method_id }, func);
    }

    /// Try to find an appropriate function for calling a given RPC method on a
    /// given RPC-visible object.
    ///
    /// On success, return a Future.
    pub fn invoke(
        &self,
        obj: Arc<dyn Object>,
        method: Box<dyn DynMethod>,
        ctx: Box<dyn Context>,
        sink: BoxedUpdateSink,
    ) -> Result<RpcResultFuture, InvokeError> {
        let func_type = FuncType {
            obj_id: obj.type_id(),
            method_id: method.type_id(),
        };

        let func = self.map.get(&func_type).ok_or(InvokeError::NoImpl)?;

        Ok(func(obj, method, ctx, sink))
    }
}

/// An error that occurred while trying to invoke a method on an object.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InvokeError {
    /// There is no implementation for the given combination of object
    /// type and method type.
    #[error("No implementation for provided object and method types.")]
    NoImpl,
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

    use crate::{templates::*, Method, NoUpdates};
    use derive_deftly::Deftly;
    use futures::SinkExt;
    use futures_await_test::async_test;
    use std::sync::Arc;

    // Define 3 animals and one brick.
    #[derive(Clone, Deftly)]
    #[derive_deftly(Object)]
    struct Swan;
    #[derive(Clone, Deftly)]
    #[derive_deftly(Object)]
    struct Wombat;
    #[derive(Clone, Deftly)]
    #[derive_deftly(Object)]
    struct Sheep;
    #[derive(Clone, Deftly)]
    #[derive_deftly(Object)]
    struct Brick;

    // Define 2 methods.
    #[derive(Debug, serde::Deserialize, Deftly)]
    #[derive_deftly(DynMethod)]
    #[deftly(rpc(method_name = "x-test:getname"))]
    struct GetName;

    #[derive(Debug, serde::Deserialize, Deftly)]
    #[derive_deftly(DynMethod)]
    #[deftly(rpc(method_name = "x-test:getkids"))]
    struct GetKids;

    impl Method for GetName {
        type Output = Outcome;
        type Update = NoUpdates;
    }
    impl Method for GetKids {
        type Output = Outcome;
        type Update = String;
    }

    #[derive(serde::Serialize)]
    struct Outcome {
        v: String,
    }

    async fn getname_swan(
        _obj: Arc<Swan>,
        _method: Box<GetName>,
        _ctx: Box<dyn crate::Context>,
    ) -> Result<Outcome, crate::RpcError> {
        Ok(Outcome {
            v: "swan".to_string(),
        })
    }
    async fn getname_sheep(
        _obj: Arc<Sheep>,
        _method: Box<GetName>,
        _ctx: Box<dyn crate::Context>,
    ) -> Result<Outcome, crate::RpcError> {
        Ok(Outcome {
            v: "sheep".to_string(),
        })
    }
    async fn getname_wombat(
        _obj: Arc<Wombat>,
        _method: Box<GetName>,
        _ctx: Box<dyn crate::Context>,
    ) -> Result<Outcome, crate::RpcError> {
        Ok(Outcome {
            v: "wombat".to_string(),
        })
    }
    async fn getname_brick(
        _obj: Arc<Brick>,
        _method: Box<GetName>,
        _ctx: Box<dyn crate::Context>,
    ) -> Result<Outcome, crate::RpcError> {
        Ok(Outcome {
            v: "brick".to_string(),
        })
    }
    async fn getkids_swan(
        _obj: Arc<Swan>,
        _method: Box<GetKids>,
        _ctx: Box<dyn crate::Context>,
    ) -> Result<Outcome, crate::RpcError> {
        Ok(Outcome {
            v: "cygnets".to_string(),
        })
    }
    async fn getkids_sheep(
        _obj: Arc<Sheep>,
        _method: Box<GetKids>,
        _ctx: Box<dyn crate::Context>,
    ) -> Result<Outcome, crate::RpcError> {
        Ok(Outcome {
            v: "lambs".to_string(),
        })
    }
    async fn getkids_wombat(
        _obj: Arc<Wombat>,
        _method: Box<GetKids>,
        _ctx: Box<dyn crate::Context>,
        mut sink: impl futures::sink::Sink<String> + Unpin, // TODO RPC: Remove "unpin" if possible.
    ) -> Result<Outcome, crate::RpcError> {
        let _ignore = sink.send("brb, burrowing".to_string()).await;
        Ok(Outcome {
            v: "joeys".to_string(),
        })
    }

    static_rpc_invoke_fn! {
        getname_swan(Swan,GetName);
        getname_sheep(Sheep,GetName);
        getname_wombat(Wombat,GetName);
        getname_brick(Brick,GetName);

        getkids_swan(Swan,GetKids);
        getkids_sheep(Sheep,GetKids);
        getkids_wombat(Wombat,GetKids) [Updates];
    }

    struct Ctx {}

    impl crate::Context for Ctx {
        fn lookup_object(
            &self,
            _id: &crate::ObjectId,
        ) -> Result<std::sync::Arc<dyn crate::Object>, crate::LookupError> {
            todo!()
        }
        fn register_owned(&self, _object: Arc<dyn crate::Object>) -> crate::ObjectId {
            todo!()
        }

        fn register_weak(&self, _object: Arc<dyn crate::Object>) -> crate::ObjectId {
            todo!()
        }

        fn release_owned(&self, _object: &crate::ObjectId) -> Result<(), crate::LookupError> {
            todo!()
        }
    }

    #[derive(Deftly, Clone)]
    #[derive_deftly(Object)]
    struct GenericObj<T, U>
    where
        T: Send + Sync + 'static + Clone + ToString,
        U: Send + Sync + 'static + Clone + ToString,
    {
        name: T,
        kids: U,
    }

    async fn getname_generic<T, U>(
        obj: Arc<GenericObj<T, U>>,
        _method: Box<GetName>,
        _ctx: Box<dyn crate::Context>,
    ) -> Result<Outcome, crate::RpcError>
    where
        T: Send + Sync + 'static + Clone + ToString,
        U: Send + Sync + 'static + Clone + ToString,
    {
        Ok(Outcome {
            v: obj.name.to_string(),
        })
    }
    async fn getkids_generic<T, U>(
        obj: Arc<GenericObj<T, U>>,
        _method: Box<GetKids>,
        _ctx: Box<dyn crate::Context>,
    ) -> Result<Outcome, crate::RpcError>
    where
        T: Send + Sync + 'static + Clone + ToString,
        U: Send + Sync + 'static + Clone + ToString,
    {
        Ok(Outcome {
            v: obj.kids.to_string(),
        })
    }
    installable_rpc_invoke_fn! {
        install_generic_fns for
             GenericObj [T,U;
                         where T: Send + Sync + 'static + Clone + ToString,
                               U: Send + Sync + 'static + Clone + ToString]
        {
            getname_generic(GetName);
            getkids_generic(GetKids);
        }
    }

    #[async_test]
    async fn try_invoke() {
        use super::*;
        fn invoke_helper<O: Object, M: Method>(
            table: &DispatchTable,
            obj: O,
            method: M,
        ) -> Result<RpcResultFuture, InvokeError> {
            let animal: Arc<dyn crate::Object> = Arc::new(obj);
            let request: Box<dyn DynMethod> = Box::new(method);
            let ctx = Box::new(Ctx {});
            let discard = Box::pin(futures::sink::drain().sink_err_into());
            table.invoke(animal, request, ctx, discard)
        }
        async fn invoke_ok<O: crate::Object, M: crate::Method>(
            table: &DispatchTable,
            obj: O,
            method: M,
        ) -> String {
            let res = invoke_helper(table, obj, method).unwrap().await.unwrap();
            serde_json::to_string(&res).unwrap()
        }
        async fn sentence<O: crate::Object + Clone>(table: &DispatchTable, obj: O) -> String {
            format!(
                "Hello I am a friendly {} and these are my lovely {}.",
                invoke_ok(table, obj.clone(), GetName).await,
                invoke_ok(table, obj, GetKids).await
            )
        }

        let table = DispatchTable::from_inventory();

        assert_eq!(
            sentence(&table, Swan).await,
            r#"Hello I am a friendly {"v":"swan"} and these are my lovely {"v":"cygnets"}."#
        );
        assert_eq!(
            sentence(&table, Sheep).await,
            r#"Hello I am a friendly {"v":"sheep"} and these are my lovely {"v":"lambs"}."#
        );
        assert_eq!(
            sentence(&table, Wombat).await,
            r#"Hello I am a friendly {"v":"wombat"} and these are my lovely {"v":"joeys"}."#
        );

        assert!(matches!(
            invoke_helper(&table, Brick, GetKids),
            Err(InvokeError::NoImpl)
        ));

        let mut table = table;
        install_generic_fns::<&'static str, &'static str>(&mut table);
        install_generic_fns::<u32, u32>(&mut table);
        let obj1 = GenericObj {
            name: "nuncle",
            kids: "niblings",
        };
        let obj2 = GenericObj {
            name: 1337_u32,
            kids: 271828_u32,
        };
        let obj3 = GenericObj {
            name: 1337_u64,
            kids: 271828_u64,
        };
        assert_eq!(
            sentence(&table, obj1).await,
            r#"Hello I am a friendly {"v":"nuncle"} and these are my lovely {"v":"niblings"}."#
        );
        assert_eq!(
            sentence(&table, obj2).await,
            r#"Hello I am a friendly {"v":"1337"} and these are my lovely {"v":"271828"}."#
        );
        assert!(matches!(
            invoke_helper(&table, obj3, GetKids),
            Err(InvokeError::NoImpl)
        ));
    }
}
