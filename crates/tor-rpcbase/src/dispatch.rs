//! A multiple-argument dispatch system for our RPC system.
//!
//! Our RPC functionality is polymorphic in Methods (what we're told to do) and
//! Objects (the things that we give the methods to); we want to be able to
//! provide different implementations for each method, on each object.
//!
//! ## Writing RPC functions
//! <a name="func"></a>
//!
//! To participate in this system, an RPC function must have a particular type:
//! ```rust,ignore
//! async fn my_rpc_func(
//!     target: Arc<OBJTYPE>,
//!     method: Box<METHODTYPE>,
//!     ctx: Box<dyn rpc::Context>,
//!     [ updates: rpc::UpdateSink<METHODTYPE::Update ] // this argument is optional!
//! ) -> Result<METHODTYPE::Output, impl Into<rpc::RpcError>>
//! { ... }
//! ```
//!
//! If the "updates" argument is present,
//! then you will need to use the `[Updates]` flag when registering this function.
//!
//! ## Registering RPC functions statically
//!
//! After writing a function in the form above,
//! you need to register it with the RPC system so that it can be invoked on objects of the right type.
//! The easiest way to do so is by registering it, using [`static_rpc_invoke_fn!`](crate::static_rpc_invoke_fn):
//!
//! ```rust,ignore
//! static_rpc_invoke_fn!{ my_rpc_func; my_other_rpc_func; }
//! ```
//!
//! If your function takes an updates sink, the syntax is:
//! ```rust,ignore
//! static_rpc_invoke_fn!{ my_rpc_func [Updates]; }
//! ```
//!
//! You can register particular instantiations of generic types, if they're known ahead of time:
//! ```rust,ignore
//! static_rpc_invoke_fn!{ my_generic_fn::<PreferredRuntime>; }
//! ```
//!
//! ## Registering RPC functions at runtime.
//!
//! If you can't predict all the instantiations of your function in advance,
//! you can insert them into a [`DispatchTable`] at run time:
//! ```rust,ignore
//! fn install_my_rpc_methods<T>(table: &mut DispatchTable) {
//!     table.insert(invoker_ent!(my_generic_fn::<T>));
//!     table.insert(invoker_ent!(my_generic_fn_with_update::<T>) [Updates]);
//! }
//! ```

use std::any;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use futures::future::BoxFuture;
use futures::Sink;

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

/// A boxed sink on which updates can be sent.
pub type BoxedUpdateSink = Pin<Box<dyn Sink<RpcValue, Error = SendUpdateError> + Send>>;

/// A boxed sink on which updates of a particular type can be sent.
//
// NOTE: I'd like our functions to be able to take `impl Sink<U>` instead,
// but that doesn't work with our macro nonsense.
// Instead, we might choose to specialize `Invoker` if we find that the
// extra boxing in this case ever matters.
pub type UpdateSink<U> = Pin<Box<dyn Sink<U, Error = SendUpdateError> + Send + 'static>>;

/// An installable handler for running a method on an object type.
///
/// Callers should not typically implement this trait directly;
/// instead, use one of its blanket implementations.
//
// (This trait isn't sealed because there _are_ theoretical reasons
// why you might want to provide a special implementation.)
pub trait Invocable: Send + Sync + 'static {
    /// Return the type of object that this Invokable will accept.
    fn object_type(&self) -> any::TypeId;
    /// Return the type of method that this Invocable will accept.
    fn method_type(&self) -> any::TypeId;
    /// Describe the types for this Invocable.  Used for debugging.
    fn describe_invocable(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;
    /// Invoke a method on an object.
    ///
    /// Requires that `obj` has the type `self.object_type()`,
    /// and that `method` has the type `self.method_type()`.
    fn invoke(
        &self,
        obj: Arc<dyn Object>,
        method: Box<dyn DynMethod>,
        ctx: Box<dyn Context>,
        sink: BoxedUpdateSink,
    ) -> Result<RpcResultFuture, InvokeError>;
}

/// Helper: Declare a blanket implementation for Invocable.
///
/// We provide two blanket implementations:
/// Once over a fn() taking an update sink,
/// and once over a fn() not taking an update sink.
macro_rules! declare_invocable_impl {
    {
      // These arguments are used to fill in some blanks that we need to use
      // when handling an update sink.
      $( update_gen: $update_gen:ident,
         update_arg: { $sink:ident: $update_arg:ty } ,
         update_arg_where: { $($update_arg_where:tt)+ } ,
         sink_fn: $sink_fn:expr
      )?
    } => {
        impl<M, OBJ, Fut, S, E, $($update_gen)?> Invocable
            for fn(Arc<OBJ>, Box<M>, Box<dyn Context + 'static> $(, $update_arg )? ) -> Fut
        where
            M: crate::Method,
            OBJ: Object,
            Fut: futures::Future<Output = Result<S, E>> + Send + 'static,
            M::Output: From<S>,
            RpcError: From<E>,
            $( M::Update: From<$update_gen>, )?
            $( $($update_arg_where)+ )?
        {
            fn object_type(&self) -> any::TypeId {
                any::TypeId::of::<OBJ>()
            }

            fn method_type(&self) -> any::TypeId {
                any::TypeId::of::<M>()
            }

            fn describe_invocable(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "Invocable({:?}.{:?})",
                    any::type_name::<OBJ>(),
                    any::type_name::<M>(),
                )
            }

            fn invoke(
                &self,
                obj: Arc<dyn Object>,
                method: Box<dyn DynMethod>,
                ctx: Box<dyn Context>,
                #[allow(unused)]
                sink: BoxedUpdateSink,
            ) -> Result<RpcResultFuture, $crate::InvokeError> {
                use futures::FutureExt;
                #[allow(unused)]
                use tor_async_utils::SinkExt as _;
                let Ok(obj) = obj.downcast_arc::<OBJ>() else {
                   return Err(InvokeError::Bug($crate::internal!("Wrong object type")));
                };
                let Ok(method) = method.downcast::<M>() else {
                    return Err(InvokeError::Bug($crate::internal!("Wrong method type")));
                };
                $(
                #[allow(clippy::redundant_closure_call)]
                let $sink = {
                    ($sink_fn)(sink)
                };
                )?

                Ok(
                    (self)(obj, method, ctx $(, $sink)? )
                        .map(|r| {
                            let r: RpcResult = match r {
                                Ok(v) => Ok(Box::new(M::Output::from(v))),
                                Err(e) => Err(RpcError::from(e)),
                            };
                            r
                        })
                        .boxed()
                )
            }
        }
    }
}

declare_invocable_impl! {}

declare_invocable_impl! {
    update_gen: U,
    update_arg: { sink: UpdateSink<U> },
    update_arg_where: { U: 'static },
    sink_fn: |sink:BoxedUpdateSink| Box::pin(
        sink.with_fn(|update: U| RpcSendResult::Ok(
            Box::new(M::Update::from(update))
        )
    ))
}

/// An annotated Invocable; used to compile a [`DispatchTable`].
///
/// Do not construct this type directly!  Instead, use [`invoker_ent!`](crate::invoker_ent!).
#[allow(clippy::exhaustive_structs)]
#[derive(Clone, Copy)]
#[must_use]
pub struct InvokerEnt {
    #[doc(hidden)]
    pub invoker: &'static (dyn Invocable),

    // These fields are used to make sure that we aren't installing different
    // functions for the same (Object, Method) pair.
    // This is a bit of a hack, but we can't do reliable comparison on fn(),
    // so this is our next best thing.
    #[doc(hidden)]
    pub file: &'static str,
    #[doc(hidden)]
    pub line: u32,
    #[doc(hidden)]
    pub function: &'static str,
}
impl InvokerEnt {
    /// Return true if these two entries appear to be the same declaration
    /// for the same function.
    //
    // It seems like it should be possible to compare these by pointer equality, somehow.
    // But that would have to be done by comparing `&dyn`, including their vtables,
    // and Rust's vtables aren't at all stable.  This is a sanity check, not critical
    // for correctness or security, so it's fine that it will catch most mistakes but
    // not deliberate abuse or exciting stunts.
    fn same_decl(&self, other: &Self) -> bool {
        self.file == other.file && self.line == other.line && self.function == other.function
    }
}

/// Create an [`InvokerEnt`] around a single function.
///
/// Syntax:
/// ```rust,ignore
///   invoker_ent!( function_name [flags] )
///   invoker_ent!( (function_expr) [flags] )
/// ```
///
/// Recognized flags are: `Updates`.
/// If no flags are given,
/// the entire `[flags]` list may be omitted.
///
/// The function must have the correct type for an RPC implementation function;
/// see the [module documentation](self).
#[macro_export]
macro_rules! invoker_ent {
    { $func:ident $(::<$($fgens:ty),*>)? $([$($flag:ident),*])? } => {
        $crate::dispatch::InvokerEnt {
            invoker: &($func $(::<$($fgens),*>)? as $crate::invoker_func_type!{ $([$($flag),*])? }),
            file: file!(),
            line: line!(),
            function: stringify!($func)
        }
    };
}
impl std::fmt::Debug for InvokerEnt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.invoker.describe_invocable(f)
    }
}
inventory::collect!(InvokerEnt);

/// Cause one or more RPC functions to be statically registered,
/// each for handling a single Method on a single Object type.
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
///                  ctx: Box<dyn rpc::Context>,
/// ) -> Result<ExampleResult, rpc::RpcError> {
///     println!("Running example method!");
///     Ok(ExampleResult { text: "here is your result".into() })
/// }
///
/// rpc::static_rpc_invoke_fn!{example;}
///
/// // You can declare an example that produces updates as well:
/// // - The fourth argument must be `UpdateSink<M::Update>`.
/// async fn example2(obj: Arc<ExampleObject2>,
///                   method: Box<ExampleMethod>,
///                   ctx: Box<dyn rpc::Context>,
///                   mut updates: rpc::UpdateSink<Progress>
/// ) -> Result<ExampleResult, rpc::RpcError> {
///     updates.send(Progress(0.90)).await?;
///     Ok(ExampleResult { text: "that was fast, wasn't it?".to_string() })
/// }
///
/// rpc::static_rpc_invoke_fn! {
///     example2 [Updates];
/// }
/// ```
///
/// # Syntax:
///
/// ```rust,ignore
/// static_rpc_invoke_fn{
///   ( IDENT  $(::<GENS>)? ([Updates])? ; ) *
/// }
/// ```
#[macro_export]
macro_rules! static_rpc_invoke_fn {
    {
        $funcname:ident $(::<$($fgens:ty),*>)? $([ $($flag:ident),* $(,)?])?;
        $( $($more:tt)+ )?
    } => {$crate::paste::paste!{
        $crate::inventory::submit!{
            $crate::invoker_ent!($funcname $(::<$($fgens),*>)? $([$($flag),*])? )
        }
        $( $crate::static_rpc_invoke_fn!{ $($more)+ } )?
    }};
}

/// Given a list of flags from an invoke function,
/// yield the function type that we need to cast to.
#[doc(hidden)]
#[macro_export]
macro_rules! invoker_func_type {
    { } => { fn(_,_,_) -> _ };
    { [] } => { fn(_,_,_) -> _ };
    { [Updates $(,)?] } => { fn(_,_,_,_) -> _ };
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
    map: HashMap<FuncType, InvokerEnt>,
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
        let mut this = Self {
            map: HashMap::new(),
        };
        for ent in inventory::iter::<InvokerEnt>() {
            let old_val = this.insert_inner(*ent);
            if old_val.is_some() {
                panic!("Tried to insert duplicate entry for {:?}", ent);
            }
        }
        this
    }

    /// Add a new entry to this DispatchTable, and return the old value if any.
    fn insert_inner(&mut self, ent: InvokerEnt) -> Option<InvokerEnt> {
        self.map.insert(
            FuncType {
                obj_id: ent.invoker.object_type(),
                method_id: ent.invoker.method_type(),
            },
            ent,
        )
    }

    /// Add a new entry to this DispatchTable.
    ///
    /// # Panics
    ///
    /// Panics if there was a previous entry inserted with the same (Object,Method) pair,
    /// but (apparently) with a different implementation function, or from a macro invocation.
    pub fn insert(&mut self, ent: InvokerEnt) {
        if let Some(old_ent) = self.insert_inner(ent) {
            // This is not a perfect check by any means; see `same_decl`.
            assert!(old_ent.same_decl(&ent));
        }
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

        func.invoker.invoke(obj, method, ctx, sink)
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

    /// An internal problem occurred while invoking a method.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
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

    use super::UpdateSink;

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
        mut sink: UpdateSink<String>,
    ) -> Result<Outcome, crate::RpcError> {
        let _ignore = sink.send("brb, burrowing".to_string()).await;
        Ok(Outcome {
            v: "joeys".to_string(),
        })
    }

    static_rpc_invoke_fn! {
        getname_swan;
        getname_sheep;
        getname_wombat;
        getname_brick;

        getkids_swan;
        getkids_sheep;
        getkids_wombat [Updates];
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

    // We can also install specific instantiations statically.
    static_rpc_invoke_fn! {
        getname_generic::<u32,u32>;
        getname_generic::<&'static str, &'static str>;
        getkids_generic::<u32,u32>;
        getkids_generic::<&'static str, &'static str>;
    }

    // And we can make code to install them dynamically too.
    impl<T, U> GenericObj<T, U>
    where
        T: Send + Sync + 'static + Clone + ToString,
        U: Send + Sync + 'static + Clone + ToString,
    {
        fn install_rpc_functions(table: &mut super::DispatchTable) {
            table.insert(invoker_ent!(getname_generic::<T, U>));
            table.insert(invoker_ent!(getkids_generic::<T, U>));
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

        /*
        install_generic_fns::<&'static str, &'static str>(&mut table);
        install_generic_fns::<u32, u32>(&mut table);
        */
        let obj1 = GenericObj {
            name: "nuncle",
            kids: "niblings",
        };
        let obj2 = GenericObj {
            name: 1337_u32,
            kids: 271828_u32,
        };
        assert_eq!(
            sentence(&table, obj1).await,
            r#"Hello I am a friendly {"v":"nuncle"} and these are my lovely {"v":"niblings"}."#
        );
        assert_eq!(
            sentence(&table, obj2).await,
            r#"Hello I am a friendly {"v":"1337"} and these are my lovely {"v":"271828"}."#
        );

        let obj3 = GenericObj {
            name: 13371337_u64,
            kids: 2718281828_u64,
        };
        assert!(matches!(
            invoke_helper(&table, obj3.clone(), GetKids),
            Err(InvokeError::NoImpl)
        ));
        let mut table = table;
        GenericObj::<u64, u64>::install_rpc_functions(&mut table);
        assert_eq!(
            sentence(&table, obj3).await,
            r#"Hello I am a friendly {"v":"13371337"} and these are my lovely {"v":"2718281828"}."#
        );
    }
}
