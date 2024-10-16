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
//!     ctx: Arc<dyn rpc::Context>,
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
//!     table.insert(invoker_ent!(my_generic_fn_with_update::<T>));
//! }
//! ```

use std::any;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use futures::future::BoxFuture;
use futures::Sink;

use tor_error::internal;
use void::Void;

#[cfg(feature = "describe-methods")]
pub(crate) mod description;

#[cfg(not(feature = "describe-methods"))]
#[macro_export]
#[doc(hidden)]
macro_rules! register_delegation_note {
    { $from_type:ty, $to_type:ty } => {
    }
}

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
pub type RpcResultFuture = BoxFuture<'static, RpcResult>;

/// A boxed sink on which updates can be sent.
pub type BoxedUpdateSink = Pin<Box<dyn Sink<RpcValue, Error = SendUpdateError> + Send>>;

/// A boxed sink on which updates of a particular type can be sent.
//
// NOTE: I'd like our functions to be able to take `impl Sink<U>` instead,
// but that doesn't work with our macro nonsense.
// Instead, we might choose to specialize `Invoker` if we find that the
// extra boxing in this case ever matters.
pub type UpdateSink<U> = Pin<Box<dyn Sink<U, Error = SendUpdateError> + Send + 'static>>;

/// Type returned by DispatchTable::invoke_special, to represent a future containing
/// a type-erased type.
type SpecialResultFuture = BoxFuture<'static, Box<dyn any::Any>>;

/// An installable handler for running a method on an object type.
///
/// Callers should not typically implement this trait directly;
/// instead, use one of its blanket implementations.
//
// (This trait isn't sealed because there _are_ theoretical reasons
// why you might want to provide a special implementation.)
pub trait Invocable: Send + Sync + 'static {
    /// Return the type of object that this Invocable will accept.
    fn object_type(&self) -> any::TypeId;
    /// Return the type of method that this Invocable will accept.
    fn method_type(&self) -> any::TypeId;
    /// Return the names of the type for the object and methods types this Invocable will accept.
    ///
    /// Caveats apply as for [`any::type_name`].
    fn object_and_method_type_names(&self) -> (&'static str, &'static str);
    /// Describe the types for this Invocable.  Used for debugging.
    fn describe_invocable(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (object_name, method_name) = self.object_and_method_type_names();
        let rpc_method_name = crate::method::method_info_by_typeid(self.method_type())
            .map(|mi| mi.method_name)
            .unwrap_or("???");
        write!(
            f,
            "Invocable({} ({}) for {})",
            method_name, rpc_method_name, object_name,
        )
    }

    /// Invoke this method on an object.
    ///
    /// Requires that `obj` has the type `self.object_type()`,
    /// and that `method` has the type `self.method_type()`.
    ///
    /// Unlike `RpcInvocable::invoke()`, does not convert the resulting types
    /// into serializable formats, and does not require that they _can be_
    /// so converted.
    fn invoke_special(
        &self,
        obj: Arc<dyn Object>,
        method: Box<dyn DynMethod>,
        ctx: Arc<dyn Context>,
    ) -> Result<SpecialResultFuture, InvokeError>;
}

/// Subtrait of `Invocable` that requires its outputs to be serializable as RPC replies.
pub trait RpcInvocable: Invocable {
    /// Invoke a method on an object.
    ///
    /// Requires that `obj` has the type `self.object_type()`,
    /// and that `method` has the type `self.method_type()`.
    fn invoke(
        &self,
        obj: Arc<dyn Object>,
        method: Box<dyn DynMethod>,
        ctx: Arc<dyn Context>,
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
             for fn(Arc<OBJ>, Box<M>, Arc<dyn Context + 'static> $(, $update_arg )? ) -> Fut
        where
            M: crate::Method,
            OBJ: Object,
            S: 'static,
            E: 'static,
            Fut: futures::Future<Output = Result<S,E>> + Send + 'static,
            $( M::Update: From<$update_gen>, )?
            $( $($update_arg_where)+ )?
        {
            fn object_type(&self) -> any::TypeId {
                any::TypeId::of::<OBJ>()
            }

            fn method_type(&self) -> any::TypeId {
                any::TypeId::of::<M>()
            }

            fn object_and_method_type_names(&self) -> (&'static str, &'static str) {
                (
                    any::type_name::<OBJ>(),
                    any::type_name::<M>(),
                )
            }

            fn invoke_special(
                &self,
                obj: Arc<dyn Object>,
                method: Box<dyn DynMethod>,
                ctx: Arc<dyn Context>,
            ) -> Result<SpecialResultFuture, $crate::InvokeError> {
                use futures::FutureExt;
                #[allow(unused)]
                use {tor_async_utils::SinkExt as _, futures::SinkExt as _};

                let Ok(obj) = obj.downcast_arc::<OBJ>() else {
                    return Err(InvokeError::Bug($crate::internal!("Wrong object type")));
                 };
                 let Ok(method) = method.downcast::<M>() else {
                     return Err(InvokeError::Bug($crate::internal!("Wrong method type")));
                 };

                 $(
                    let $sink = Box::pin(futures::sink::drain().sink_err_into());
                 )?

                 Ok(
                    (self)(obj, method, ctx $(, $sink )? )
                        .map(|r| Box::new(r) as Box<dyn any::Any>)
                        .boxed()
                 )
            }
        }

        impl<M, OBJ, Fut, S, E, $($update_gen)?> RpcInvocable
            for fn(Arc<OBJ>, Box<M>, Arc<dyn Context + 'static> $(, $update_arg )? ) -> Fut
        where
            M: crate::RpcMethod,
            M::Output: serde::Serialize,
            S: 'static,
            E: 'static,
            OBJ: Object,
            Fut: futures::Future<Output = Result<S, E>> + Send + 'static,
            M::Output: From<S>,
            RpcError: From<E>,
            $( M::Update: From<$update_gen>, )?
            $( $($update_arg_where)+ )?
        {
            fn invoke(
                &self,
                obj: Arc<dyn Object>,
                method: Box<dyn DynMethod>,
                ctx: Arc<dyn Context>,
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
    update_arg_where: {
        U: 'static + Send,
        M::Update: serde::Serialize
    },
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
    /// The function that implements this method on a given type.
    ///
    /// Always present.
    #[doc(hidden)]
    pub invoker: &'static (dyn Invocable),

    /// The same function as `invoker`, but only if that function implements
    /// `RpcInvocable`
    ///
    /// This will be `None` if this is a "special" method--that is, one whose inputs and outputs are not serializable,
    /// and which is therefore not invocable directly from an RPC connection.
    #[doc(hidden)]
    pub rpc_invoker: Option<&'static (dyn RpcInvocable)>,

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
///   invoker_ent!( function )
///   invoker_ent!( @special function )
/// ```
///
/// The function must be a `fn` item
/// (with all necessary generic parameters specified)
/// with the correct type for an RPC implementation function;
/// see the [module documentation](self).
///
/// If the function is marked as @special,
/// it does not have to return a type serializable as an RPC message,
/// and it will not be exposed as an RPC function.
/// You will still be able to invoke it with `DispatchTable::invoke_special`.
#[macro_export]
macro_rules! invoker_ent {
    { $func:expr } => {
        $crate::invoker_ent!{ @@impl
            func: ($func),
            rpc_invoker:
                (Some($crate::invocable_func_as_dyn_invocable!($func, $crate::dispatch::RpcInvocable))),
        }
    };
    { @special $func:expr } => {
        $crate::invoker_ent!{ @@impl
            func: ($func),
            rpc_invoker: (None),
        }
    };
    { @@impl
            func: ($func:expr),
            rpc_invoker:  ($rpc_invoker:expr),
    }  => {
        $crate::dispatch::InvokerEnt {
            invoker: $crate::invocable_func_as_dyn_invocable!($func, $crate::dispatch::Invocable),
            rpc_invoker: $rpc_invoker,
            file: file!(),
            line: line!(),
            function: stringify!($func)
        }
    };
}

/// Crate a `Vec<` of [`InvokerEnt`].
///
///
/// See `invoker_ent` for function syntax.
///
/// ## Example:
///
/// ```rust,ignore
/// dispatch_table.extend(invoker_ent_list![
///    function1,
///    function2,
///    function3,
/// ]);
/// ```
#[macro_export]
macro_rules! invoker_ent_list {
    { $($(@$tag:ident)* $func:expr),* $(,)? } => {
        vec![
            $(
                $crate::invoker_ent!($(@$tag)* $func)
            ),*
        ]
    }
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
/// impl rpc::RpcMethod for ExampleMethod {
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
/// //  - `ctx` must be Arc<dyn rpc::Context>.
/// //  - The function must be async.
/// //  - The return type must be a Result.
/// //  - The OK variant of the result must M::Output.
/// //  - The Err variant of the result must implement Into<rpc::RpcError>.
/// async fn example(obj: Arc<ExampleObject>,
///                  method: Box<ExampleMethod>,
///                  ctx: Arc<dyn rpc::Context>,
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
///                   ctx: Arc<dyn rpc::Context>,
///                   mut updates: rpc::UpdateSink<Progress>
/// ) -> Result<ExampleResult, rpc::RpcError> {
///     updates.send(Progress(0.90)).await?;
///     Ok(ExampleResult { text: "that was fast, wasn't it?".to_string() })
/// }
///
/// rpc::static_rpc_invoke_fn! {
///     example2;
/// }
/// ```
///
/// # Syntax:
///
/// ```rust,ignore
/// static_rpc_invoke_fn{
///   function;  // zero or morea
///   ...
/// }
/// ```
///
/// where `function` is an expression referring to a static fn item,
/// with all necessary generics.
#[macro_export]
macro_rules! static_rpc_invoke_fn {
    {
        $( $(@$tag:ident)* $func:expr; )*
    } => {$crate::paste::paste!{ $(
        $crate::inventory::submit!{
            $crate::invoker_ent!($(@$tag)* $func)
        }
    )* }};
}

/// Obtain `&'static dyn `[`Invocable`] for a fn item
///
/// Given the name of a suitable fn item with all necessary generics,
/// expands to an expression for it of type `&'static dyn Invocable`.
#[doc(hidden)]
#[macro_export]
macro_rules! invocable_func_as_dyn_invocable { { $f:expr, $trait:path } => { {
    let f = &($f as _);
    // We want ^ this `as _ ` cast to convert the fn item (as a value
    // of its unique unnameable type) to a value of type `fn(..) -> _`.
    // We're not allowed to write `fn(..) -> _`, though.
    //
    // So: we cast it to `_`, and then arrange for the type inference to have to unify
    // the `_` with the appropriate fn type, which we obtain through further trickery.
    if let Some(v) = None {
        // Putting `*f` and the return value from `obtain_fn_type_for`
        // into the same array means that they must have the same type.
        // Ie type inference can see they must be the same type.
        //
        // We would have preferred to write, above, something like
        //     let f = $f as <$f as FnTypeOfFnTrait>::FnType;
        // but the compiler refuses to let us treat the name of the fn item as a type name.
        //
        // We evade this problem by passing `$f` to a function that expects
        // an impl `FnTypeOfFnTrait` and pretends that it would return the `fn` type.
        let _: [_; 2] = [*f, $crate::dispatch::obtain_fn_type_for($f, v)];
    }
    // So, because of all the above, f is of type `fn(..) -> _`, which implements `Invocable`
    // (assuming the fn item has the right signature).  So we can cast it to dyn.
    f as &'static dyn $trait
} } }

/// Helper trait for obtaining (at the type level) `fn` type from an `impl Fn`
///
/// Implemented for all types that implement `Fn`, up to and including 6 arguments.
/// (We only use the arities 3 and 4 right now.)
#[doc(hidden)]
pub trait FnTypeOfFnTrait<X> {
    /// The `fn` type with the same arguments and return type.
    type FnType;
}
/// Provide a blanket implementation of [`FnTypeOfFnTrait`] for some specific arity.
#[doc(hidden)]
macro_rules! impl_fn_type_of_fn_trait { { $($arg:ident)* } => {
    impl<Func, Ret, $($arg),*> FnTypeOfFnTrait<(Ret, $($arg),*)> for Func
    where Func: Fn($($arg),*) -> Ret {
        type FnType = fn($($arg),*) -> Ret;
    }
} }
impl_fn_type_of_fn_trait!();
impl_fn_type_of_fn_trait!(A);
impl_fn_type_of_fn_trait!(A B);
impl_fn_type_of_fn_trait!(A B C);
impl_fn_type_of_fn_trait!(A B C D);
impl_fn_type_of_fn_trait!(A B C D E);
impl_fn_type_of_fn_trait!(A B C D E F);

/// Pretend to return a value of type `fn..` corresponding to an `impl Fn`
///
/// Given a function implementing `FnTypeOfFnTrait`, ie, any `Fn` closure,
/// pretends that it would return a value of the corresponding `fn` type.
///
/// Doesn't actually return a value (since that would be impossible):
/// can only be called in statically unreachable contexts,
/// as evidenced by the uninhabited [`Void`] argument.
///
/// Instead we use the type of its mythical return value, in a non-taken branch,
/// to drive type inference.
#[doc(hidden)]
pub const fn obtain_fn_type_for<X, F: FnTypeOfFnTrait<X>>(_: F, v: Void) -> F::FnType {
    match v {}
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

    /// Add multiple new entries to this DispatchTable.
    ///
    /// # Panics
    ///
    /// As for `insert`.
    pub fn extend<I>(&mut self, ents: I)
    where
        I: IntoIterator<Item = InvokerEnt>,
    {
        ents.into_iter().for_each(|e| self.insert(e));
    }

    /// Helper: Look up the `InvokerEnt` for a given method on a given object,
    /// performing delegation as necessary.
    ///
    /// Along with the `InvokerEnt`, return either the object, or a delegation target
    /// on which the method should be invoked.
    fn resolve_entry(
        &self,
        mut obj: Arc<dyn Object>,
        method_id: std::any::TypeId,
    ) -> Result<(Arc<dyn Object>, &InvokerEnt), InvokeError> {
        loop {
            let obj_id = {
                let dyn_obj: &dyn Object = obj.as_ref();
                dyn_obj.type_id()
            };
            let func_type = FuncType { obj_id, method_id };
            if let Some(ent) = self.map.get(&func_type) {
                return Ok((obj, ent));
            } else if let Some(delegation) = obj.delegate() {
                obj = delegation;
            } else {
                return Err(InvokeError::NoImpl);
            }
        }
    }

    /// Helper: Resolve the invoker for a given RPC object and a given method type,
    /// if there is one.
    ///
    /// Along with the invoker, return either the object, or a delegation target
    /// on which the method should be invoked.
    pub(crate) fn resolve_rpc_invoker(
        &self,
        obj: Arc<dyn Object>,
        method: &dyn DynMethod,
    ) -> Result<(Arc<dyn Object>, &'static dyn RpcInvocable), InvokeError> {
        let (obj, invoker_ent) = self.resolve_entry(obj, method.type_id())?;
        let rpc_invoker = invoker_ent.rpc_invoker.ok_or_else(|| {
            InvokeError::Bug(internal!(
                "Somehow tried to call a special method as an RPC method."
            ))
        })?;
        Ok((obj, rpc_invoker))
    }

    /// Helper: Return the special invoker for a given object and a given method type,
    /// if there is one.
    ///
    /// Along with the invoker, return either the object, or a delegation target
    /// on which the method should be invoked.
    pub(crate) fn resolve_special_invoker<M: crate::Method>(
        &self,
        obj: Arc<dyn Object>,
    ) -> Result<(Arc<dyn Object>, &'static dyn Invocable), InvokeError> {
        let (obj, invoker_ent) = self.resolve_entry(obj, std::any::TypeId::of::<M>())?;
        Ok((obj, invoker_ent.invoker))
    }
}

/// An error that occurred while trying to invoke a method on an object.
#[derive(Debug, Clone, thiserror::Error)]
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

impl From<InvokeError> for RpcError {
    fn from(err: InvokeError) -> Self {
        use crate::RpcErrorKind as EK;
        let kind = match &err {
            InvokeError::NoImpl => EK::MethodNotImpl,
            InvokeError::Bug(_) => EK::InternalError,
        };
        RpcError::new(err.to_string(), kind)
    }
}

#[cfg(test)]
pub(crate) mod test {
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

    use crate::{method::RpcMethod, templates::*, DispatchTable, InvokeError, Method, NoUpdates};
    use derive_deftly::Deftly;
    use futures::SinkExt;
    use futures_await_test::async_test;
    use std::sync::{Arc, RwLock};

    use super::UpdateSink;

    // Define 3 animals and one brick.
    #[derive(Clone, Deftly)]
    #[derive_deftly(Object)]
    pub(crate) struct Swan;
    #[derive(Clone, Deftly)]
    #[derive_deftly(Object)]
    pub(crate) struct Wombat;
    #[derive(Clone, Deftly)]
    #[derive_deftly(Object)]
    pub(crate) struct Sheep;
    #[derive(Clone, Deftly)]
    #[derive_deftly(Object)]
    pub(crate) struct Brick;

    // Define 2 methods.
    #[derive(Debug, serde::Deserialize, Deftly)]
    #[derive_deftly(DynMethod)]
    #[deftly(rpc(method_name = "x-test:getname"))]
    pub(crate) struct GetName;

    #[derive(Debug, serde::Deserialize, Deftly)]
    #[derive_deftly(DynMethod)]
    #[deftly(rpc(method_name = "x-test:getkids"))]
    pub(crate) struct GetKids;

    impl RpcMethod for GetName {
        type Output = Outcome;
        type Update = NoUpdates;
    }
    impl RpcMethod for GetKids {
        type Output = Outcome;
        type Update = String;
    }

    #[derive(serde::Serialize)]
    pub(crate) struct Outcome {
        pub(crate) v: String,
    }

    async fn getname_swan(
        _obj: Arc<Swan>,
        _method: Box<GetName>,
        _ctx: Arc<dyn crate::Context>,
    ) -> Result<Outcome, crate::RpcError> {
        Ok(Outcome {
            v: "swan".to_string(),
        })
    }
    async fn getname_sheep(
        _obj: Arc<Sheep>,
        _method: Box<GetName>,
        _ctx: Arc<dyn crate::Context>,
    ) -> Result<Outcome, crate::RpcError> {
        Ok(Outcome {
            v: "sheep".to_string(),
        })
    }
    async fn getname_wombat(
        _obj: Arc<Wombat>,
        _method: Box<GetName>,
        _ctx: Arc<dyn crate::Context>,
    ) -> Result<Outcome, crate::RpcError> {
        Ok(Outcome {
            v: "wombat".to_string(),
        })
    }
    async fn getname_brick(
        _obj: Arc<Brick>,
        _method: Box<GetName>,
        _ctx: Arc<dyn crate::Context>,
    ) -> Result<Outcome, crate::RpcError> {
        Ok(Outcome {
            v: "brick".to_string(),
        })
    }
    async fn getkids_swan(
        _obj: Arc<Swan>,
        _method: Box<GetKids>,
        _ctx: Arc<dyn crate::Context>,
    ) -> Result<Outcome, crate::RpcError> {
        Ok(Outcome {
            v: "cygnets".to_string(),
        })
    }
    async fn getkids_sheep(
        _obj: Arc<Sheep>,
        _method: Box<GetKids>,
        _ctx: Arc<dyn crate::Context>,
    ) -> Result<Outcome, crate::RpcError> {
        Ok(Outcome {
            v: "lambs".to_string(),
        })
    }
    async fn getkids_wombat(
        _obj: Arc<Wombat>,
        _method: Box<GetKids>,
        _ctx: Arc<dyn crate::Context>,
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
        getkids_wombat;
    }

    pub(crate) struct Ctx {
        table: Arc<RwLock<DispatchTable>>,
    }
    impl From<DispatchTable> for Ctx {
        fn from(table: DispatchTable) -> Self {
            Self {
                table: Arc::new(RwLock::new(table)),
            }
        }
    }

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

        fn dispatch_table(&self) -> &Arc<RwLock<crate::DispatchTable>> {
            &self.table
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
        _ctx: Arc<dyn crate::Context>,
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
        _ctx: Arc<dyn crate::Context>,
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

    // Define an object with delegation.
    #[derive(Clone, Deftly)]
    #[derive_deftly(Object)]
    #[deftly(rpc(
        delegate_with = "|this: &Self| this.contents.clone()",
        delegate_type = "dyn crate::Object"
    ))]
    struct CatCarrier {
        contents: Option<Arc<dyn crate::Object>>,
    }

    #[async_test]
    async fn try_invoke() {
        use super::*;
        fn invoke_helper<O: Object, M: Method>(
            ctx: &Arc<dyn Context>,
            obj: O,
            method: M,
        ) -> Result<RpcResultFuture, InvokeError> {
            let animal: Arc<dyn crate::Object> = Arc::new(obj);
            let request: Box<dyn DynMethod> = Box::new(method);
            let discard = Box::pin(futures::sink::drain().sink_err_into());
            crate::invoke_rpc_method(Arc::clone(ctx), animal, request, discard)
        }
        async fn invoke_ok<O: crate::Object, M: crate::Method>(
            table: &Arc<dyn Context>,
            obj: O,
            method: M,
        ) -> String {
            let res = invoke_helper(table, obj, method).unwrap().await.unwrap();
            serde_json::to_string(&res).unwrap()
        }
        async fn sentence<O: crate::Object + Clone>(table: &Arc<dyn Context>, obj: O) -> String {
            format!(
                "Hello I am a friendly {} and these are my lovely {}.",
                invoke_ok(table, obj.clone(), GetName).await,
                invoke_ok(table, obj, GetKids).await
            )
        }

        let table: Arc<dyn Context> = Arc::new(Ctx::from(DispatchTable::from_inventory()));

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
        {
            let mut tab = table.dispatch_table().write().unwrap();
            GenericObj::<u64, u64>::install_rpc_functions(&mut tab);
        }
        assert_eq!(
            sentence(&table, obj3).await,
            r#"Hello I am a friendly {"v":"13371337"} and these are my lovely {"v":"2718281828"}."#
        );

        // Try with delegation.
        let carrier_1 = CatCarrier {
            contents: Some(Arc::new(Wombat)),
        };
        let carrier_2 = CatCarrier {
            contents: Some(Arc::new(Swan)),
        };
        let carrier_3 = CatCarrier {
            contents: Some(Arc::new(Brick)),
        };
        let carrier_4 = CatCarrier { contents: None };
        assert_eq!(
            sentence(&table, carrier_1).await,
            r#"Hello I am a friendly {"v":"wombat"} and these are my lovely {"v":"joeys"}."#
        );
        assert_eq!(
            sentence(&table, carrier_2).await,
            r#"Hello I am a friendly {"v":"swan"} and these are my lovely {"v":"cygnets"}."#
        );
        assert!(matches!(
            invoke_helper(&table, carrier_3, GetKids),
            Err(InvokeError::NoImpl)
        ));
        assert!(matches!(
            invoke_helper(&table, carrier_4, GetKids),
            Err(InvokeError::NoImpl)
        ));
    }

    // Doesn't implement Deserialize.
    #[derive(Debug)]
    struct MyObject {}

    #[derive(Debug, Deftly)]
    #[derive_deftly(DynMethod)]
    #[deftly(rpc(no_method_name))]
    struct SpecialOnly {}
    impl Method for SpecialOnly {
        type Output = Result<MyObject, MyObject>; // Doesn't implement deserialize.
        type Update = crate::NoUpdates;
    }

    async fn specialonly_swan(
        _obj: Arc<Swan>,
        _method: Box<SpecialOnly>,
        _ctx: Arc<dyn crate::Context>,
    ) -> Result<MyObject, MyObject> {
        Ok(MyObject {})
    }
    static_rpc_invoke_fn! { @special specialonly_swan; }

    #[async_test]
    async fn try_invoke_special() {
        let table = crate::DispatchTable::from_inventory();
        let ctx: Arc<dyn crate::Context> = Arc::new(Ctx::from(table));

        let res: Outcome =
            crate::invoke_special_method(Arc::clone(&ctx), Arc::new(Swan), Box::new(GetKids))
                .await
                .unwrap()
                .unwrap();

        assert_eq!(res.v, "cygnets");

        let _an_obj: MyObject = crate::invoke_special_method(
            Arc::clone(&ctx),
            Arc::new(Swan),
            Box::new(SpecialOnly {}),
        )
        .await
        .unwrap()
        .unwrap();
    }

    #[test]
    fn invoke_poorly() {
        fn is_internal_invoke_err<T>(val: Result<T, InvokeError>) -> bool {
            matches!(val, Err(InvokeError::Bug(_)))
        }

        // Make sure that our invoker function invocations return plausible bugs warnings on
        // misuse.
        let ctx: Arc<dyn crate::Context> = Arc::new(Ctx::from(DispatchTable::from_inventory()));
        let discard = || Box::pin(futures::sink::drain().sink_err_into());

        let table = DispatchTable::from_inventory();
        let (_swan, ent) = table.resolve_rpc_invoker(Arc::new(Swan), &GetKids).unwrap();

        // Wrong method
        let bug = ent.invoke(
            Arc::new(Swan),
            Box::new(GetName),
            Arc::clone(&ctx),
            discard(),
        );
        assert!(is_internal_invoke_err(bug));

        // Wrong object type
        let bug = ent.invoke(
            Arc::new(Wombat),
            Box::new(GetKids),
            Arc::clone(&ctx),
            discard(),
        );
        assert!(is_internal_invoke_err(bug));

        // Special: Wrong method.
        let bug = ent.invoke_special(Arc::new(Swan), Box::new(GetName), Arc::clone(&ctx));
        assert!(is_internal_invoke_err(bug));
        // Special: Wrong object type
        let bug = ent.invoke_special(Arc::new(Wombat), Box::new(GetKids), Arc::clone(&ctx));
        assert!(is_internal_invoke_err(bug));
    }

    #[test]
    fn invoker_ents() {
        let ent1 = invoker_ent!(@special specialonly_swan);
        let ent1b = invoker_ent!(@special specialonly_swan); // Same as 1, but different declaration.
        let ent2 = invoker_ent!(getname_generic::<String, String>);
        let ent2b = invoker_ent!(getname_generic::<String, String>);

        assert_eq!(ent1.same_decl(&ent1), true);
        assert_eq!(ent1.same_decl(&ent1b), false);
        assert_eq!(ent1.same_decl(&ent2), false);

        assert_eq!(ent2.same_decl(&ent2), true);
        assert_eq!(ent2.same_decl(&ent2b), false);

        let re = regex::Regex::new(
            r#"^Invocable\(.*GetName \(x-test:getname\) for .*GenericObj.*String.*String"#,
        )
        .unwrap();
        let debug_fmt = format!("{:?}", &ent2);
        dbg!(&debug_fmt);
        assert!(re.is_match(&debug_fmt));
    }

    #[test]
    fn redundant_invoker_ents() {
        let ent = invoker_ent!(getname_generic::<String, String>);
        let mut table = DispatchTable::from_inventory();

        assert_eq!(ent.same_decl(&ent.clone()), true);
        table.insert(ent.clone());
        table.insert(ent);
    }

    #[test]
    #[should_panic]
    fn conflicting_invoker_ents() {
        let ent = invoker_ent!(getname_generic::<String, String>);
        let ent2 = invoker_ent!(getname_generic::<String, String>);
        let mut table = DispatchTable::from_inventory();
        table.insert(ent);
        table.insert(ent2);
    }
}
