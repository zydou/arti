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
/// These are generated using [`inventory`] by our `rpc_invoke_fn` macro;
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
/// use tor_rpcbase::{self as rpc};
/// use std::sync::Arc;
///
/// #[derive(Debug)]
/// struct ExampleObject {}
/// impl rpc::Object for ExampleObject {}
/// rpc::decl_object! {ExampleObject}
///
/// #[derive(Debug,serde::Deserialize)]
/// struct ExampleMethod {}
/// rpc::decl_method! { "arti:x-example" => ExampleMethod}
/// impl rpc::Method for ExampleMethod {
///     type Output = ExampleResult;
///     type Update = rpc::NoUpdates;
/// }
///
/// #[derive(serde::Serialize)]
/// struct ExampleResult {
///    text: String,
/// }
///
/// // Note that the types of this function are very constrained:
/// //  - `obj` must be an Arc<O> for some `Object` type.
/// //  - `mth` must be Box<M> for some `Method` type.
/// //  - `ctx` must be Box<dyn rpc::Context>.
/// //  - The function must be async.
/// //  - The return type must be a Result.
/// //  - The OK variant of the result must be Serialize + Send + 'static.
/// //  - The Err variant of the result must implement Into<rpc::RpcError>.
/// async fn example(obj: Arc<ExampleObject>,
///                  method: Box<ExampleMethod>,
///                  ctx: Box<dyn rpc::Context>) -> Result<ExampleResult, rpc::RpcError> {
///     println!("Running example method!");
///     Ok(ExampleResult { text: "here is your result".into() })
/// }
///
/// rpc::rpc_invoke_fn!{
///     example(ExampleObject, ExampleMethod);
/// }
/// ```
#[macro_export]
macro_rules! rpc_invoke_fn {
    {
        $funcname:ident($objtype:ty, $methodtype:ty $(, $sink:ident: Sink)? $(,)?);  // XXXX sink syntax not final.
        $( $($more:tt)+ )?
    } => {$crate::paste::paste!{
        // We declare a type-erased version of the function that takes Arc<dyn> and Box<dyn> arguments, and returns
        // a boxed future.
        #[doc(hidden)]
        fn [<_typeerased_ $funcname>](obj: std::sync::Arc<dyn $crate::Object>,
                                  method: Box<dyn $crate::DynMethod>,
                                  ctx: Box<dyn $crate::Context>,
                                  #[allow(unused)]
                                  sink: $crate::dispatch::BoxedUpdateSink)
        -> $crate::futures::future::BoxFuture<'static, $crate::RpcResult> {
            type Output = <$methodtype as $crate::Method>::Output;
            use $crate::futures::FutureExt;
            #[allow(unused)]
            use $crate::{
                tor_async_utils::SinkExt as _
            };
            let obj = obj
                .downcast_arc::<$objtype>()
                .unwrap_or_else(|_| panic!());
            let method = method
                .downcast::<$methodtype>()
                .unwrap_or_else(|_| panic!());
            $(
                let $sink = sink.with_fn(|update|
                    $crate::dispatch::RpcSendResult::Ok(Box::new(update))
                );
            )?
            $funcname(obj, method, ctx $(, $sink)?).map(|r| {
                let r: $crate::RpcResult = match r {
                    Ok(v) => Ok(Box::new(Output::from(v))),
                    Err(e) => Err($crate::RpcError::from(e))
                };
                r
            }).boxed()
        }
        // Finally we use `inventory` to register the type-erased function with
        // the right types.
        $crate::inventory::submit!{
            $crate::dispatch::InvokeEntry_::new(
                <$objtype as $crate::typeid::HasConstTypeId_>::CONST_TYPE_ID_,
                <$methodtype as $crate::typeid::HasConstTypeId_>::CONST_TYPE_ID_,
                [<_typeerased_ $funcname >]
            )
        }

        $(rpc_invoke_fn!{$($more)+})?
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
/// [`rpc_invoke_fn!`].
#[derive(Debug, Clone)]
pub struct DispatchTable {
    /// An internal HashMap used to look up the correct function for a given
    /// method/object pair.
    map: HashMap<FuncType, ErasedInvokeFn>,
}

impl DispatchTable {
    /// Construct a `DispatchTable` from the entries registered statically via
    /// [`rpc_invoke_fn!`].
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
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use crate::{Method, NoUpdates};
    use futures::SinkExt;
    use futures_await_test::async_test;
    use std::sync::Arc;

    // Define 3 animals and one brick.
    #[derive(Clone)]
    struct Swan;
    #[derive(Clone)]
    struct Wombat;
    #[derive(Clone)]
    struct Sheep;
    #[derive(Clone)]
    struct Brick;

    impl crate::Object for Swan {}
    impl crate::Object for Wombat {}
    impl crate::Object for Sheep {}
    impl crate::Object for Brick {}
    crate::decl_object! {Swan Wombat Sheep Brick}

    // Define 2 methods.
    #[derive(Debug, serde::Deserialize)]
    struct GetName;
    #[derive(Debug, serde::Deserialize)]
    struct GetKids;
    crate::decl_method! { "x-test:getname"=>GetName, "x-test:getkids" => GetKids}
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

    rpc_invoke_fn! {
        getname_swan(Swan,GetName);
        getname_sheep(Sheep,GetName);
        getname_wombat(Wombat,GetName);
        getname_brick(Brick,GetName);

        getkids_swan(Swan,GetKids);
        getkids_sheep(Sheep,GetKids);
        getkids_wombat(Wombat,GetKids,sink:Sink);
    }

    struct Ctx {}

    impl crate::Context for Ctx {
        fn lookup_object(
            &self,
            _id: &crate::ObjectId,
        ) -> Result<std::sync::Arc<dyn crate::Object>, crate::LookupError> {
            todo!()
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
    }
}
