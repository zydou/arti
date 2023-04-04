//! A multiple-argument dispatch system for our RPC system.
//!
//! Our RPC functionality is polymorphic in Commands (what we're told to do) and
//! Objects (the things that we give the commands to); we want to be able to
//! provide different implementations for each command, on each object.

use std::collections::HashMap;
use std::sync::Arc;

use futures::future::BoxFuture;
use once_cell::sync::Lazy;

use crate::typeid::ConstTypeId_;
use crate::{Command, Context, Object, RpcError};

/// The return type from an RPC function.
#[doc(hidden)]
pub type RpcResult = Result<Box<dyn erased_serde::Serialize + Send + 'static>, RpcError>;

// A boxed future holding the result of an RPC command.
type RpcResultFuture = BoxFuture<'static, RpcResult>;

/// A type-erased RPC-command invocation function.
///
/// This function takes `Arc`s rather than a reference, so that it can return a
/// `'static` future.
type ErasedInvokeFn = fn(Arc<dyn Object>, Box<dyn Command>, Arc<dyn Context>) -> RpcResultFuture;

/// An entry for our dynamic dispatch code.
///
/// These are generated using [`inventory`] by our `rpc_invoke_fn` macro;
/// they are later collected into a more efficient data structure.
#[doc(hidden)]
pub struct InvokeEntry_ {
    obj_id: ConstTypeId_,
    cmd_id: ConstTypeId_,
    func: ErasedInvokeFn,
}

// Note that using `inventory` here means that _anybody_ can define new
// commands!  This may not be the greatest property.
inventory::collect!(InvokeEntry_);

impl InvokeEntry_ {
    /// Create a new `InvokeEntry_`.
    #[doc(hidden)]
    pub const fn new(obj_id: ConstTypeId_, cmd_id: ConstTypeId_, func: ErasedInvokeFn) -> Self {
        InvokeEntry_ {
            obj_id,
            cmd_id,
            func,
        }
    }
}

/// Declare an RPC function that will be used to call a single type of [`Command`] on a
/// single type of [`Object`].
///
/// # Example
///
/// ```
/// use tor_rpccmd::{self as rpc};
///
/// #[derive(Debug)]
/// struct ExampleObject {}
/// impl rpc::Object for ExampleObject {}
/// rpc::decl_object! {ExampleObject}
///
/// #[derive(Debug,serde::Deserialize)]
/// struct ExampleCommand {}
/// #[typetag::deserialize]
/// impl rpc::Command for ExampleCommand {}
/// rpc::decl_command! {ExampleCommand}
///
/// #[derive(serde::Serialize)]
/// struct ExampleResult {
///    text: String,
/// }
///
/// rpc::rpc_invoke_fn!{
///     // Note that the types of this function are very constrained:
///     //  - `obj` must be an Arc<O> for some `Object` type.
///     //  - `cmd` must be Box<C> for come `Command` type.
///     //  - `ctx` must be Arc<dyn rpc::Context>.
///     //  - The return type must be a Result.
///     //  - The OK variant of the result must be Serialize + Send + 'static.
///     //  - The Err variant of the result must implement Into<rpc::RpcError>.
///     async fn example(obj: Arc<ExampleObject>,
///                      cmd: Box<ExampleCommand>,
///                      ctx: Arc<dyn rpc::Context>) -> Result<ExampleResult, rpc::RpcError> {
///         println!("Running example command!");
///         Ok(ExampleResult { text: "here is your result".into() })
///     }
/// }
/// ```
#[macro_export]
macro_rules! rpc_invoke_fn {
    {
        $(#[$meta:meta])*
        $v:vis async fn $name:ident($obj:ident : Arc<$objtype:ty>, $cmd:ident: Box<$cmdtype:ty>, $ctx:ident: Arc<dyn $ctxtype:ty>) -> $rtype:ty {
            $($body:tt)*
        }
        $( $($more:tt)+ )?
    } => {$crate::paste::paste!{
        // First we declare the function that the user gave us.
        $(#[$meta])*
        $v async fn $name($obj: std::sync::Arc<$objtype>, $cmd: Box<$cmdtype>, $ctx: std::sync::Arc<dyn $ctxtype>) -> $rtype {
           $($body)*
        }
        // Now we declare a type-erased version of the function that takes Arc<dyn> and Box<dyn> arguments, and returns
        // a boxed future.
        #[doc(hidden)]
        fn [<_typeerased_ $name>](obj: std::sync::Arc<dyn $crate::Object>,
                                  cmd: Box<dyn $crate::Command>,
                                  ctx: std::sync::Arc<dyn $crate::Context>)
        -> $crate::futures::future::BoxFuture<'static, $crate::RpcResult> {
            use $crate::futures::FutureExt;
            let obj = obj
                .downcast_arc::<$objtype>()
                .unwrap_or_else(|_| panic!());
            let cmd = cmd
                .downcast::<$cmdtype>()
                .unwrap_or_else(|_| panic!());
            $name(obj, cmd, ctx).map(|r| {
                let r: $crate::RpcResult = match r {
                    Ok(v) => Ok(Box::new(v)),
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
                <$cmdtype as $crate::typeid::HasConstTypeId_>::CONST_TYPE_ID_,
                [<_typeerased_ $name >]
            )
        }

        $(rpc_invoke_fn!{$($more)+})?
    }}
}

/// Actual types to use when looking up a function in our HashMap.
#[derive(Eq, PartialEq, Clone, Debug, Hash)]
struct FuncType {
    obj_id: ConstTypeId_,
    cmd_id: ConstTypeId_,
}

/// Table mapping `FuncType` to `ErasedInvokeFn`.
///
/// This is constructed once, the first time we use our dispatch code.
static FUNCTION_TABLE: Lazy<HashMap<FuncType, ErasedInvokeFn>> = Lazy::new(|| {
    // We want to assert that there are no duplicates, so we can't use "collect"
    let mut map = HashMap::new();
    for ent in inventory::iter::<InvokeEntry_>() {
        let InvokeEntry_ {
            obj_id,
            cmd_id,
            func,
        } = *ent;
        let old_val = map.insert(FuncType { obj_id, cmd_id }, func);
        assert!(
            old_val.is_none(),
            "Tried to register two RPC functions with the same type IDs!"
        );
    }
    map
});

/// An error that occurred while trying to invoke a command on an object.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InvokeError {
    /// There is no implementation for the given combination of object
    /// type and command type.
    #[error("No implementation for provided object and command types.")]
    NoImpl,
}

/// Try to find an appropriate function for calling a given RPC command on a
/// given RPC-visible object.
///
/// On success, return a Future.
pub fn invoke_command(
    obj: Arc<dyn Object>,
    cmd: Box<dyn Command>,
    ctx: Arc<dyn Context>,
) -> Result<RpcResultFuture, InvokeError> {
    let func_type = FuncType {
        obj_id: obj.const_type_id(),
        cmd_id: cmd.const_type_id(),
    };

    let func = FUNCTION_TABLE.get(&func_type).ok_or(InvokeError::NoImpl)?;

    Ok(func(obj, cmd, ctx))
}

#[cfg(test)]
mod test {
    use futures_await_test::async_test;

    pub struct Animal {}

    #[derive(Debug, serde::Deserialize)]
    pub struct SayHi {}
    impl crate::Object for Animal {}
    #[typetag::deserialize]
    impl crate::Command for SayHi {}

    crate::decl_object! {Animal}
    crate::decl_command! {SayHi}

    #[derive(serde::Serialize)]
    struct Hello {
        name: String,
    }

    rpc_invoke_fn! {
        /// Hello there
        async fn invoke(_obj: Arc<Animal>, cmd: Box<SayHi>, _ctx: Arc<dyn crate::Context>) -> Result<Hello, crate::RpcError> {
            Ok(Hello{ name: format!("{:?}", cmd) })
        }
    }

    struct Ctx {}
    #[async_trait::async_trait]
    impl crate::Context for Ctx {
        fn lookup_object(
            &self,
            _id: &crate::ObjectId,
        ) -> Option<std::sync::Arc<dyn crate::Object>> {
            todo!()
        }

        fn accepts_updates(&self) -> bool {
            false
        }

        async fn send_untyped_update(
            &self,
            _update: Box<dyn erased_serde::Serialize + Send>,
        ) -> Result<(), crate::SendUpdateError> {
            Ok(())
        }
    }

    // TODO RPC: Improve this test!
    #[async_test]
    async fn t() {
        use super::*;
        let animal: Arc<dyn Object> = Arc::new(Animal {});
        let hi: Box<dyn Command> = Box::new(SayHi {});
        let ctx = Arc::new(Ctx {});
        let s = invoke_command(animal, hi, ctx).unwrap().await;
        assert_eq!(
            serde_json::to_string(&s.unwrap_or_else(|_| panic!())).unwrap(),
            r#"{"name":"SayHi"}"#
        );
    }
}
