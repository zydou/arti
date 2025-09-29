#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![allow(renamed_and_removed_lints)] // @@REMOVE_WHEN(ci_arti_stable)
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_duration_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::mod_module_files)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
#![allow(clippy::needless_lifetimes)] // See arti#1765
#![allow(mismatched_lifetime_syntaxes)] // temporary workaround for arti#2060
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

pub mod dispatch;
mod err;
mod method;
mod obj;

use std::{collections::HashSet, convert::Infallible, sync::Arc};

pub use dispatch::{DispatchTable, InvokeError, UpdateSink};
pub use err::{RpcError, RpcErrorKind};
pub use method::{
    DeserMethod, DynMethod, Method, NoUpdates, RpcMethod, check_method_names, is_method_name,
    iter_method_names,
};
pub use obj::{Object, ObjectArcExt, ObjectId};

#[cfg(feature = "describe-methods")]
#[cfg_attr(docsrs, doc(cfg(feature = "describe-methods")))]
pub use dispatch::description::RpcDispatchInformation;

#[cfg(feature = "describe-methods")]
#[cfg_attr(docsrs, doc(cfg(feature = "describe-methods")))]
#[doc(hidden)]
pub use dispatch::description::DelegationNote;

#[doc(hidden)]
pub use obj::cast::CastTable;
#[doc(hidden)]
pub use {
    derive_deftly, dispatch::RpcResult, downcast_rs, erased_serde, futures, inventory,
    method::MethodInfo_, paste, tor_async_utils, tor_error::internal, typetag,
};

/// Templates for use with [`derive_deftly`]
pub mod templates {
    pub use crate::method::derive_deftly_template_DynMethod;
    pub use crate::obj::derive_deftly_template_Object;
}

/// An error returned from [`ContextExt::lookup`].
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum LookupError {
    /// The specified object does not (currently) exist,
    /// or the user does not have permission to access it.
    #[error("No visible object with ID {0:?}")]
    NoObject(ObjectId),

    /// The specified object exists, but does not have the
    /// expected type.
    #[error("Unexpected type on object with ID {0:?}")]
    WrongType(ObjectId),
}

impl From<LookupError> for RpcError {
    fn from(err: LookupError) -> Self {
        use LookupError as E;
        use RpcErrorKind as EK;
        let kind = match &err {
            E::NoObject(_) => EK::ObjectNotFound,
            E::WrongType(_) => EK::InvalidRequest,
        };
        RpcError::new(err.to_string(), kind)
    }
}

/// A trait describing the context in which an RPC method is executed.
pub trait Context: Send + Sync {
    /// Look up an object by identity within this context.
    fn lookup_object(&self, id: &ObjectId) -> Result<Arc<dyn Object>, LookupError>;

    /// Create an owning reference to `object` within this context.
    ///
    /// Return an ObjectId for this object.
    fn register_owned(&self, object: Arc<dyn Object>) -> ObjectId;

    // TODO: If we add weak references again, we may need a register_weak method here.

    /// Drop an owning reference to the object called `object` within this context.
    ///
    /// This will return an error if `object` is not an owning reference,
    /// or does not exist.
    fn release_owned(&self, object: &ObjectId) -> Result<(), LookupError>;

    /// Return a dispatch table that can be used to invoke other RPC methods.
    fn dispatch_table(&self) -> &Arc<std::sync::RwLock<DispatchTable>>;
}

/// An error caused while trying to send an update to a method.
///
/// These errors should be impossible in our current implementation, since they
/// can only happen if the `mpsc::Receiver` is closed—which can only happen
/// when the session loop drops it, which only happens when the session loop has
/// stopped polling its `FuturesUnordered` full of RPC request futures. Thus, any
/// `send` that would encounter this error should be in a future that is never
/// polled under circumstances when the error could happen.
///
/// Still, programming errors are real, so we are handling this rather than
/// declaring it a panic or something.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum SendUpdateError {
    /// The request was cancelled, or the connection was closed.
    #[error("Unable to send on MPSC connection")]
    ConnectionClosed,
}

impl tor_error::HasKind for SendUpdateError {
    fn kind(&self) -> tor_error::ErrorKind {
        tor_error::ErrorKind::Internal
    }
}

impl From<Infallible> for SendUpdateError {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}
impl From<futures::channel::mpsc::SendError> for SendUpdateError {
    fn from(_: futures::channel::mpsc::SendError) -> Self {
        SendUpdateError::ConnectionClosed
    }
}

/// Extension trait for [`Context`].
///
/// This is a separate trait so that `Context` can be object-safe.
pub trait ContextExt: Context {
    /// Look up an object of a given type, and downcast it.
    ///
    /// Return an error if the object can't be found, or has the wrong type.
    fn lookup<T: Object>(&self, id: &ObjectId) -> Result<Arc<T>, LookupError> {
        self.lookup_object(id)?
            .downcast_arc()
            .map_err(|_| LookupError::WrongType(id.clone()))
    }
}

impl<T: Context> ContextExt for T {}

/// Try to find an appropriate function for calling a given RPC method on a
/// given RPC-visible object.
///
/// On success, return a Future.
///
/// Differs from using `DispatchTable::invoke()` in that it drops its lock
/// on the dispatch table before invoking the method.
pub fn invoke_rpc_method(
    ctx: Arc<dyn Context>,
    obj_id: &ObjectId,
    obj: Arc<dyn Object>,
    method: Box<dyn DynMethod>,
    sink: dispatch::BoxedUpdateSink,
) -> Result<dispatch::RpcResultFuture, InvokeError> {
    match method.invoke_without_dispatch(Arc::clone(&ctx), obj_id) {
        Err(InvokeError::NoDispatchBypass) => {
            // fall through
        }
        other => return other,
    }

    let (obj, invocable) = ctx
        .dispatch_table()
        .read()
        .expect("poisoned lock")
        .resolve_rpc_invoker(obj, method.as_ref())?;

    invocable.invoke(obj, method, ctx, sink)
}

/// Invoke the given `method` on `obj` within `ctx`, and return its
/// actual result type.
///
/// Unlike `invoke_rpc_method`, this method does not return a type-erased result,
/// and does not require that the result can be serialized as an RPC object.
///
/// Differs from using `DispatchTable::invoke_special()` in that it drops its lock
/// on the dispatch table before invoking the method.
pub async fn invoke_special_method<M: Method>(
    ctx: Arc<dyn Context>,
    obj: Arc<dyn Object>,
    method: Box<M>,
) -> Result<Box<M::Output>, InvokeError> {
    let (obj, invocable) = ctx
        .dispatch_table()
        .read()
        .expect("poisoned lock")
        .resolve_special_invoker::<M>(obj)?;

    invocable
        .invoke_special(obj, method, ctx)?
        .await
        .downcast()
        .map_err(|_| InvokeError::Bug(tor_error::internal!("Downcast to wrong type")))
}

/// A serializable empty object.
///
/// Used when we need to declare that a method returns nothing.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, Default)]
#[non_exhaustive]
pub struct Nil {}
/// An instance of rpc::Nil.
pub const NIL: Nil = Nil {};

/// Common return type for RPC methods that return a single object ID
/// and nothing else.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, derive_more::From)]
pub struct SingleIdResponse {
    /// The ID of the object that we're returning.
    id: ObjectId,
}

/// Error representing an "invalid" RPC identifier.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum InvalidRpcIdentifier {
    /// The method doesn't have a ':' to demarcate its namespace.
    #[error("Identifier has no namespace separator")]
    NoNamespace,

    /// The method's namespace is not one we recognize.
    #[error("Identifier has unrecognized namespace")]
    UnrecognizedNamespace,

    /// The method's name is not in snake_case.
    #[error("Identifier name has unexpected format")]
    BadIdName,
}

/// Check whether `method` is an expected and well-formed RPC identifier.
///
/// If `recognized_namespaces` is provided, only identifiers within those
/// namespaces are accepted; otherwise, all namespaces are accepted.
///
/// (Examples of RPC identifiers are method names.)
pub(crate) fn is_valid_rpc_identifier(
    recognized_namespaces: Option<&HashSet<&str>>,
    method: &str,
) -> Result<(), InvalidRpcIdentifier> {
    /// Return true if name is in acceptable format.
    fn name_ok(n: &str) -> bool {
        let mut chars = n.chars();
        let Some(first) = chars.next() else {
            return false;
        };
        first.is_ascii_lowercase()
            && chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
    }
    let (scope, name) = method
        .split_once(':')
        .ok_or(InvalidRpcIdentifier::NoNamespace)?;

    if let Some(recognized_namespaces) = recognized_namespaces {
        if !(scope.starts_with("x-") || recognized_namespaces.contains(scope)) {
            return Err(InvalidRpcIdentifier::UnrecognizedNamespace);
        }
    }
    if !name_ok(name) {
        return Err(InvalidRpcIdentifier::BadIdName);
    }

    Ok(())
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

    use futures::SinkExt as _;
    use futures_await_test::async_test;

    use super::*;
    use crate::dispatch::test::{Ctx, GetKids, Swan};

    #[async_test]
    async fn invoke() {
        let ctx = Arc::new(Ctx::from(DispatchTable::from_inventory()));
        let discard = || Box::pin(futures::sink::drain().sink_err_into());
        let r = invoke_rpc_method(
            ctx.clone(),
            &ObjectId::from("Odile"),
            Arc::new(Swan),
            Box::new(GetKids),
            discard(),
        )
        .unwrap()
        .await
        .unwrap();
        assert_eq!(serde_json::to_string(&r).unwrap(), r#"{"v":"cygnets"}"#);

        let r = invoke_special_method(ctx, Arc::new(Swan), Box::new(GetKids))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r.v, "cygnets");
    }

    #[test]
    fn valid_method_names() {
        let namespaces: HashSet<_> = ["arti", "wombat"].into_iter().collect();

        for name in [
            "arti:clone",
            "arti:clone7",
            "arti:clone_now",
            "wombat:knish",
            "x-foo:bar",
        ] {
            assert!(is_valid_rpc_identifier(Some(&namespaces), name).is_ok());
        }
    }

    #[test]
    fn invalid_method_names() {
        let namespaces: HashSet<_> = ["arti", "wombat"].into_iter().collect();
        use InvalidRpcIdentifier as E;

        for (name, expect_err) in [
            ("arti-foo:clone", E::UnrecognizedNamespace),
            ("fred", E::NoNamespace),
            ("arti:", E::BadIdName),
            ("arti:7clone", E::BadIdName),
            ("arti:CLONE", E::BadIdName),
            ("arti:clone-now", E::BadIdName),
        ] {
            assert_eq!(
                is_valid_rpc_identifier(Some(&namespaces), name),
                Err(expect_err)
            );
        }
    }
}
