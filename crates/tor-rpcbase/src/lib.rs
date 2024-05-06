#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![cfg_attr(not(ci_arti_stable), allow(renamed_and_removed_lints))]
#![cfg_attr(not(ci_arti_nightly), allow(unknown_lints))]
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
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

pub mod dispatch;
mod err;
mod method;
mod obj;

use std::{convert::Infallible, sync::Arc};

pub use dispatch::{DispatchTable, InvokeError, UpdateSink};
pub use err::RpcError;
pub use method::{is_method_name, iter_method_names, DynMethod, Method, NoUpdates};
pub use obj::{Object, ObjectId, ObjectRefExt};

#[doc(hidden)]
pub use obj::cast::CastTable;
#[doc(hidden)]
pub use {
    derive_deftly, dispatch::RpcResult, downcast_rs, erased_serde, futures, inventory,
    method::MethodInfo_, once_cell, paste, tor_async_utils, tor_error::internal, typetag,
};

/// Templates for use with [`derive_deftly`]
pub mod templates {
    pub use crate::method::derive_deftly_template_DynMethod;
    pub use crate::obj::derive_deftly_template_Object;
}

/// An error returned from [`ContextExt::lookup`].
///
/// TODO RPC: This type should be made to conform with however we represent RPC
/// errors.
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

/// A trait describing the context in which an RPC method is executed.
pub trait Context: Send {
    /// Look up an object by identity within this context.
    fn lookup_object(&self, id: &ObjectId) -> Result<Arc<dyn Object>, LookupError>;

    /// Create an owning reference to `object` within this context.
    ///
    /// Return an ObjectId for this object.
    ///
    /// TODO RPC: We may need to change the above semantics and the name of this
    /// function depending on how we decide to name and specify things.
    fn register_owned(&self, object: Arc<dyn Object>) -> ObjectId;

    /// Make sure that
    /// this context contains a non-owning reference to `object`,
    /// creating one if necessary.
    ///
    /// Return an ObjectId for this object.
    ///
    /// Note that this takes an Arc, since that's required in order to find a
    /// working type Id for the target object.
    ///
    /// TODO RPC: We may need to change the above semantics and the name of this
    /// function depending on how we decide to name and specify things.
    fn register_weak(&self, object: Arc<dyn Object>) -> ObjectId;

    /// Drop an owning reference to the object called `object` within this context.
    ///
    /// This will return an error if `object` is not an owning reference.
    ///
    /// TODO RPC should this really return a LookupError?
    fn release_owned(&self, object: &ObjectId) -> Result<(), LookupError>;
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

/// A serializable empty object.
///
/// Used when we need to declare that a method returns nothing.
///
/// TODO RPC: Perhaps we can get () to serialize as {} and make this an alias
/// for ().
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, Default)]
#[non_exhaustive]
pub struct Nil {}
/// An instance of rpc::Nil.
pub const NIL: Nil = Nil {};
