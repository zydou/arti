#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![cfg_attr(not(ci_arti_stable), allow(renamed_and_removed_lints))]
#![cfg_attr(not(ci_arti_nightly), allow(unknown_lints))]
#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
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
#![deny(clippy::missing_panics_doc)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

pub mod dispatch;
mod err;
mod method;
mod obj;
#[doc(hidden)]
pub mod typeid;

use std::{convert::Infallible, sync::Arc};

pub use dispatch::DispatchTable;
pub use err::RpcError;
pub use method::Method;
pub use obj::{Object, ObjectId};

#[doc(hidden)]
pub use {dispatch::RpcResult, downcast_rs, erased_serde, futures, inventory, paste};

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
}

/// An error caused while trying to send an update to a method.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum SendUpdateError {
    /// The application didn't ask for any updates for this request.
    #[error("Application did not request updates")]
    NoUpdatesWanted,

    /// The request was cancelled, or the connection was closed.
    #[error("Request cancelled")]
    RequestCancelled,
}

impl From<Infallible> for SendUpdateError {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}
impl From<futures::channel::mpsc::SendError> for SendUpdateError {
    fn from(_: futures::channel::mpsc::SendError) -> Self {
        SendUpdateError::RequestCancelled
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
