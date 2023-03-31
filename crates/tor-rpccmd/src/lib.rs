#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
// I'll run add_warning before we merge XXXX
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

mod cmd;
mod obj;

pub use cmd::Command;
pub use obj::{Object, ObjectId};
