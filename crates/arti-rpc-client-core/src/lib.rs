#![doc = include_str!("../README.md")]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(missing_docs)]

mod conn;
pub mod llconn;
mod msgs;
#[macro_use]
mod util;

pub use conn::{BuilderError, ConnectError, ProtoError, RpcConn, RpcConnBuilder};
pub use msgs::{response::RpcError, AnyRequestId, ObjectId};
