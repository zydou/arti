//! Thin veneer over `futures::channel::oneshot` to fix use with [`select!`](futures::select)
//!
//! A bare [`futures::channel::oneshot::Receiver`] doesn't work properly with
//! `futures::select!`, because it has a broken
//! [`FusedFuture`](futures::future::FusedFuture)
//! implementation.
//! (See [`futures-rs` ticket #2455](https://github.com/rust-lang/futures-rs/issues/2455).)
//!
//! Wrapping it up in a [`future::Fuse`](futures::future::Fuse) works around this,
//! with a minor performance penalty.
//!
//! ### Limitations
//!
//! The API of this [`Receiver`] is rather more limited.
//! For example, it lacks `.try_recv()`.
//
// The veneer is rather thin and the types from `futures-rs` show through.
// If we change this in the future, it will be a breaking change.

use futures::channel::oneshot as fut_oneshot;
use futures::FutureExt as _;

pub use fut_oneshot::Canceled;

/// `oneshot::Sender` type alias
//
// This has to be `pub type` rather than `pub use` so that
// (i) call sites don't trip the "disallowed types" lint
// (ii) we can apply a fine-grained allow, here.
#[allow(clippy::disallowed_types)]
pub type Sender<T> =  fut_oneshot::Sender<T>;

/// `oneshot::Receiver` that works properly with [`futures::select!`]
#[allow(clippy::disallowed_types)]
pub type Receiver<T> = futures::future::Fuse<fut_oneshot::Receiver<T>>;

/// Return a fresh oneshot channel
pub fn channel<T>() -> (Sender<T>, Receiver<T>) {
    #[allow(clippy::disallowed_methods)]
    let (tx, rx) = fut_oneshot::channel();
    (tx, rx.fuse())
}
