//! Definitions for circuit padding.
//!
//! This module defines the API for a circuit padder, which is divided into two parts:
//! a [`PaddingController`] and [`PaddingEventStream`].
//!
//! When the `circ-padding` feature is enabled, the [`PaddingController`] is used
//! to tell a set of padding machines about incoming and outgoing
//! traffic to a circuit hop,
//! and the [`PaddingEventStream`] is used to decide when to send padding to that hop.
//!
//! When `circ-padding` is not enabled, both types are empty, and do nothing.
//!
//! # Padding event semantics
//!
//! Our events here are fairly tightly coupled
//! to the semantics provided by [`maybenot`].
//!
//! In brief, `maybenot` assumes:
//!   * That incoming traffic arrives on a queue,
//!     then is decrypted and sorted into "normal" and "padding".
//!   * That outgoing traffic (normal or padding) is placed onto a queue,
//!     and then eventually sent.
//!
//! For each of these cases, the circuit/tunnnel reactor
//! needs to call an appropriate method on [`PaddingController`]
//! to inform each hop's padding machines about the event.
//!
//! See the [`maybenot`] documentation for more information about when,
//! exactly, each method needs to be invoked.
//!
//! # Design considerations
//!
//! We expect that a substantial fraction of all circuit hops
//! will require padding in some form.
//! Because of this, we've taken some effort to optimize the
//! storage overhead of our padding state.
//!
//! [`PaddingController`]: maybenot_padding::PaddingController
//! [`PaddingEventStream`]: maybenot_padding::PaddingEventStream

// TODO circpad: Remove these allows when we integrate padding into the rest of our code.
#![allow(dead_code)]
#![allow(unused_imports)]

cfg_if::cfg_if! {
    if #[cfg(feature = "circ-padding")] {
        mod maybenot_padding;
        use maybenot_padding as padding_impl;
        pub(crate) use maybenot_padding::{Replace, Bypass};
    } else {
        mod no_padding;
        use no_padding as padding_impl;
    }
}

pub(crate) use padding_impl::{
    PaddingController, PaddingEventStream, QueuedCellPaddingInfo, SendPadding, StartBlocking,
    new_padding,
};

/// An instruction from the padding machine to the circuit.
///
/// These are returned from the [`PaddingEventStream`].
///
/// When the `circ-padding` feature is disabled, these won't actually be constructed.
#[derive(Clone, Copy, Debug)]
pub(crate) enum PaddingEvent {
    /// An instruction to send padding.
    SendPadding(SendPadding),
    /// An instruction to start blocking outbound traffic,
    /// or change the hop at which traffic is blocked.
    StartBlocking(StartBlocking),
    /// An instruction to stop all blocking.
    StopBlocking,
}
