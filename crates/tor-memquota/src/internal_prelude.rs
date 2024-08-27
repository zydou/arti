//! Internal prelude
//!
//! This file contains most of the imports we wish to use, throughout this crate.
//!
//! Every module does `use crate::internal_prelude::*;`
//!
//! Exceptions:
//!
//!  * Names that are private to a module and its submodules
//!    are imported to the sub-modules via `use super::*`.
//!    (Thus, the sub-module inherits the prelude from its parent.)
//!
//!  * Broad names from specific contexts, that are unsuitable for wide imports.
//!    For example, individual cell and message names from `tor-cell`,
//!    and the types from `tor_proto::stream` other than the high-level `DataStream`.

#![allow(unused_imports)]

pub(crate) use std::{
    cmp::{Ordering, Reverse},
    collections::{BinaryHeap, HashSet},
    fmt::{self, Debug},
    future::Future,
    marker::PhantomData,
    mem,
    ops::{Deref, DerefMut},
    panic::{catch_unwind, AssertUnwindSafe},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError, Weak},
};

pub(crate) use futures::{
    channel::mpsc,
    stream::FusedStream,
    task::{noop_waker_ref, Spawn, SpawnError, SpawnExt as _},
    FutureExt as _, Sink, SinkExt as _, Stream, StreamExt as _,
};

pub(crate) use {
    derive_deftly::{define_derive_deftly, Deftly},
    derive_more::{Constructor, Deref, DerefMut},
    educe::Educe,
    pin_project::pin_project,
    serde::{Deserialize, Serialize},
    slotmap::SlotMap,
    static_assertions::assert_not_impl_any,
    thiserror::Error,
    tracing::{error, info},
    void::{ResultVoidExt as _, Void},
};

pub(crate) use {
    tor_async_utils::stream_peek::StreamUnobtrusivePeeker,
    tor_basic_utils::ByteQty as Qty,
    tor_config::ConfigBuildError,
    tor_error::{error_report, internal, into_internal, Bug, ErrorKind, HasKind},
    tor_log_ratelim::log_ratelim,
    tor_rtcompat::{CoarseInstant, CoarseTimeProvider},
};

pub(crate) use crate::{
    config::{Config, ConfigInner},
    drop_bomb::{DropBomb, DropBombCondition},
    drop_reentrancy,
    error::{Error, ReclaimCrashed, StartupError, TrackerCorrupted},
    if_enabled::{EnabledToken, IfEnabled},
    memory_cost::{HasMemoryCost, HasTypedMemoryCost, TypedParticipation},
    mtracker::{self, Account, IsParticipant, Participation},
    private::Sealed,
    refcount,
    utils::DefaultExtTake,
};
