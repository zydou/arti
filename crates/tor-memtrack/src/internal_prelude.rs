//! Internal prelude
//!
//! This file contains most of the imports we wish to use, throughout this crate.
//!
//! Every module does `use crate::internal_prelude::*;`
//!
//! Exceptions:
//!
//!  * Names that are private to a module and its submodules (eg, `publish`)
//!    are imported to the sub-modules via `use super::*`.
//!    (Thus, the sub-module inherits the prelude from its parent.)
//!
//!  * Broad names from specific contexts, that are unsuitable for wide imports.
//!    For example, individual cell and message names from `tor-cell`,
//!    and the types from `tor_proto::stream` other than the high-level `DataStream`.

pub(crate) use std::{
    cmp::{Ordering, Reverse},
    collections::{BinaryHeap, HashSet},
    fmt::{self, Debug, Display},
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
    task::{Spawn, SpawnError, SpawnExt as _},
    FutureExt as _, StreamExt as _,
};

pub(crate) use {
    derive_builder::Builder,
    derive_deftly::{define_derive_deftly, Deftly},
    derive_more::{Deref, DerefMut, From, Into},
    educe::Educe,
    serde::{Deserialize, Serialize},
    slotmap::SlotMap,
    static_assertions::assert_not_impl_any,
    thiserror::Error,
    tracing::{error, info},
    void::{ResultVoidExt as _, Void},
};

pub(crate) use {
    tor_config::ConfigBuildError,
    tor_error::{error_report, internal, into_internal, Bug, ErrorKind, HasKind},
    tor_log_ratelim::log_ratelim,
    tor_rtcompat::CoarseInstant,
};

pub(crate) use crate::{
    config::Config,
    error::{Error, ReclaimCrashed, StartupError, TrackerCorrupted},
    utils::{DefaultExtTake, Qty},
};
