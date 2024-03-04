//! Imports used internally within this crate
//!
//! This file contains most of the imports we wish to use, throughout this crate.
//!
//! Every module does `use crate::internal_prelude::*;`
//!
//! Exceptions:
//!
//!  * Names that are private to a module (eg, `publish`),
//!    are re-exported from its sub-modules, and imported via `use super::*`.
//!    (The sub-module inherits the prelude from its parent.)
//!
//!  * Broad names from specific contexts, that are unsuitable for wide imports.
//!    For example, individual cell and message names from `tor-cell`,
//!    and the types from `tor_proto::stream` other than the high-level `DataStream`.

//---------- std ----------

pub(crate) use std::sync::{Arc, Mutex};
pub(crate) use std::time::{Duration, Instant};
pub(crate) use std::fmt::{self, Display};
pub(crate) use std::str::FromStr;

//---------- upstreams ----------

pub(crate) use educe::Educe;
pub(crate) use futures::{channel::mpsc, task::SpawnExt as _, Future, FutureExt as _};
pub(crate) use postage::watch;
pub(crate) use safelog::Redactable as _;
pub(crate) use tracing::debug;
pub(crate) use void::{ResultVoidErrExt as _, Void};
pub(crate) use derive_adhoc::Adhoc;
pub(crate) use serde::{Deserialize, Serialize};
pub(crate) use serde::{Deserializer, Serializer};
pub(crate) use thiserror::Error;
pub(crate) use futures::Stream;
pub(crate) use postage::broadcast;
pub(crate) use safelog::sensitive;
pub(crate) use tracing::info;

//---------- tor-* crates ----------

pub(crate) use tor_async_utils::oneshot;
pub(crate) use tor_async_utils::DropNotifyWatchSender;
pub(crate) use tor_cell::relaycell::{
    msg::AnyRelayMsg,
    RelayMsg as _,
};
pub(crate) use tor_circmgr::hspool::HsCircPool;
pub(crate) use tor_error::warn_report;
pub(crate) use tor_error::{bad_api_usage, debug_report, internal, into_internal};
pub(crate) use tor_hscrypto::pk::{HsIntroPtSessionIdKeypair, HsSvcNtorKeypair};
pub(crate) use tor_keymgr::KeyMgr;
pub(crate) use tor_linkspec::CircTarget;
pub(crate) use tor_linkspec::{HasRelayIds as _, RelayIds};
pub(crate) use tor_log_ratelim::log_ratelim;
pub(crate) use tor_netdir::NetDirProvider;
pub(crate) use tor_proto::circuit::{ClientCirc, ConversationInHandler, MetaCellDisposition};
pub(crate) use tor_rtcompat::{Runtime, SleepProviderExt as _};
pub(crate) use tor_basic_utils::impl_debug_hex;
pub(crate) use tor_keymgr::KeySpecifierComponentViaDisplayFromStr;
pub(crate) use tor_async_utils::PostageWatchSenderExt as _;
pub(crate) use tor_config::{Reconfigure, ReconfigureError};
pub(crate) use tor_hscrypto::pk::HsId;
pub(crate) use tor_hscrypto::pk::HsIdKey;
pub(crate) use tor_hscrypto::pk::HsIdKeypair;
pub(crate) use tor_keymgr::KeystoreSelector;
pub(crate) use tor_llcrypto::pk::curve25519;
pub(crate) use tor_persist::state_dir::StateDirectory;

//---------- names from this crate ----------

pub(crate) use crate::replay::ReplayError;
pub(crate) use crate::replay::ReplayLog;
pub(crate) use crate::OnionServiceConfig;
pub(crate) use crate::{
    req::RendRequestContext,
    LinkSpecs, NtorPublicKey,
    HsNickname,
};
pub(crate) use crate::{FatalError, RendRequest};
pub(crate) use crate::netdir::{wait_for_netdir, wait_for_netdir_to_list, NetdirProviderShutdown};
pub(crate) use crate::ipt_mgr::IptManager;
pub(crate) use crate::ipt_set::IptsManagerView;
pub(crate) use crate::status::{OnionServiceStatus, OnionServiceStatusStream, StatusSender};
pub(crate) use crate::publish::Publisher;
pub(crate) use crate::err::IptStoreError;
pub(crate) use crate::ipt_lid::{InvalidIptLocalId, IptLocalId};
