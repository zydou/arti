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
pub(crate) use std::any::Any;
pub(crate) use std::collections::{HashSet, VecDeque};
pub(crate) use std::fmt::Debug;
pub(crate) use std::fs;
pub(crate) use std::hash::Hash;
pub(crate) use std::io;
pub(crate) use std::marker::PhantomData;
pub(crate) use std::panic::AssertUnwindSafe;
pub(crate) use std::path::{Path, PathBuf};
pub(crate) use std::collections::HashMap;
pub(crate) use std::ops::{Deref, DerefMut};
pub(crate) use std::sync::{MutexGuard};
pub(crate) use std::error::Error as StdError;
pub(crate) use std::future::Future;
pub(crate) use std::time::SystemTime;
pub(crate) use std::cmp::max;
pub(crate) use std::collections::BinaryHeap;
pub(crate) use std::iter;
pub(crate) use std::cmp::Ordering;
pub(crate) use std::{
    borrow::Cow,
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
};

//---------- upstreams ----------

pub(crate) use educe::Educe;
pub(crate) use futures::{channel::mpsc, task::SpawnExt as _, FutureExt as _};
pub(crate) use postage::watch;
pub(crate) use safelog::Redactable as _;
pub(crate) use void::{ResultVoidErrExt as _, Void};
pub(crate) use derive_adhoc::Adhoc;
pub(crate) use serde::{Deserialize, Serialize};
pub(crate) use serde::{Deserializer, Serializer};
pub(crate) use thiserror::Error;
pub(crate) use futures::Stream;
pub(crate) use postage::broadcast;
pub(crate) use safelog::sensitive;
pub(crate) use futures::{future, select_biased};
pub(crate) use futures::{SinkExt as _, StreamExt as _};
pub(crate) use itertools::Itertools as _;
pub(crate) use rand::Rng;
pub(crate) use tor_keymgr::{KeyMgr};
pub(crate) use tracing::{debug, error, info, trace, warn};
pub(crate) use base64ct::{Base64Unpadded, Encoding as _};
pub(crate) use derive_builder::Builder;
pub(crate) use futures::task::SpawnError;
pub(crate) use futures::{future::Either, stream};
pub(crate) use derive_more::{Deref, DerefMut};
pub(crate) use itertools::{chain};
pub(crate) use derive_adhoc::{define_derive_adhoc};
pub(crate) use derive_more::Constructor;
pub(crate) use rand_core::{CryptoRng, RngCore};
pub(crate) use async_trait::async_trait;
pub(crate) use derive_more::{From, Into};
pub(crate) use futures::{AsyncRead, AsyncWrite, TryStreamExt as _};
pub(crate) use postage::sink::SendError;
pub(crate) use futures::{stream::BoxStream};

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
pub(crate) use tor_linkspec::CircTarget;
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
pub(crate) use tor_basic_utils::RngExt as _;
pub(crate) use tor_error::{error_report, info_report};
pub(crate) use tor_error::{Bug, ErrorKind, ErrorReport as _, HasKind};
pub(crate) use tor_keymgr::KeySpecifierPattern as _;
pub(crate) use tor_linkspec::{HasRelayIds as _, RelayIds};
pub(crate) use tor_llcrypto::pk::ed25519;
pub(crate) use tor_config::ConfigBuildError;
pub(crate) use tor_hscrypto::pk::HsClientDescEncKey;
pub(crate) use tor_rtcompat::SleepProvider;
pub(crate) use tor_hscrypto::time::TimePeriod;
pub(crate) use tor_keymgr::derive_adhoc_template_KeySpecifier;
pub(crate) use tor_netdir::HsDirParams;
pub(crate) use retry_error::RetryError;
pub(crate) use tor_error::{into_bad_api_usage};
pub(crate) use tor_hscrypto::pk::{HsBlindIdKey, HsDescSigningKeypair};
pub(crate) use tor_hscrypto::RevisionCounter;
pub(crate) use tor_netdoc::doc::hsdesc::{create_desc_sign_key_cert, HsDescBuilder};
pub(crate) use tor_netdoc::NetdocBuilder;
pub(crate) use tor_basic_utils::retry::RetryDelay;
pub(crate) use tor_hscrypto::ope::AesOpeKey;
pub(crate) use tor_keymgr::{KeySpecifier};
pub(crate) use tor_circmgr::hspool::{HsCircKind};
pub(crate) use tor_dirclient::request::HsDescUploadRequest;
pub(crate) use tor_dirclient::{send_request, Error as DirClientError, RequestFailedError};
pub(crate) use tor_error::define_asref_dyn_std_error;
pub(crate) use tor_hscrypto::pk::{
    HsBlindId, HsBlindIdKeypair,
};
pub(crate) use tor_linkspec::{OwnedCircTarget};
pub(crate) use tor_netdir::{NetDir, Relay, Timeliness};
pub(crate) use tor_circmgr::{
    build::circparameters_from_netparameters,
};
pub(crate) use tor_linkspec::{
    OwnedChanTargetBuilder,
};
pub(crate) use tor_persist::state_dir::ContainsInstanceStateGuard as _;
pub(crate) use tor_persist::state_dir::{InstanceRawSubdir, LockFileGuard};
pub(crate) use tor_hscrypto::{
    pk::{HsIntroPtSessionIdKey},
};
pub(crate) use tor_keymgr::{KeyPath, KeyPathRange, KeySpecifierComponent};
pub(crate) use tor_persist::slug::Slug;
pub(crate) use tor_proto::{
    stream::DataStream,
};

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
pub(crate) use crate::err::StateExpiryError;
pub(crate) use crate::ipt_set::{self, PublishIptSet};
pub(crate) use crate::keys::{IptKeyRole, IptKeySpecifier, IptKeySpecifierPattern};
pub(crate) use crate::status::{IptMgrStatusSender, State as IptMgrState};
pub(crate) use crate::{ipt_establish, ShutdownStatus};
pub(crate) use crate::timeout_track::{TrackingInstantOffsetNow, TrackingNow, Update as _};
pub(crate) use crate::{StartupError};
pub(crate) use ipt_establish::{IptEstablisher, IptParameters, IptStatus, IptStatusStatus, IptWantsToRetire};
pub(crate) use crate::{StreamRequest};
pub(crate) use crate::time_store;
pub(crate) use crate::status::PublisherStatusSender;
pub(crate) use crate::{ipt_set::IptsPublisherView};
pub(crate) use crate::config::DescEncryptionConfig;
pub(crate) use crate::ipt_set::IptSet;
pub(crate) use crate::{
    BlindIdKeypairSpecifier, DescSigningKeypairSpecifier, HsIdKeypairSpecifier,
};
pub(crate) use crate::ipt_set::{IptsPublisherUploadView};
pub(crate) use crate::keys::expire_publisher_keys;
pub(crate) use crate::status::{State};
pub(crate) use crate::ipt_mgr::CreateIptError;
pub(crate) use crate::{
    keys::BlindIdKeypairSpecifierPattern,
    rend_handshake::{self, RendCircConnector},
    ClientError,
};
pub(crate) use crate::{DescUploadError, IptError};
