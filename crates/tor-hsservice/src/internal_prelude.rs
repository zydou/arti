//! Imports used internally within this crate
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

//---------- std ----------

pub(crate) use {
    std::any::Any,
    std::borrow::Cow,
    std::cmp::max,
    std::cmp::Ordering,
    std::collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    std::error::Error as StdError,
    std::ffi::OsStr,
    std::fmt::{self, Debug, Display},
    std::fs,
    std::fs::{File, OpenOptions},
    std::future::Future,
    std::hash::Hash,
    std::io,
    std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    std::iter,
    std::marker::PhantomData,
    std::ops::{Deref, DerefMut},
    std::panic::AssertUnwindSafe,
    std::path::{Path, PathBuf},
    std::str::FromStr,
    std::sync::{Arc, Mutex, MutexGuard},
    std::time::{Duration, Instant, SystemTime},
};

//---------- upstreams ----------

pub(crate) use {
    async_trait::async_trait,
    derive_builder::Builder,
    derive_deftly::{define_derive_deftly, Deftly},
    derive_more::{Constructor, Deref, DerefMut, From, Into},
    educe::Educe,
    futures::channel::mpsc,
    futures::future::{self, Either},
    futures::select_biased,
    futures::stream::BoxStream,
    futures::task::{SpawnError, SpawnExt as _},
    futures::{AsyncRead, AsyncWrite, Stream},
    futures::{FutureExt as _, SinkExt as _, StreamExt as _, TryStreamExt as _},
    itertools::{chain, Itertools as _},
    postage::{broadcast, watch},
    rand::Rng,
    rand_core::{CryptoRng, RngCore},
    serde::{Deserialize, Deserializer, Serialize, Serializer},
    thiserror::Error,
    tracing::{debug, error, info, trace, warn},
    void::{ResultVoidErrExt as _, Void},
};

//---------- tor-* crates ----------

pub(crate) use {
    oneshot_fused_workaround as oneshot,
    retry_error::RetryError,
    safelog::{sensitive, Redactable as _},
    tor_async_utils::{DropNotifyWatchSender, PostageWatchSenderExt as _},
    tor_basic_utils::{impl_debug_hex, retry::RetryDelay, PathExt as _, RngExt as _},
    tor_cell::relaycell::{msg::AnyRelayMsg, RelayMsg as _},
    tor_circmgr::build::circparameters_from_netparameters,
    tor_circmgr::hspool::{HsCircKind, HsCircPool},
    tor_config::{ConfigBuildError, Reconfigure, ReconfigureError},
    tor_dirclient::request::HsDescUploadRequest,
    tor_dirclient::{send_request, Error as DirClientError, RequestFailedError},
    tor_error::define_asref_dyn_std_error,
    tor_error::{bad_api_usage, internal, into_bad_api_usage, into_internal},
    tor_error::{debug_report, error_report, info_report, warn_report},
    tor_error::{Bug, ErrorKind, ErrorReport as _, HasKind},
    tor_hscrypto::ope::AesOpeKey,
    tor_hscrypto::pk::{
        HsBlindId, HsBlindIdKey, HsBlindIdKeypair, HsClientDescEncKey, HsDescSigningKeypair, HsId,
        HsIdKey, HsIdKeypair, HsIntroPtSessionIdKey, HsIntroPtSessionIdKeypair, HsSvcNtorKeypair,
    },
    tor_hscrypto::time::TimePeriod,
    tor_hscrypto::RevisionCounter,
    tor_keymgr::{
        derive_deftly_template_KeySpecifier, KeyMgr, KeySpecifier,
        KeySpecifierComponentViaDisplayFromStr, KeySpecifierPattern as _, KeystoreSelector,
        {KeyPath, KeyPathRange, KeySpecifierComponent},
    },
    tor_linkspec::{
        CircTarget, HasRelayIds as _, OwnedChanTargetBuilder, OwnedCircTarget, RelayIds,
    },
    tor_llcrypto::pk::{curve25519, ed25519},
    tor_log_ratelim::log_ratelim,
    tor_netdir::{HsDirParams, NetDir, NetDirProvider, Relay, Timeliness},
    tor_netdoc::doc::hsdesc::{create_desc_sign_key_cert, HsDescBuilder},
    tor_netdoc::NetdocBuilder,
    tor_persist::slug::Slug,
    tor_persist::state_dir::{
        ContainsInstanceStateGuard as _, InstanceRawSubdir, LockFileGuard, StateDirectory,
    },
    tor_proto::circuit::{ClientCirc, ConversationInHandler, MetaCellDisposition},
    tor_proto::stream::DataStream,
    tor_rtcompat::SleepProvider,
    tor_rtcompat::{Runtime, SleepProviderExt as _},
};

//---------- names from this crate ----------

pub(crate) use {
    crate::err::IptStoreError,
    crate::err::StateExpiryError,
    crate::ipt_lid::{InvalidIptLocalId, IptLocalId},
    crate::ipt_mgr::CreateIptError,
    crate::ipt_mgr::IptManager,
    crate::ipt_set::IptSet,
    crate::ipt_set::IptsManagerView,
    crate::ipt_set::IptsPublisherUploadView,
    crate::ipt_set::IptsPublisherView,
    crate::ipt_set::{self, PublishIptSet},
    crate::keys::expire_publisher_keys,
    crate::keys::{IptKeyRole, IptKeySpecifier, IptKeySpecifierPattern},
    crate::netdir::{wait_for_netdir, wait_for_netdir_to_list, NetdirProviderShutdown},
    crate::publish::Publisher,
    crate::replay::ReplayError,
    crate::replay::ReplayLog,
    crate::status::PublisherStatusSender,
    crate::status::State,
    crate::status::{IptMgrStatusSender, State as IptMgrState},
    crate::status::{OnionServiceStatus, OnionServiceStatusStream, StatusSender},
    crate::time_store,
    crate::timeout_track::{TrackingInstantOffsetNow, TrackingNow, Update as _},
    crate::OnionServiceConfig,
    crate::StartupError,
    crate::StreamRequest,
    crate::{ipt_establish, ShutdownStatus},
    crate::{
        keys::BlindIdKeypairSpecifierPattern,
        rend_handshake::{self, RendCircConnector},
        ClientError,
    },
    crate::{req::RendRequestContext, HsNickname, LinkSpecs, NtorPublicKey},
    crate::{BlindIdKeypairSpecifier, DescSigningKeypairSpecifier, HsIdKeypairSpecifier},
    crate::{DescUploadError, IptError},
    crate::{FatalError, RendRequest},
    ipt_establish::{IptEstablisher, IptParameters, IptStatus, IptStatusStatus, IptWantsToRetire},
};
