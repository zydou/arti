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
//!    and the types from `tor_proto::client::stream` other than the high-level `DataStream`.

//---------- std ----------

pub(crate) use {
    std::any::Any,
    std::borrow::Cow,
    std::cmp::Ordering,
    std::cmp::max,
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
    derive_deftly::{Deftly, define_derive_deftly},
    derive_more::{Constructor, Deref, DerefMut, Into},
    educe::Educe,
    futures::channel::mpsc,
    futures::future::{self, Either},
    futures::select_biased,
    futures::stream::BoxStream,
    futures::task::SpawnError,
    futures::{AsyncRead, AsyncWrite, Stream},
    futures::{FutureExt as _, SinkExt as _, StreamExt as _, TryStreamExt as _},
    itertools::{Itertools as _, chain},
    postage::{broadcast, watch},
    rand::Rng,
    rand_core::{CryptoRng, RngCore},
    serde::{Deserialize, Deserializer, Serialize, Serializer},
    thiserror::Error,
    tor_rtcompat::SpawnExt as _,
    tracing::{debug, error, info, trace, warn},
    void::{ResultVoidErrExt as _, Void},
};

//---------- tor-* crates ----------

pub(crate) use {
    oneshot_fused_workaround as oneshot,
    retry_error::RetryError,
    safelog::{DisplayRedacted as _, Redactable as _},
    tor_async_utils::mpsc_channel_no_memquota,
    tor_async_utils::{DropNotifyWatchSender, PostageWatchSenderExt as _},
    tor_basic_utils::{PathExt as _, RngExt as _, impl_debug_hex, retry::RetryDelay},
    tor_cell::relaycell::{RelayMsg as _, msg::AnyRelayMsg},
    tor_circmgr::hspool::HsCircPool,
    tor_config::{ConfigBuildError, Reconfigure, ReconfigureError},
    tor_dirclient::request::HsDescUploadRequest,
    tor_dirclient::{Error as DirClientError, RequestFailedError, send_request},
    tor_error::define_asref_dyn_std_error,
    tor_error::{Bug, ErrorKind, ErrorReport as _, HasKind},
    tor_error::{bad_api_usage, internal, into_bad_api_usage, into_internal},
    tor_error::{debug_report, error_report, info_report, warn_report},
    tor_hscrypto::RevisionCounter,
    tor_hscrypto::ope::AesOpeKey,
    tor_hscrypto::pk::{
        HsBlindId, HsBlindIdKey, HsBlindIdKeypair, HsClientDescEncKey, HsDescSigningKeypair,
        HsIdKey, HsIdKeypair, HsIntroPtSessionIdKey, HsIntroPtSessionIdKeypair, HsSvcNtorKeypair,
    },
    tor_hscrypto::time::TimePeriod,
    tor_keymgr::{
        KeyMgr, KeySpecifier, KeySpecifierComponentViaDisplayFromStr, KeySpecifierPattern as _,
        KeystoreSelector, derive_deftly_template_KeySpecifier,
        {ArtiPathRange, KeySpecifierComponent},
    },
    tor_linkspec::{CircTarget, HasRelayIds as _, OwnedCircTarget, RelayIds},
    tor_llcrypto::pk::{curve25519, ed25519},
    tor_log_ratelim::log_ratelim,
    tor_netdir::{HsDirParams, NetDirProvider, Relay, Timeliness},
    tor_netdoc::NetdocBuilder,
    tor_netdoc::doc::hsdesc::{HsDescBuilder, create_desc_sign_key_cert},
    tor_persist::slug::Slug,
    tor_persist::state_dir::{
        ContainsInstanceStateGuard as _, InstanceRawSubdir, LockFileGuard, StateDirectory,
    },
    tor_proto::MetaCellDisposition,
    tor_proto::client::stream::DataStream,
    tor_rtcompat::SleepProvider,
    tor_rtcompat::{Runtime, SleepProviderExt as _},
};

//---------- names from this crate ----------

pub(crate) use {
    crate::OnionServiceConfig,
    crate::StartupError,
    crate::StreamRequest,
    crate::err::IptStoreError,
    crate::err::StateExpiryError,
    crate::ipt_lid::{InvalidIptLocalId, IptLocalId},
    crate::ipt_mgr::IptManager,
    crate::ipt_set::IptSet,
    crate::ipt_set::IptsManagerView,
    crate::ipt_set::IptsPublisherUploadView,
    crate::ipt_set::IptsPublisherView,
    crate::ipt_set::{self, PublishIptSet},
    crate::keys::expire_publisher_keys,
    crate::keys::{IptKeyRole, IptKeySpecifier, IptKeySpecifierPattern},
    crate::publish::Publisher,
    crate::replay::IptReplayLog,
    crate::replay::ReplayError,
    crate::status::PublisherStatusSender,
    crate::status::State,
    crate::status::{IptMgrStatusSender, State as IptMgrState},
    crate::status::{OnionServiceStatus, OnionServiceStatusStream, StatusSender},
    crate::time_store,
    crate::timeout_track::{TrackingInstantOffsetNow, TrackingNow, Update as _},
    crate::{
        BlindIdKeypairSpecifier, DescSigningKeypairSpecifier, HsIdKeypairSpecifier,
        HsIdPublicKeySpecifier,
    },
    crate::{
        ClientError,
        keys::BlindIdKeypairSpecifierPattern,
        rend_handshake::{self, RendCircConnector},
    },
    crate::{DescUploadError, IptError},
    crate::{FatalError, RendRequest},
    crate::{HsNickname, LinkSpecs, NtorPublicKey, req::RendRequestContext},
    crate::{ShutdownStatus, ipt_establish},
    ipt_establish::{IptEstablisher, IptParameters, IptStatus, IptStatusStatus, IptWantsToRetire},
};
