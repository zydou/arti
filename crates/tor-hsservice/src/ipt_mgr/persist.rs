//! Persistent state for the IPT manager
//!
//! Records of our IPTs.
//! Does *not* include private keys - those are in the `KeyMgr`.

use super::*;
use crate::time_store;

/// Handle for a suitable persistent storage manager
pub(crate) type IptStorageHandle = Arc<dyn tor_persist::StorageHandle<StateRecord> + Sync + Send>;

//---------- On disk data structures, done with serde ----------

/// Record of intro point establisher state, as stored on disk
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct StateRecord {
    /// Relays
    ipt_relays: Vec<RelayRecord>,
    /// Reference time
    stored: time_store::Reference,
}

/// Record of a selected intro point relay, as stored on disk
#[derive(Serialize, Deserialize, Debug)]
struct RelayRecord {
    /// Which relay?
    relay: RelayIds,
    /// When do we plan to retire it?
    planned_retirement: time_store::FutureTimestamp,
    /// The IPTs, including the current one and any still-wanted old ones
    ipts: Vec<IptRecord>,
}

/// Record of a single intro point, as stored on disk
#[derive(Serialize, Deserialize, Debug)]
struct IptRecord {
    /// Used to find the cryptographic keys, amongst other things
    lid: IptLocalId,
    /// Is this IPT current, or are we just keeping it because of old descriptors
    #[serde(default, skip_serializing_if = "<&bool as std::ops::Not>::not")]
    is_current: bool,
}

//---------- Storing ----------

/// Store the IPTs in the persistent state
pub(super) fn store<R: Runtime, M: Mockable<R>>(
    imm: &Immutable<R>,
    state: &mut State<R, M>,
) -> Result<(), IptStoreError> {
    let tstoring = time_store::Storing::start(&imm.runtime);

    // Convert the IPT relays (to the on-disk format)
    let ipt_relays = state
        .irelays
        .iter()
        .map(|irelay| {
            // Convert one IPT relay, with its IPTs, to the on-disk format
            let relay = irelay.relay.clone();
            let planned_retirement = tstoring.store_future(irelay.planned_retirement);
            let ipts = irelay
                .ipts
                .iter()
                .map(|ipt| {
                    // Convert one IPT - at least, the parts we store here
                    IptRecord {
                        lid: ipt.lid,
                        is_current: ipt.is_current.is_some(),
                    }
                })
                .collect_vec();
            RelayRecord {
                relay,
                planned_retirement,
                ipts,
            }
        })
        .collect_vec();

    let on_disk = StateRecord {
        ipt_relays,
        stored: tstoring.store_ref(),
    };
    state.storage.store(&on_disk)?;
    Ok(())
}

//---------- Loading ----------

/// Load the IPTs from the persistent state
///
/// `publish_set` should already have been loaded from its persistent state.
pub(super) fn load<R: Runtime, M: Mockable<R>>(
    imm: &Immutable<R>,
    storage: &IptStorageHandle,
    config: &watch::Receiver<Arc<OnionServiceConfig>>,
    mockable: &mut M,
    publish_set: &PublishIptSet,
) -> Result<Vec<IptRelay>, StartupError> {
    let on_disk = storage.load().map_err(StartupError::LoadState)?;

    let Some(on_disk) = on_disk else {
        return Ok(vec![]);
    };

    // Throughout, we use exhaustive struct patterns on the data we got from disk,
    // so we avoid missing any of the data.
    let StateRecord { ipt_relays, stored } = on_disk;

    let tloading = time_store::Loading::start(&imm.runtime, stored);

    // Load the IPT relays (from the on-disk to the in-memory format)
    let mut ipt_relays: Vec<_> = ipt_relays
        .into_iter()
        .map(|rrelay| {
            // Load one IPT relay
            let RelayRecord {
                relay,
                planned_retirement,
                ipts,
            } = rrelay;
            let planned_retirement = tloading.load_future(planned_retirement);
            // Load the IPTs at this relay, restarting their establishers, etc.
            let ipts = ipts
                .into_iter()
                .map(|ipt| ipt.load_restart(imm, config, mockable, &relay))
                .try_collect()?;
            Ok::<_, StartupError>(IptRelay {
                relay,
                planned_retirement,
                ipts,
            })
        })
        .try_collect()?;

    IptManager::<R, M>::import_new_expiry_times(&mut ipt_relays, publish_set);

    Ok(ipt_relays)
}

impl IptRecord {
    /// Recreate (load) one IPT
    fn load_restart<R: Runtime, M: Mockable<R>>(
        self,
        imm: &Immutable<R>,
        new_configs: &watch::Receiver<Arc<OnionServiceConfig>>,
        mockable: &mut M,
        relay: &RelayIds,
    ) -> Result<Ipt, StartupError> {
        let IptRecord { lid, is_current } = self;

        let ipt = Ipt::start_establisher(
            imm,
            new_configs,
            mockable,
            relay,
            lid,
            is_current.then_some(IsCurrent),
            Some(IptExpectExistingKeys),
            // last_descriptor_expiry_including_slop
            // is restored by the `import_new_expiry_times` call in `load`
            PromiseLastDescriptorExpiryNoneIsGood {},
        )
        .map_err(|e| match e {
            CreateIptError::Fatal(e) => e.into(),
            // During startup we're trying to *read* the keystore;
            // if it goes wrong, we bail rather than continuing the startup attempt.
            CreateIptError::Keystore(cause) => StartupError::Keystore {
                action: "load IPT key(s)",
                cause,
            },
            CreateIptError::OpenReplayLog { file, error } => {
                StartupError::StateDirectoryInaccessibleIo {
                    source: error,
                    action: "opening",
                    path: file,
                }
            }
        })?;

        // We don't record whether this IPT was published, so we should assume it was.
        mockable.start_accepting(&*ipt.establisher);

        Ok(ipt)
    }
}
