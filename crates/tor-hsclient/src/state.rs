//! Implement a cache for onion descriptors and the facility to remember a bit
//! about onion service history.

use std::collections::HashMap;
use std::mem;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use futures::FutureExt as _;

use postage::stream::Stream as _;
use slotmap::dense::DenseSlotMap;
use tracing::{debug, error};

use tor_circmgr::isolation::Isolation;
use tor_error::{internal, Bug, ErrorReport as _};
use tor_hscrypto::pk::HsId;
use tor_proto::circuit::ClientCirc;
use tor_rtcompat::Runtime;

use crate::connect::{self, Data};
use crate::{HsClientConnError, HsClientConnector, HsClientSecretKeys};

slotmap::new_key_type! {
    struct TableIndex;
}

/// Number of times we're willing to iterate round the state machine loop
///
/// This is fairly arbitrary, but we shouldn't get anywhere near it.
const MAX_ATTEMPTS: u32 = 10;

/// Hidden services;, our connections to them, and history of connections, etc.
///
/// Data structure is keyed (indexed) by:
///  * `HsId`, hidden service identity
///  * any secret keys we are to use
///  * circuit isolation
///
/// We treat different values for any of the above as completely independent,
/// except that we try isolation joining (narrowing) if everything else matches.
///
/// When deleting an entry, it should be remooved from both layers of the structure.
///
/// ```text
///           index                                         table
///           HashMap           Vec_______________          SlotMap___________________
///           |     | contains  | KS, isol | t_i |  t_i     | ServiceState / <empty> |
///   Hsid -> |  ---+---------> | KS, isol | t_i | -------> | ServiceState / <empty> |
///           |_____|           | KS, isol | t_i |          | ServiceState / <empty> |
///                             | KS, isol | t_i |          | ServiceState / <empty> |
///   KS, isol ---------------> | .........|.... |          | ServiceState / <empty> |
///             linear search   |________________|          | ...            ....    |
/// ```                                                     |________________________|
#[derive(Default)]
pub(crate) struct Services {
    /// Index, mapping key to entry in the data tble
    ///
    /// There's a HashMap from HsId.
    ///
    /// Then there is a linear search over the other key info,
    /// which can only be compared for equality/compatibility, not indexed.
    index: HashMap<HsId, Vec<IndexRecord>>,

    /// Actual table containing the state of our ideas about this service
    ///
    /// Using a slotmap allows the task, when it completes, to find the relevant
    /// place to put its results, without having to re-traverse the data structure.
    /// It also doesn't need a complete copy of the data structure key,
    /// nor to get involved with `Isolation` edge cases.
    table: DenseSlotMap<TableIndex, ServiceState>,
}

/// Entry in the 2nd-level lookup array
struct IndexRecord {
    /// Client secret keys (part of the data structure key)
    secret_keys: HsClientSecretKeys,
    /// Circuit isolation (part of the data structure key)
    isolation: Box<dyn Isolation>,
    /// Index into `Services.table`, intermediate value, data structure key for next step
    table_index: TableIndex,
}

/// Value in the `Services` data structure
///
/// State and history of of our connections, including connection to any connection task.
///
/// `last_used` is used to expire data eventually.
// TODO HS actually expire old data
//
// TODO unify this with channels and circuits.  See arti#778.
enum ServiceState {
    /// We don't have a circuit
    Closed {
        /// The state
        data: Data,
        /// Last time we touched this, including reuse
        #[allow(dead_code)] // TODO hs remove, when we do expiry
        last_used: Instant,
    },
    /// We have an open circuit, which we can (hopefully) just use
    Open {
        /// The state
        data: Data,
        /// The circuit
        circuit: ClientCirc,
        /// Last time we touched this, including reuse
        last_used: Instant,
    },
    /// We have a task trying to find the service and establish the circuit
    ///
    /// CachedData is owned by the task.
    Working {
        /// Signals instances of `get_or_launch_connection` when the task completes
        barrier_recv: postage::barrier::Receiver,
        /// Where the task will store the error.
        ///
        /// Lock hierarchy: this lock is "inside" the big lock on `Services`.
        error: Arc<Mutex<Option<HsClientConnError>>>,
    },
    /// Dummy value for use with temporary mem replace
    Dummy,
}

impl Services {
    /// Connect to a hidden service
    // We *do* drop guard.  There is *one* await point, just after drop(guard).
    #[allow(clippy::await_holding_lock)]
    pub(crate) async fn get_or_launch_connection(
        connector: &HsClientConnector<impl Runtime>,
        hs_id: HsId,
        isolation: Box<dyn Isolation>,
        secret_keys: HsClientSecretKeys,
    ) -> Result<ClientCirc, HsClientConnError> {
        let mut guard = connector.services.lock()
            .map_err(|_| internal!("HS connector poisoned"))?;
        let services = &mut *guard;
        let records = services.index.entry(hs_id).or_default();

        let blank_state = || ServiceState::Closed {
            data: Data::default(),
            last_used: connector.runtime.now(),
        };

        let table_index = match records.iter_mut().enumerate().find_map(|(v_index, record)| {
            // Deconstruct so that we can't accidentally fail to check some of the key fields
            let IndexRecord {
                secret_keys: t_keys,
                isolation: t_isolation,
                table_index:_,
            } = record;
            (t_keys == &secret_keys).then(||())?;
            let new_isolation = t_isolation.join(&*isolation)?;
            Some((v_index, new_isolation))
        }) {
            Some((v_index, new_isolation)) => {
                records[v_index].isolation = new_isolation;
                records[v_index].table_index
            }
            None => {
                let table_index = services.table.insert(blank_state());
                records.push(IndexRecord {
                    secret_keys: secret_keys.clone(),
                    isolation,
                    table_index,
                });
                table_index
            }
        };

        for _attempt in 0..MAX_ATTEMPTS {
            let state = guard.table.get_mut(table_index)
                .ok_or_else(|| internal!("guard table entry vanished!"))?;

            let (data, barrier_send) = match state {
                ServiceState::Open { data:_, circuit, last_used } => {
                    let now = connector.runtime.now();
                    if circuit.is_closing() {
                        // Well that's no good, we need a fresh one, but keep the data
                        let data = match mem::replace(state, ServiceState::Dummy) {
                            ServiceState::Open { data, last_used: _, circuit: _ } => data,
                            _ => panic!("state changed between maches"),
                        };
                        *state = ServiceState::Closed { data, last_used: now };
                        continue;
                    }
                    *last_used = now;
                    return Ok(circuit.clone());
                },
                ServiceState::Working { barrier_recv, error } => {
                    if !matches!(
                        barrier_recv.try_recv(),
                        Err(postage::stream::TryRecvError::Pending)
                    ) {
                        // This information is stale; the task no longer exists.
                        // We want information from a fresh attempt.
                        *state = blank_state();
                        continue;
                    }
                    let mut barrier_recv = barrier_recv.clone();
                    let error = error.clone();
                    drop(guard);
                    // Wait for the task to complete (at which point it drops the barrier)
                    barrier_recv.recv().await;
                    guard = connector.services.lock()
                        .map_err(|_| internal!("HS connector poisoned (relock)"))?;
                    let error = error.lock()
                        .map_err(|_| internal!("Working error poisoned"))?;
                    if let Some(error) = &*error {
                        return Err(error.clone());
                    }
                    continue;
                }
                ServiceState::Closed { .. } => {
                    let (barrier_send, barrier_recv) = postage::barrier::channel();
                    let data = match mem::replace(state, ServiceState::Working {
                        barrier_recv,
                        error: Arc::new(Mutex::new(None)),
                    }) {
                        ServiceState::Closed { data, .. } => data,
                        _ => panic!("state changed between maches"),
                    };
                    (data, barrier_send)
                }
                ServiceState::Dummy => {
                    *state = blank_state();
                    return Err(internal!("HS connector found dummy state").into());
                }
            };

            // Make a connection attempt
            let runtime = &connector.runtime;
            let connector = connector.clone();
            let secret_keys = secret_keys.clone();
            let connect_future = async move {
                let mut data = data;

                let got = AssertUnwindSafe(
                    connect::connect(&connector, &mut data, secret_keys)
                )
                    .catch_unwind()
                    .await
                    .unwrap_or_else(|_| {
                        data = Data::default();
                        Err(internal!("hidden service connector task panicked!").into())
                    });
                let last_used = connector.runtime.now();
                let got_error = got.as_ref().map(|_| ()).map_err(Clone::clone);

                // block for handling inability to store
                let stored = async {
                    // If we can't record the new state, just panic this task.
                    let mut guard = connector.services.lock()
                        .map_err(|_| internal!("HS connector poisoned"))?;
                    let state = guard.table.get_mut(table_index)
                        .ok_or_else(|| internal!("HS table entry removed while task running"))?;
                    // Always match this, so we check what we're overwriting
                    let error_store = match state {
                        ServiceState::Working { error, .. } => error,
                        _ => return Err(internal!("HS task found state other than Working")),
                    };

                    match got {
                        Ok(circuit) => {
                            *state = ServiceState::Open {
                                data,
                                circuit,
                                last_used,
                            }
                        }
                        Err(error) => {
                            let mut error_store = error_store.lock().map_err(|_| {
                                internal!("Working error poisoned, cannot store error")
                            })?;
                            *error_store = Some(error);
                        }
                    };

                    Ok(())
                }.await;

                match (got_error, stored) {
                    (Ok::<(), HsClientConnError>(()), Ok::<(), Bug>(())) => {}
                    (Err(got_error), Ok(())) => debug!(
                        "HS connection failure: {}",
                        // TODO HS show hs_id,
                        got_error.report(),
                    ),
                    (Ok(()), Err(bug)) => error!(
                        "internal error storing built HS circuit: {}",
                        // TODO HS show sv(hs_id),
                        bug.report(),
                    ),
                    (Err(got_error), Err(bug)) => error!(
                        "internal error storing HS connection error: {}; {}",
                        // TODO HS show sv(hs_id),
                        got_error.report(),
                        bug.report(),
                    ),
                };
                drop(barrier_send);
            };
            runtime.spawn_obj(Box::new(connect_future).into())
                .map_err(|cause| HsClientConnError::Spawn {
                    spawning: "connection task",
                    cause: cause.into(),
                })?;
        }

        Err(internal!("HS connector state management malfunction (exceeded MAX_ATTEMPTS").into())
    }
}
