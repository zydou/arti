//! This module contains the code that actually runs checks on bridges
use arti_client::config::pt::TransportConfigBuilder;
use arti_client::config::{BridgeConfigBuilder, CfgPath, TorClientConfigBuilder};
use arti_client::{TorClient, TorClientConfig};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::broadcast;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::{timeout, Duration};
use tor_error::ErrorReport;
use tor_guardmgr::bridge::{BridgeConfig, BridgeParseError};
use tor_proto::channel::Channel;
use tor_rtcompat::PreferredRuntime;

use crate::BridgeResult;

/// The maximum number of open connections to relays at any given time
const MAX_CONNECTIONS: usize = 10;

/// The maximum amount of time we wait for a response from a channel
/// before giving up. This is important to avoid getting the program stuck
pub const RECEIVE_TIMEOUT: Duration = Duration::from_secs(1);

/// The amount of messages our channels will be able to store in them
/// while in transit
pub(crate) const CHANNEL_SIZE: usize = 100;

/// Attempt to create a Channel to a provided bridge
///
/// If successful, we will obtain a Channel, if not we get an error.
///
/// The channel is created using [tor_chanmgr::ChanMgr], accessed using
/// [TorClient::chanmgr()]
async fn is_bridge_online(
    bridge_config: &BridgeConfig,
    tor_client: &TorClient<PreferredRuntime>,
) -> Result<Arc<Channel>, tor_chanmgr::Error> {
    let chanmgr = tor_client.chanmgr();
    chanmgr
        .build_unmanaged_channel(bridge_config)
        .await
}

/// Waits for given channel to expire and sends this info through specified
/// channel
async fn is_bridge_still_online(
    channel: &Channel,
    bridge_line: String,
    expiry_tx: Sender<String>,
) -> anyhow::Result<()> {
    let _ = channel.wait_for_close().await;
    // if we reached this statement, it means the channel has expired
    expiry_tx.send(bridge_line).await?;
    Ok(())
}

/// Return a [TorClientConfigBuilder] which is set to use a pluggable transport
/// for all connections
fn build_pt_bridge_config(
    protocol: &str,
    bin_path: &str,
) -> anyhow::Result<TorClientConfigBuilder> {
    let mut builder = TorClientConfig::builder();
    let mut transport = TransportConfigBuilder::default();
    let protocol_parsed = protocol.parse()?;
    transport
        .protocols(vec![protocol_parsed])
        .path(CfgPath::new(bin_path.into()))
        .run_on_startup(true);
    builder.bridges().transports().push(transport);
    Ok(builder)
}

/// Contains the main logic for testing each bridge.
///
/// It ends up taking in a slice of bridge lines, and creates [MAX_CONNECTIONS]
/// number of connections as tasks, then waits for these requests to be resolved,
/// either by successfully connecting or not (for a variety of reasons). The
/// actual work to check each single bridge is done by [is_bridge_online()]
///
/// This is done up until all the bridges in the slice are covered
async fn test_bridges(
    bridge_lines: &[String],
    common_tor_client: TorClient<PreferredRuntime>,
) -> (HashMap<String, BridgeResult>, HashMap<String, Arc<Channel>>) {
    let mut results = HashMap::new();
    let mut channels = HashMap::new();
    let mut counter = 0;
    while counter < bridge_lines.len() {
        let tasks: Vec<_> = bridge_lines
            [counter..(counter + MAX_CONNECTIONS).min(bridge_lines.len())]
            .iter()
            .map(|rawbridgeline_ref| {
                let rawbridgeline = rawbridgeline_ref.to_string();
                let maybe_bridge: Result<BridgeConfigBuilder, BridgeParseError> =
                    rawbridgeline.parse();
                match maybe_bridge {
                    Ok(bridge) => {
                        let bridge_config = bridge.build().unwrap();
                        let tor_client = common_tor_client.isolated_client();
                        tokio::spawn(async move {
                            let current_time = OffsetDateTime::now_utc();
                            match is_bridge_online(&bridge_config, &tor_client).await {
                                Ok(functional) => {
                                    (rawbridgeline, Some(functional), current_time, None)
                                }
                                Err(er) => {
                                    // Build error here since we can't
                                    // represent the actual Arti-related errors
                                    // by `dyn ErrorReport` and we need the
                                    // `.report()` method's output to pretty print
                                    // errors in the JSON we return to the user
                                    let error_report =
                                        er.report().to_string().replace("error: ", "");
                                    (rawbridgeline, None, current_time, Some(error_report))
                                }
                            }
                        })
                    }
                    Err(e) => tokio::spawn(async move {
                        let current_time = OffsetDateTime::now_utc();
                        // Build error here since we can't
                        // represent the actual Arti-related errors
                        // by `dyn ErrorReport` and we need the
                        // `.report()` method's output to pretty print
                        // errors in the JSON we return to the user
                        (
                            rawbridgeline,
                            None,
                            current_time,
                            Some(e.report().to_string()),
                        )
                    }),
                }
            })
            .collect();
        counter += MAX_CONNECTIONS;
        let task_results = futures::future::join_all(tasks).await;
        for (bridgeline, chan, time, error) in task_results.into_iter().flatten() {
            let res = BridgeResult {
                functional: chan.is_some(),
                last_tested: time,
                error,
            };
            results.insert(bridgeline.clone(), res);
            if let Some(channel) = chan {
                channels.insert(bridgeline, channel);
            }
        }
    }
    (results, channels)
}

/// Calculates a list of bridge lines that have no channels
pub fn get_failed_bridges(
    bridge_lines: &[String],
    channels: &HashMap<String, Arc<Channel>>,
) -> Vec<String> {
    bridge_lines
        .iter()
        .filter_map(|bridge_line| {
            if !channels.contains_key(bridge_line) {
                Some(bridge_line.to_owned())
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
}

/// Task which checks if failed bridges have come up online
pub async fn check_failed_bridges_task(
    initial_failed_bridges: Vec<String>,
    common_tor_client: TorClient<PreferredRuntime>,
    now_online_bridges_tx: Sender<HashMap<String, Arc<Channel>>>,
    mut once_online_bridges_rx: Receiver<Vec<String>>,
    updates_tx: broadcast::Sender<HashMap<String, BridgeResult>>,
    mut new_bridges_rx: broadcast::Receiver<Vec<String>>,
) {
    let mut failed_bridges = initial_failed_bridges;
    loop {
        let (newresults, good_bridges) =
            test_bridges(&failed_bridges, common_tor_client.isolated_client()).await;
        // detect which bridges failed again
        failed_bridges = get_failed_bridges(&failed_bridges, &good_bridges);
        // report online bridges to the appropriate task
        now_online_bridges_tx.send(good_bridges).await.unwrap();
        // get new failures from the other task
        while let Ok(Some(new_failures)) =
            timeout(RECEIVE_TIMEOUT, once_online_bridges_rx.recv()).await
        {
            if new_failures.is_empty() {
                break;
            }
            failed_bridges.splice(..0, new_failures.iter().cloned());
        }
        // get new bridges to test from API call and merge them with known bad
        // bridges
        while let Ok(Ok(new_failures)) = timeout(RECEIVE_TIMEOUT, new_bridges_rx.recv()).await {
            if new_failures.is_empty() {
                break;
            }
            let set1: HashSet<_> = new_failures.iter().cloned().collect();
            let set2: HashSet<_> = failed_bridges.iter().cloned().collect();
            failed_bridges = set1.union(&set2).cloned().collect();
        }
        // write newresults into the updates channel
        if !newresults.is_empty() {
            updates_tx.send(newresults).unwrap();
        }
    }
}

/// Task which checks if online bridges have gone down
///
/// TODO: use new Arti APIs for detecting bridges going down
pub async fn detect_bridges_going_down(
    initial_channels: HashMap<String, Arc<Channel>>,
    once_online_bridges_tx: Sender<Vec<String>>,
    mut now_online_bridges_rx: Receiver<HashMap<String, Arc<Channel>>>,
) {
    let mut channels = initial_channels;
    let (expiry_tx, mut expiry_rx) = mpsc::channel::<String>(CHANNEL_SIZE);
    loop {
        let mut failed_bridges = Vec::new();
        let mut new_channels = HashMap::new();
        for (bridgeline, channel) in channels.into_iter() {
            let new_expiry_tx = expiry_tx.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    is_bridge_still_online(channel.as_ref(), bridgeline.clone(), new_expiry_tx)
                        .await
                {
                    eprintln!("Error while waiting on close: {:#?}", e);
                }
            });
        }
        // detect any bridges failing
        while let Ok(Some(bridgeline)) = timeout(RECEIVE_TIMEOUT, expiry_rx.recv()).await {
            new_channels.remove(&bridgeline);
            failed_bridges.push(bridgeline);
        }
        // report failures to the appropriate task
        once_online_bridges_tx.send(failed_bridges).await.unwrap();
        // get new channels from the other task
        while let Ok(Some(just_online_bridges)) =
            timeout(RECEIVE_TIMEOUT, now_online_bridges_rx.recv()).await
        {
            new_channels.extend(just_online_bridges);
        }
        channels = new_channels;
    }
}

/// Function which keeps track of the state of all the bridges given to it
pub async fn continuous_check(
    channels: HashMap<String, Arc<Channel>>,
    failed_bridges: Vec<String>,
    common_tor_client: TorClient<PreferredRuntime>,
    updates_tx: broadcast::Sender<HashMap<String, BridgeResult>>,
    new_bridges_rx: broadcast::Receiver<Vec<String>>,
) {
    let (once_online_sender, once_online_recv) = mpsc::channel(CHANNEL_SIZE);
    let (now_online_sender, now_online_recv) = mpsc::channel(CHANNEL_SIZE);
    let task1 = detect_bridges_going_down(channels, once_online_sender, now_online_recv);
    let task2 = check_failed_bridges_task(
        failed_bridges,
        common_tor_client,
        now_online_sender,
        once_online_recv,
        updates_tx,
        new_bridges_rx,
    );
    tokio::join!(task1, task2);
}

/// Build a [TorClient] that is intended to be used purely for creating isolated clients off of.
///
/// Note that this is mainly a wrapper for convenience purposes
pub async fn build_common_tor_client(
    obfs4_path: &str,
) -> anyhow::Result<TorClient<PreferredRuntime>> {
    let builder = build_pt_bridge_config("obfs4", obfs4_path)?.build()?;
    Ok(TorClient::create_bootstrapped(builder).await?)
}

/// Main function to unite everything together
///
/// In summary,
///
/// 1. Create the common [`TorClient`] which will be used for every connection
///
/// 2. Give [test_bridges()] the bridge lines
///
/// 3. Return the results
pub async fn main_test(
    bridge_lines: Vec<String>,
    obfs4_path: &str,
) -> Result<(HashMap<String, BridgeResult>, HashMap<String, Arc<Channel>>), arti_client::Error> {
    let common_tor_client = build_common_tor_client(obfs4_path).await.unwrap();
    Ok(test_bridges(&bridge_lines, common_tor_client).await)
}
