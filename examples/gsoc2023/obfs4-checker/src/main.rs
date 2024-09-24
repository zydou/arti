#![warn(clippy::missing_docs_in_private_items)]
#![doc = include_str!("../README.md")]
use crate::checking::RECEIVE_TIMEOUT;
use axum::{
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr};
use time::OffsetDateTime;
use tokio::sync::broadcast::{self, Receiver, Sender};
use tokio::time::timeout;
use tor_error::ErrorReport;
mod checking;

/// Utility to deliver real-time updates on bridge health
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, required = true)]
    /// Path to the `lyrebird` or `obfs4proxy`, required for making obfs4 connections
    obfs4_bin: String,
}

/// The input to our `bridge-state` handler
///
/// Just contains a list of bridge lines to test
#[derive(Deserialize)]
struct BridgeLines {
    /// List of bridge lines to test
    pub bridge_lines: Vec<String>,
}

/// Struct which represents one bridge's result
#[derive(Serialize, Clone, Debug)]
pub struct BridgeResult {
    /// Is bridge online or not?
    functional: bool,
    /// The time at which the bridge was last tested, written as a nice string
    last_tested: OffsetDateTime,
    /// Error encountered while trying to connect to the bridge, if any
    ///
    /// It is generated using [tor_error::ErrorReport]
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// The output to our `bridge-state` handler
///
/// Contains the [BridgeResult] for each bridgeline,
/// an error (if any), and the total time it took
/// to run the entire test
#[derive(Serialize)]
struct BridgesResult {
    /// All the bridge results, mapped by bridge line
    bridge_results: HashMap<String, BridgeResult>,
    /// General error encountered, if any
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// The time it took to generate this result
    time: f64,
}

/// Wrapper around the main testing function
async fn check_bridges(
    bridge_lines: Vec<String>,
    updates_tx: Sender<HashMap<String, BridgeResult>>,
    obfs4_path: String,
    new_bridges_rx: broadcast::Receiver<Vec<String>>,
) -> (StatusCode, Json<BridgesResult>) {
    let commencement_time = OffsetDateTime::now_utc();
    let mainop = crate::checking::main_test(bridge_lines.clone(), &obfs4_path).await;
    let end_time = OffsetDateTime::now_utc();
    let diff = (end_time - commencement_time).as_seconds_f64();
    let (bridge_results, error) = match mainop {
        Ok((bridge_results, channels)) => {
            let failed_bridges = crate::checking::get_failed_bridges(&bridge_lines, &channels);
            let common_tor_client = crate::checking::build_common_tor_client(&obfs4_path)
                .await
                .unwrap();
            tokio::spawn(async move {
                crate::checking::continuous_check(
                    channels,
                    failed_bridges,
                    common_tor_client,
                    updates_tx,
                    new_bridges_rx,
                )
                .await
            });
            (bridge_results, None)
        }
        Err(e) => {
            let error_report = e.report().to_string().replace("error: ", "");
            (HashMap::new(), Some(error_report))
        }
    };
    let finalresult = BridgesResult {
        bridge_results,
        error,
        time: diff,
    };
    (StatusCode::OK, Json(finalresult))
}

/// Wrapper around the main testing function
async fn updates(
    mut updates_rx: Receiver<HashMap<String, BridgeResult>>,
) -> (StatusCode, Json<BridgesResult>) {
    let mut bridge_results = HashMap::new();
    while let Ok(Ok(update)) = timeout(RECEIVE_TIMEOUT, updates_rx.recv()).await {
        if update.is_empty() {
            break;
        }
        bridge_results.extend(update);
    }
    let finalresult = BridgesResult {
        bridge_results,
        error: None,
        time: 0.0,
    };
    (StatusCode::OK, Json(finalresult))
}

/// Add new bridges to the main testing tasks
async fn add_new_bridges(
    new_bridge_lines: Vec<String>,
    new_bridges_tx: Sender<Vec<String>>,
) -> StatusCode {
    match new_bridges_tx.send(new_bridge_lines) {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Run the HTTP server and call the required methods to initialize the testing
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let obfs4_bin_path = args.obfs4_bin;
    // unused Receiver prevents SendErrors
    let (updates_tx, _updates_rx_unused) =
        broadcast::channel::<HashMap<String, BridgeResult>>(crate::checking::CHANNEL_SIZE);
    let (new_bridges_tx, _new_bridges_rx) =
        broadcast::channel::<Vec<String>>(crate::checking::CHANNEL_SIZE);
    let updates_sender_clone = updates_tx.clone();
    let new_bridges_tx_clone = new_bridges_tx.clone();
    let bridges_check_callback = move |Json(payload): Json<BridgeLines>| {
        let new_bridges_recv_clone = new_bridges_tx_clone.subscribe();
        async {
            check_bridges(
                payload.bridge_lines,
                updates_sender_clone,
                obfs4_bin_path,
                new_bridges_recv_clone,
            )
            .await
        }
    };
    let updates_callback = move || {
        let updates_rx = updates_tx.subscribe();
        async move { updates(updates_rx).await }
    };
    let add_new_bridges_callback = move |Json(payload): Json<BridgeLines>| async move {
        add_new_bridges(payload.bridge_lines, new_bridges_tx).await
    };
    let app = Router::new()
        .route("/bridge-state", post(bridges_check_callback))
        .route("/add-bridges", post(add_new_bridges_callback))
        .route("/updates", get(updates_callback));

    let addr = SocketAddr::from(([127, 0, 0, 1], 5000));

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind to TCP address");

    axum::serve(listener, app).await.expect("failed to serve");
}
