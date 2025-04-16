use std::sync::Arc;

use anyhow::Result;
use futures::StreamExt;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

use arti_client::{TorClient, TorClientConfig};
use safelog::sensitive;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::StreamRequest;
use tor_proto::stream::IncomingStreamRequest;

use std::io::Write;

struct WebHandler {
    shutdown: CancellationToken,
}

impl WebHandler {
    async fn serve(&self, request: Request<Incoming>) -> Result<Response<String>> {
        println!("[+] Incoming request: {:?}", request);

        let path = request.uri().path();

        // Path to shutdown the service.
        // TODO: Unauthenticated management. This route is accessible by anyone, and exists solely
        //  to demonstrate how to safely shutdown further incoming requests. You should probably
        //  move this elsewhere to ensure proper checks are in place!
        if path == "/shutdown" {
            self.shutdown.cancel();
        }

        // Default path.
        Ok(Response::builder().status(StatusCode::OK).body(format!(
            "You have succesfully reached your onion service served by Arti and hyper.\n\nYour request:\n\n{} {}",
            request.method(),
            path
        ))?)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Make sure you read doc/OnionService.md to extract your Onion service hostname

    // Arti uses the `tracing` crate for logging. Install a handler for this, to print Arti's logs.
    // (You'll need to set RUST_LOG=info as an environment variable to actually see much; also try
    // =debug for more detailed logging.)
    tracing_subscriber::fmt::init();

    // Initialize web server data, if you need to
    let handler = Arc::new(WebHandler {
        shutdown: CancellationToken::new(),
    });

    // The client config includes things like where to store persistent Tor network state.
    // The defaults provided are the same as the Arti standalone application, and save data
    // to a conventional place depending on operating system (for example, ~/.local/share/arti
    // on Linux platforms)
    let config = TorClientConfig::default();

    // We now let the Arti client start and bootstrap a connection to the network.
    // (This takes a while to gather the necessary consensus state, etc.)
    let client = TorClient::create_bootstrapped(config).await.unwrap();

    // Launch onion service.
    println!("[+] Launching onion service...");
    let svc_cfg = OnionServiceConfigBuilder::default()
        .nickname("test".parse().unwrap())
        .build()
        .unwrap();
    let (service, request_stream) = client.launch_onion_service(svc_cfg)?;

    // Wait until the service is believed to be fully reachable.
    // `is_fully_reachable` is no guarantee that the service is reachable or not, so we implement
    // a timeout to avoid waiting indefinitely.
    let timeout = tokio::time::Duration::from_secs(60);
    let start = tokio::time::Instant::now();
    let mut status_stream = service.status_events();

    print!(
        "[+] Waiting for onion service to be reachable. Please wait {} seconds...\r",
        timeout.as_secs()
    );
    loop {
        let elapsed = tokio::time::Instant::now().duration_since(start);
        let remaining = timeout.checked_sub(elapsed).unwrap_or_default();

        // If the timeout has elapsed we stop checking the status of the onion service.
        // Because `is_fully_reachable` is no guarantee, the service may still be reachable.
        if remaining.is_zero() {
            eprintln!(
                "[-] Timeout for status check reached. Still trying to serve onion address..."
            );
            break;
        }

        tokio::select! {
            // Check status of onion service.
            // Note that `is_fully_reachable` is not a guarantee that the service is reachable or not.
            maybe_status = status_stream.next() => {
                if let Some(status) = maybe_status {
                    if status.state().is_fully_reachable() {
                        break;
                    }
                } else {
                    eprintln!("[-] Status stream ended unexpectedly.");
                    break;
                }
            }

            // Output remaining seconds until timeout.
            _ = sleep(tokio::time::Duration::from_secs(1)) => {
                print!("[+] Waiting for onion service to be reachable. Please wait {} seconds...\r", remaining.as_secs());
                std::io::stdout().flush().unwrap();
            }
        }
    }

    println!(
        "\n\n[+] Onion service is reachable at: {}",
        service.onion_address().expect("Onion address not found")
    );

    let stream_requests = tor_hsservice::handle_rend_requests(request_stream)
        .take_until(handler.shutdown.cancelled());
    tokio::pin!(stream_requests);

    while let Some(stream_request) = stream_requests.next().await {
        // Incoming connection.
        let handler = handler.clone();

        tokio::spawn(async move {
            let request = stream_request.request().clone();
            let result = handle_stream_request(stream_request, handler).await;

            match result {
                Ok(()) => {}
                Err(err) => {
                    eprintln!(
                        "[-] Error serving connection {:?}: {}",
                        sensitive(request),
                        err
                    );
                }
            }
        });
    }

    drop(service);
    println!("[+] Onion service exited cleanly.");

    Ok(())
}

async fn handle_stream_request(
    stream_request: StreamRequest,
    handler: Arc<WebHandler>,
) -> Result<()> {
    match stream_request.request() {
        IncomingStreamRequest::Begin(begin) if begin.port() == 80 => {
            let onion_service_stream = stream_request.accept(Connected::new_empty()).await?;
            let io = TokioIo::new(onion_service_stream);

            http1::Builder::new()
                .serve_connection(io, service_fn(|request| handler.serve(request)))
                .await?;
        }
        _ => {
            stream_request.shutdown_circuit()?;
        }
    }

    Ok(())
}
