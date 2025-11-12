use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use futures::StreamExt;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio_util::sync::CancellationToken;

use arti_client::{TorClient, TorClientConfig};
use safelog::{DisplayRedacted, sensitive};
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::StreamRequest;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_proto::client::stream::IncomingStreamRequest;

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
    eprintln!("[+] Launching onion service...");
    let svc_cfg = OnionServiceConfigBuilder::default()
        .nickname("allium-ampeloprasum".parse().unwrap())
        .build()
        .unwrap();
    let (service, request_stream) = match client.launch_onion_service(svc_cfg)? {
        Some(running_service) => running_service,
        None => {
            eprintln!("[+] Onion service not launched due to being disabled in config.");
            return Ok(());
        }
    };
    eprintln!(
        "[+] Onion address: {}",
        service
            .onion_address()
            .expect("Onion address not found")
            .display_unredacted()
    );

    // `is_fully_reachable` might remain false even if the service is reachable in practice;
    // after a timeout, we stop waiting for that and try anyway.
    let timeout_seconds = 60;
    eprintln!(
        "[+] Waiting for onion service to be reachable. Please wait {} seconds...\r",
        timeout_seconds
    );
    let status_stream = service.status_events();
    let mut binding =
        status_stream.filter(|status| futures::future::ready(status.state().is_fully_reachable()));
    match tokio::time::timeout(Duration::from_secs(timeout_seconds), binding.next()).await {
        Ok(Some(_)) => eprintln!("[+] Onion service is fully reachable."),
        Ok(None) => eprintln!("[-] Status stream ended unexpectedly."),
        Err(_) => eprintln!(
            "[-] Timeout waiting for service to become reachable. You can still attempt to visit the service."
        ),
    }

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
    eprintln!("[+] Onion service exited cleanly.");

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
