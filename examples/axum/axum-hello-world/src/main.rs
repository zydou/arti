use anyhow::Result;
use axum::routing::get;
use axum::Router;
use futures::StreamExt;
use hyper::body::Incoming;
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server;
use tower::Service;

use arti_client::{TorClient, TorClientConfig};
use safelog::sensitive;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::StreamRequest;
use tor_proto::stream::IncomingStreamRequest;

#[tokio::main]
async fn main() {
    // Make sure you read doc/OnionService.md to extract your Onion service hostname

    // Arti uses the `tracing` crate for logging. Install a handler for this, to print Arti's logs.
    // (You'll need to set RUST_LOG=info as an environment variable to actually see much; also try
    // =debug for more detailed logging.)
    tracing_subscriber::fmt::init();

    // Axum router
    let router = Router::new().route("/", get(|| async { "Hello world!" }));

    // The client config includes things like where to store persistent Tor network state.
    // The defaults provided are the same as the Arti standalone application, and save data
    // to a conventional place depending on operating system (for example, ~/.local/share/arti
    // on Linux platforms)
    let config = TorClientConfig::default();

    // We now let the Arti client start and bootstrap a connection to the network.
    // (This takes a while to gather the necessary consensus state, etc.)
    let client = TorClient::create_bootstrapped(config).await.unwrap();

    let svc_cfg = OnionServiceConfigBuilder::default()
        .nickname("allium-ampeloprasum".parse().unwrap())
        .build()
        .unwrap();

    let (service, request_stream) = client.launch_onion_service(svc_cfg).unwrap();
    println!("{}", service.onion_name().unwrap());

    let stream_requests = tor_hsservice::handle_rend_requests(request_stream);
    tokio::pin!(stream_requests);
    eprintln!("ready to serve connections");

    while let Some(stream_request) = stream_requests.next().await {
        let router = router.clone();

        tokio::spawn(async move {
            let request = stream_request.request().clone();
            if let Err(err) = handle_stream_request(stream_request, router).await {
                eprintln!("error serving connection {:?}: {}", sensitive(request), err);
            };
        });
    }

    drop(service);
    eprintln!("onion service exited cleanly");
}

async fn handle_stream_request(stream_request: StreamRequest, router: Router) -> Result<()> {
    match stream_request.request() {
        IncomingStreamRequest::Begin(begin) if begin.port() == 80 => {
            let onion_service_stream = stream_request.accept(Connected::new_empty()).await?;
            let io = TokioIo::new(onion_service_stream);

            let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
                router.clone().call(request)
            });

            server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, hyper_service)
                .await
                .map_err(|x| anyhow::anyhow!(x))?;
        }
        _ => {
            stream_request.shutdown_circuit()?;
        }
    }

    Ok(())
}
