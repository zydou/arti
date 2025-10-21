BREAKING: `TorClient<R>::launch_onion_service()` and `TorClient<R>::launch_onion_service_with_hsid()` now return `Result<Option<(Arc<tor_hsservice::RunningOnionService>, impl futures::Stream<Item = tor_hsservice::RendRequest> + use<R>,)>` (the `Option` is new).
MODIFIED: New `config::onion_service::OnionServiceConfigBuilder::enabled()` method.
MODIFIED: New `config::onion_service::OnionServiceConfig::enabled()` method.
