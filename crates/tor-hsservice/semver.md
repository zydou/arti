BREAKING: `OnionService::launch<R>()` now returns `Result<Option<(Arc<RunningOnionService>, impl Stream<Item = RendRequest>)>, StartupError>` (the `Option` is new), returning `Ok(None)` if the service is disabled in the config.
MODIFIED: New `config::OnionServiceConfigBuilder::enabled()` method.
MODIFIED: New `config::OnionServiceConfig::enabled()` method.
