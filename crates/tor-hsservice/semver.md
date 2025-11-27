BREAKING: `OnionService::launch<R>()` now returns `Result<Option<(Arc<RunningOnionService>, impl Stream<Item = RendRequest>)>, StartupError>` (the `Option` is new).
BREAKING: `RestrictedDiscoveryConfig::build_unvalidated()` is now private.
