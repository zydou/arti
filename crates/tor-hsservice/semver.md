BREAKING: `OnionService::launch<R>()` now returns `Result<Option<(Arc<RunningOnionService>, impl Stream<Item = RendRequest>)>, StartupError>` (the `Option` is new).
