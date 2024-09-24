BREAKING: `CircMgr::new` now returns `Result<CircMgr>` instead of `Result<Arc<CircMgr>>`
BREAKING: `CircMgr::new` takes `&GuardMgr<R>` instead of `GuardMgr<R>`.
BREAKING: `CircMgr::launch_background_tasks` takes generic `StateMgr + std::marker::Send + 'static` instead of concrete `FsStateMgr`.
