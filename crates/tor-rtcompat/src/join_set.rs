//! Module exposing [`FuturesJoinSet`].

use async_trait::async_trait;
use futures::FutureExt;
use futures::future::RemoteHandle;
use futures::stream::{FuturesUnordered, StreamExt};
use futures::task::SpawnError;

use std::any::Any;
use std::panic::AssertUnwindSafe;

use crate::traits::{JoinSet, SpawnExt};

/// A [`futures`]-based [`JoinSet`] implementation.
pub struct FuturesJoinSet<T: Send + Sync + 'static, R> {
    /// The runtime to spawn tasks on.
    runtime: R,
    /// The currently pending tasks.
    ///
    /// The remote futures of these handles can never panic,
    /// because [`Self::spawn`] wraps them in [`futures::future::CatchUnwind`].
    pending: FuturesUnordered<RemoteHandle<Result<T, Box<dyn Any + Send>>>>,
}

impl<T, R> FuturesJoinSet<T, R>
where
    T: Send + Sync + 'static,
    R: SpawnExt + Send + Sync + 'static,
{
    /// Create a [`FuturesJoinSet`], for spawning tasks on `runtime`.
    pub fn new(runtime: R) -> Self {
        Self {
            runtime,
            pending: Default::default(),
        }
    }
}

#[async_trait]
impl<T, R> JoinSet<T> for FuturesJoinSet<T, R>
where
    T: Send + Sync + 'static,
    R: SpawnExt + Send + Sync + 'static,
{
    fn spawn<F>(&mut self, task: F) -> Result<(), SpawnError>
    where
        F: Future<Output = T> + Send + 'static,
    {
        let handle = self.runtime.spawn_with_handle(AssertUnwindSafe(task).catch_unwind())?;
        self.pending.push(handle);
        Ok(())
    }

    async fn join_next(&mut self) -> Option<Result<T, Box<dyn Any + Send>>> {
        self.pending.next().await
    }
}
