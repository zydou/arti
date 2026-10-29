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
        let handle = self
            .runtime
            .spawn_with_handle(AssertUnwindSafe(task).catch_unwind())?;
        self.pending.push(handle);
        Ok(())
    }

    async fn join_next(&mut self) -> Option<Result<T, Box<dyn Any + Send>>> {
        self.pending.next().await
    }
}

// test_with_all_runtimes! only exists if these features are satisfied.
#[cfg(all(
    test,
    any(feature = "native-tls", feature = "rustls"),
    any(feature = "tokio", feature = "async-std", feature = "smol"),
    not(miri), // Several of these use real SystemTime
))]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use crate::test_with_all_runtimes;

    #[test]
    fn catch_unwinding_panics() {
        test_with_all_runtimes!(|rt| async move {
            let mut join_set = FuturesJoinSet::new(rt);

            // Dummy values to return from the JoinSet tasks
            let task_results = (1..=10).collect::<Vec<_>>();
            for res in task_results.clone() {
                join_set
                    .spawn(async move {
                        // Does not panic, returns immediately
                        res
                    })
                    .unwrap();
            }

            join_set
                .spawn(async {
                    // This panic should be mapped to an Err(),
                    // and not cause the task awaiting the JoinSet to unwind
                    panic!("")
                })
                .unwrap();

            let mut num_tasks = 0;
            let mut actual = vec![];
            while let Some(res) = join_set.join_next().await {
                if let Ok(res) = res {
                    actual.push(res);
                }
                num_tasks += 1;
            }
            actual.sort();

            assert_eq!(num_tasks, task_results.len() + 1);
            assert_eq!(actual, task_results);
        });
    }
}
