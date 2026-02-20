//! Configure timers for a timer for retrying a single failed fetch or object.
//!
//! For a more information on the algorithm, see
//! [`RetryDelay`].

use std::num::{NonZeroU8, NonZeroU32};
use std::time::Duration;

use derive_deftly::Deftly;
use tor_basic_utils::retry::RetryDelay;
use tor_config::ConfigBuildError;
use tor_config::derive::prelude::*;

/// Configuration for how many times to retry a download, with what
/// frequency.
#[derive(Debug, Deftly, Copy, Clone, Eq, PartialEq)]
#[derive_deftly(TorConfig)]
pub struct DownloadSchedule {
    /// How many attempts to make before giving up?
    #[deftly(tor_config(default = r#"NonZeroU32::new(3).expect("Somehow 3==0")"#))]
    attempts: NonZeroU32,

    /// The amount of time to delay after the first failure, and a
    /// lower-bound for future delays.
    #[deftly(tor_config(default = "Duration::from_millis(1000)"))]
    initial_delay: Duration,

    /// When we want to download a bunch of these at a time, how many
    /// attempts should we try to launch at once?
    #[deftly(tor_config(default = r#"NonZeroU8::new(1).expect("Somehow 1==0")"#))]
    parallelism: NonZeroU8,
}

impl DownloadScheduleBuilder {
    /// Default value for retry_bootstrap in DownloadScheduleConfig.
    pub fn build_retry_bootstrap(&self) -> Result<DownloadSchedule, ConfigBuildError> {
        let mut bld = self.clone();
        bld.attempts.get_or_insert(128);
        bld.initial_delay.get_or_insert_with(|| Duration::new(1, 0));
        bld.parallelism.get_or_insert(1);
        bld.build()
    }

    /// Default value for microdesc_bootstrap in DownloadScheduleConfig.
    pub fn build_retry_microdescs(&self) -> Result<DownloadSchedule, ConfigBuildError> {
        let mut bld = self.clone();
        bld.attempts.get_or_insert(3);
        bld.initial_delay.get_or_insert_with(|| Duration::new(1, 0));
        bld.parallelism.get_or_insert(4);
        bld.build()
    }
}

impl DownloadSchedule {
    /// Return an iterator to use over all the supported attempts for
    /// this configuration.
    pub fn attempts(&self) -> impl Iterator<Item = u32> + use<> {
        0..(self.attempts.into())
    }

    /// Return the number of times that we're supposed to retry, according
    /// to this DownloadSchedule.
    pub fn n_attempts(&self) -> u32 {
        self.attempts.into()
    }

    /// Return the number of parallel attempts that we're supposed to launch,
    /// according to this DownloadSchedule.
    pub fn parallelism(&self) -> u8 {
        self.parallelism.into()
    }

    /// Return a RetryDelay object for this configuration.
    ///
    /// If the initial delay is longer than 32
    pub fn schedule(&self) -> RetryDelay {
        RetryDelay::from_duration(self.initial_delay)
    }
}

#[cfg(test)]
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
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use tor_basic_utils::test_rng::testing_rng;

    #[test]
    fn config() {
        // default configuration is 3 tries, 1000 msec initial delay
        let cfg = DownloadSchedule::default();
        let one_sec = Duration::from_secs(1);
        let mut rng = testing_rng();

        assert_eq!(cfg.n_attempts(), 3);
        let v: Vec<_> = cfg.attempts().collect();
        assert_eq!(&v[..], &[0, 1, 2]);

        assert_eq!(cfg.initial_delay, one_sec);
        let mut sched = cfg.schedule();
        assert_eq!(sched.next_delay(&mut rng), one_sec);

        // Try schedules with zeroes and show that they fail
        DownloadSchedule::builder()
            .attempts(0)
            .build()
            .expect_err("built with 0 retries");
        DownloadSchedule::builder()
            .parallelism(0)
            .build()
            .expect_err("built with 0 parallelism");
    }
}
