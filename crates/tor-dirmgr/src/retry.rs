//! Configure timers for a timer for retrying a single failed fetch or object.
//!
//! For a more information on the algorithm, see
//! [`RetryDelay`].

use std::num::{NonZeroU32, NonZeroU8};
use std::time::Duration;

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use tor_basic_utils::retry::RetryDelay;
use tor_config::{impl_standard_builder, ConfigBuildError};

/// Configuration for how many times to retry a download, with what
/// frequency.
#[derive(Debug, Builder, Copy, Clone, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
pub struct DownloadSchedule {
    /// How many attempts to make before giving up?
    #[builder(
        setter(strip_option),
        field(
            type = "Option<u32>",
            build = r#"build_nonzero(self.attempts, 3, "attempts")?"#
        )
    )]
    attempts: NonZeroU32,

    /// The amount of time to delay after the first failure, and a
    /// lower-bound for future delays.
    #[builder(default = "Duration::from_millis(1000)")]
    #[builder_field_attr(serde(default, with = "humantime_serde::option"))]
    initial_delay: Duration,

    /// When we want to download a bunch of these at a time, how many
    /// attempts should we try to launch at once?
    #[builder(
        setter(strip_option),
        field(
            type = "Option<u8>",
            build = r#"build_nonzero(self.parallelism, 1, "parallelism")?"#
        )
    )]
    parallelism: NonZeroU8,
}

impl_standard_builder! { DownloadSchedule }

impl DownloadScheduleBuilder {
    /// Default value for retry_bootstrap in DownloadScheduleConfig.
    pub(crate) fn build_retry_bootstrap(&self) -> Result<DownloadSchedule, ConfigBuildError> {
        let mut bld = self.clone();
        bld.attempts.get_or_insert(128);
        bld.initial_delay.get_or_insert_with(|| Duration::new(1, 0));
        bld.parallelism.get_or_insert(1);
        bld.build()
    }

    /// Default value for microdesc_bootstrap in DownloadScheduleConfig.
    pub(crate) fn build_retry_microdescs(&self) -> Result<DownloadSchedule, ConfigBuildError> {
        let mut bld = self.clone();
        bld.attempts.get_or_insert(3);
        bld.initial_delay
            .get_or_insert_with(|| (Duration::new(1, 0)));
        bld.parallelism.get_or_insert(4);
        bld.build()
    }
}

/// Helper for building a NonZero* field
fn build_nonzero<NZ, I>(
    spec: Option<I>,
    default: I,
    field: &'static str,
) -> Result<NZ, ConfigBuildError>
where
    I: TryInto<NZ>,
{
    spec.unwrap_or(default).try_into().map_err(|_| {
        let field = field.into();
        let problem = "zero specified, but not permitted".to_string();
        ConfigBuildError::Invalid { field, problem }
    })
}

impl DownloadSchedule {
    /// Return an iterator to use over all the supported attempts for
    /// this configuration.
    pub fn attempts(&self) -> impl Iterator<Item = u32> {
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
    #![allow(clippy::unchecked_duration_subtraction)]
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
