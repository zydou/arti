//! Helper types used by the [`Reactor`](super::Reactor) for scheduling descriptor reuploads.

use std::cmp::Ordering;
use std::time::Instant;

use tor_hscrypto::time::TimePeriod;

/// A type that represents when a descriptor should be republished.
///
/// A `ReuploadTimer` is "greater" than another if its `when` timestamp is earlier.
///
/// This type is used in a max-heap to extract the earliest reupload the publisher can schedule.
#[derive(Clone, Copy, Debug)]
pub(super) struct ReuploadTimer {
    /// The TP for which to republish the descriptor.
    pub(super) period: TimePeriod,
    /// The earliest time when the descriptor should be republished.
    pub(super) when: Instant,
}

impl Ord for ReuploadTimer {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reversed, because we want the earlier
        // `ReuploadTimer` to be "greater".
        self.when.cmp(&other.when).reverse()
    }
}

impl PartialOrd for ReuploadTimer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for ReuploadTimer {
    fn eq(&self, other: &Self) -> bool {
        self.when == other.when
    }
}

impl Eq for ReuploadTimer {}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use std::collections::BinaryHeap;
    use std::time::Duration;

    use super::*;

    #[test]
    fn reupload_for_time_period_ordering() {
        const ONE_SEC: Duration = Duration::from_secs(1);

        let now = Instant::now();
        let later = now + ONE_SEC;
        let later_still = now + ONE_SEC * 2;
        let timer1 = ReuploadTimer {
            period: TimePeriod::from_parts(1, 2, 3),
            when: now,
        };

        let timer2 = ReuploadTimer {
            period: TimePeriod::from_parts(4, 5, 6),
            when: later,
        };

        let timer3 = ReuploadTimer {
            period: TimePeriod::from_parts(7, 8, 9),
            when: later_still,
        };

        for timer in &[timer1, timer2, timer3] {
            assert_eq!(timer, timer);
        }

        assert_ne!(timer1, timer2);
        assert_ne!(timer1, timer3);
        assert_ne!(timer2, timer3);

        assert!(timer1 > timer2);
        assert!(timer1 > timer3);
        assert!(timer2 > timer3);

        // A ReuploadTimer same `when`, but a different `time_period`.
        let mut timer4 = timer1;
        timer4.period = TimePeriod::from_parts(9, 9, 9);
        assert_ne!(timer1.period, timer4.period);
        assert_eq!(timer1, timer4);

        let mut heap = BinaryHeap::default();
        for timer in &[timer3, timer2, timer1] {
            heap.push(*timer);
        }

        assert_eq!(heap.pop(), Some(timer1));
        assert_eq!(heap.pop(), Some(timer2));
        assert_eq!(heap.pop(), Some(timer3));
        assert_eq!(heap.pop(), None);
    }
}
