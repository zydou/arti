//! Helpers for tracking whether a tunnel or circuit is still active.

use derive_deftly::Deftly;
use std::{num::NonZeroUsize, time::Instant};

/// An object to track whether a tunnel or circuit should still be considered active.
///
/// The "active" status of a tunnel depends on whether it is in use for streams,
/// and if not, how much time has passed since it was last in use for streams.
///
/// # Ordering and aggregation
///
/// We rely on the ordering for `TunnelActivity` structs.
/// In particular, we depend on the property that a "more active"
/// `TunnelActivity` is greater than a less active one.
///
/// Specifically,
/// - a TunnelActivity with streams is "more active" than one without streams.
/// - a TunnelActivity that was last used for streams recently is "more active"
///   than one that was last used for streams more time ago.
/// - a TunnelActivity that was ever in use for streams is "more active"
///   than one that has never been used.
///
/// For implementation convenience, we do not generally keep a TunnelActivity
/// for an entire tunnel.
/// Instead, we keep a separate TunnelActivity for each hop of each circuit.
/// When we need to find the TunnelActivity of the tunnel as a whole,
/// we look for the TunnelActivity of the "most active" hop.
/// This _does not_ give an accurate count of all the streams on the
/// tunnel, but we don't generally care about that.
///
/// > We could instead _add_ the TunnelActivity for each hop,
/// > but that would be a bit more implementation effort to little benefit,
/// > and we'd need to avoid counting conflux join points twice.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct TunnelActivity {
    /// Actual activity for the associated tunnel.
    inner: Inner,
}

/// Inner enumeration used to implement [`TunnelActivity`].
///
/// This is a separate type to keep it private.
//
// NOTE: Don't re-order these: we rely on the speicific behavior of
// derive(PartialOrd) in order to get the behavior we want.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
enum Inner {
    /// The tunnel has never been used for streams.
    #[default]
    NeverUsed,
    /// The tunnel was in use for streams, but has no streams right now.
    Disused {
        /// The time at which the last stream was closed.
        ///
        /// See note on [`TunnelActivity::disused_since`].
        since: Instant,
    },
    /// The tunnel has open streams.
    InUse {
        /// The number of open streams on this tunnel.
        n_open_streams: NonZeroUsize,
    },
}

/// A zero-sized token type returned for each call to [`TunnelActivity::inc_streams()`].
///
/// The caller is responsible for passing this object to [`TunnelActivity::dec_streams()`]
/// when the stream is no longer in use.
/// Otherwise, this type will panic when it is dropped.
#[derive(Debug, Deftly)]
#[must_use]
#[derive_deftly_adhoc]
pub(crate) struct InTunnelActivity {
    /// Prevent this type from being created from other modules.
    _prevent_create: (),
}

impl Drop for InTunnelActivity {
    fn drop(&mut self) {
        panic!("Dropped an InTunnelActivity without giving it to dec_streams()")
    }
}

// Assert that no member of InTunnelActivity actually has meaningful drop semantics.
//
// (This lets us call std::mem::forget() below with confidence.)
derive_deftly::derive_deftly_adhoc! {
    InTunnelActivity:
    const _ : () = {
        $(
            assert!(! std::mem::needs_drop::<$ftype>());
        )
    };
}

impl InTunnelActivity {
    /// Consume this token safely, without triggering its drop panic.
    ///
    /// Calling this method directly will invalidate the corresponding TunnelActivity's counter.
    /// Instead, you should usually pass this to [`TunnelActivity::dec_streams`]
    pub(crate) fn consume_and_forget(self) {
        std::mem::forget(self);
    }
}

impl TunnelActivity {
    /// Construct a new TunnelActivity for a tunnel that has never been used.
    pub(crate) fn never_used() -> Self {
        Self::default()
    }

    /// Increase the number of streams on this tunnel by one.
    pub(crate) fn inc_streams(&mut self) -> InTunnelActivity {
        self.inner = Inner::InUse {
            n_open_streams: NonZeroUsize::new(self.n_open_streams() + 1)
                .expect("overflow on stream count"),
        };
        InTunnelActivity {
            _prevent_create: (),
        }
    }

    /// Decrease the number of streams on this tunnel by one.
    pub(crate) fn dec_streams(&mut self, token: InTunnelActivity) {
        token.consume_and_forget();
        let Inner::InUse { n_open_streams } = &mut self.inner else {
            panic!("Tried to decrement 0!");
        };

        if let Some(new_value) = NonZeroUsize::new(n_open_streams.get() - 1) {
            *n_open_streams = new_value;
        } else {
            self.inner = Inner::Disused {
                since: Instant::now(),
            };
        }
    }

    /// Return the number of open streams on this tunnel.
    ///
    /// (But see note on [`TunnelActivity`] documentation)
    pub(crate) fn n_open_streams(&self) -> usize {
        match self.inner {
            Inner::NeverUsed | Inner::Disused { .. } => 0,
            Inner::InUse { n_open_streams } => n_open_streams.get(),
        }
    }

    /// Return the time at which this tunnel was last in use.
    ///
    /// Returns None if the tunnel has open streams right now,
    /// or if it has never had any open streams.
    ///
    /// # A note about time
    ///
    /// The returned Instant value is a direct result of an earlier call to `Instant::now()`.
    /// It is not affected by any runtime mocking.
    pub(crate) fn disused_since(&self) -> Option<Instant> {
        match self.inner {
            Inner::Disused { since } => Some(since),
            Inner::NeverUsed | Inner::InUse { .. } => None,
        }
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

    use std::time::Duration;

    use super::*;
    use rand::seq::SliceRandom as _;
    use tor_basic_utils::test_rng::testing_rng;

    #[test]
    fn ordering() {
        use Inner::*;
        let t1 = Instant::now();
        let t2 = t1 + Duration::new(60, 0);
        let t3 = t2 + Duration::new(120, 0);
        let sorted = vec![
            NeverUsed,
            NeverUsed,
            Disused { since: t1 },
            Disused { since: t2 },
            Disused { since: t3 },
            InUse {
                n_open_streams: 5.try_into().unwrap(),
            },
            InUse {
                n_open_streams: 10.try_into().unwrap(),
            },
        ];

        let mut scrambled = sorted.clone();
        let mut rng = testing_rng();
        for _ in 0..=8 {
            scrambled.shuffle(&mut rng);
            scrambled.sort();
            assert_eq!(&scrambled, &sorted);
        }
    }
}
