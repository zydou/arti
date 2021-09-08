//! Testing-only functionality, used elsewhere in this crate.

pub(crate) use imp::*;

/// Testing implementation helpers.
///
/// This module comes in two flavors: a stochastic and a non-stochastic one.
/// When stochastic testing is enabeld, we use a real PRNG, and therefore
/// we require more iterations and broader tolerances.
///
/// The stochastic testing version of this module is on when the
/// `stochastic-tests` feature is enabled.
#[cfg(any(doc, not(feature = "stochastic-tests")))]
mod imp {
    /// Return a new RNG -- possibly a pre-seeded one.
    pub(crate) fn get_rng() -> impl rand::Rng {
        // When stochastic tests aren't enabled, we use a RNG seeded
        // with a fixed value and a small number of iterators for each test.
        //
        // XXXX: Note that the StdRng is not guaranteed to be
        // reproducible across rust stdlib versions; an upgrade might break
        // these tests.
        use rand::SeedableRng;
        rand::rngs::StdRng::from_seed(
            // Fun facts:
            // The Julius Tote was a mechanical computer and point-of-sale
            // system from the 1920s that used horses as an RNG.
            *b"George Alfred Julius Totalisator",
        )
    }

    /// Return the number of iterations for which to run a randomized test.
    pub(crate) fn get_iters() -> usize {
        5000
    }

    /// Assert that a is close to b.
    pub(crate) fn check_close(a: isize, b: isize) {
        assert!((a - b).abs() <= (b / 20) + 5);
    }
}

// ------ stochastic implementations of above features.
#[cfg(all(not(doc), feature = "stochastic-tests"))]
mod imp {
    pub(crate) fn get_rng() -> impl rand::Rng {
        rand::thread_rng()
    }

    #[cfg(all(not(doc), feature = "stochastic-tests"))]
    pub(crate) fn get_iters() -> usize {
        1000000
    }

    #[cfg(feature = "stochastic-tests")]
    pub(crate) fn check_close(a: isize, b: isize) {
        assert!((a - b).abs() <= (b / 100));
    }
}
