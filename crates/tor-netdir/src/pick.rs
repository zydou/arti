//! Declare helper function for choosing from a weighted iterator

/// Choose a nonuniform random member of an iterator.
///
/// For each value `v` yielded by `i`, this function will return that
/// value with probability proportional to `weightfn(v)`.
///
/// We'll return None if and only if there are no values with nonzero
/// weight.
///
/// Note that if the total values of `weightfn()` over all values has
/// a sum greater than `u64::MAX`, this function may use incorrect
/// approximations for its probabilities.  Try to make sure that the
/// maximum value of `weightfn()` is no more than `u64::MAX / i.len()`.
//
// Performance note: this implementation requires a fast RNG, but
// doesn't need much storage.
pub(crate) fn pick_weighted<R, I, F>(rng: &mut R, i: I, weightfn: F) -> Option<I::Item>
where
    I: Iterator,
    F: Fn(&I::Item) -> u64,
    R: rand::Rng,
{
    // Correctness argument: at the end of each iteration of the loop,
    // `result` holds a value chosen with weighted probability from
    // all of the items yielded so far.  The loop body preserves this
    // invariant.

    let mut shift = 0_u8;
    let mut result = None;
    let mut weight_so_far: u64 = 0;

    for item in i {
        let mut w = weightfn(&item) >> shift;
        if w == 0 {
            continue;
        }
        weight_so_far = match weight_so_far.checked_add(w) {
            Some(sum) => sum,
            None => {
                // We can't represent the total using u64.  We
                // increment the 'shift' value to reflect this, and
                // adjust the total accordingly.  It's not perfectly
                // accurate, but it's better than nothing.
                shift += 1;
                // This will always be true, since by the time 'shift' is 63,
                // w will be at most 1 for any item.   So we can't overflow
                // with shift == 63 unless we have over 2^63 items in the
                // iterator.  Even if the caller does pass us an iterator
                // with so many items (like an infinite one), we will
                // never be able to iterate over 2^63 of them.
                assert!(shift < 64);
                w >>= 1;
                weight_so_far >>= 1;
                // w and weight_so_far are <= 2^64-1.  After the
                // shift, each one is <= 2^63 - 1. Adding those together
                // gives a value no larger than 2^64 - 2, so this addition
                // is safe.
                weight_so_far + w
            }
        };

        let x = rng.gen_range(0..weight_so_far);
        // TODO: we could probably do this in constant-time, if we are
        // worried about a side-channel.
        assert!(x < weight_so_far);
        assert!(w <= weight_so_far);
        if x < w {
            result = Some(item);
        }
    }

    result
}

#[cfg(test)]
pub(crate) mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[cfg(not(feature = "stochastic_tests"))]
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

    #[cfg(not(feature = "stochastic_tests"))]
    pub(crate) fn get_iters() -> usize {
        5000
    }

    #[cfg(feature = "stochastic_tests")]
    pub(crate) fn get_rng() -> impl rand::Rng {
        rand::thread_rng()
    }

    #[cfg(feature = "stochastic_tests")]
    pub(crate) fn get_iters() -> usize {
        1000000
    }

    /// Assert that a is close to b.
    #[cfg(not(feature = "stochastic_tests"))]
    pub(crate) fn check_close(a: isize, b: isize) {
        assert!((a - b).abs() <= (b / 20) + 5);
    }

    #[cfg(feature = "stochastic_tests")]
    pub(crate) fn check_close(a: isize, b: isize) {
        assert!((a - b).abs() <= (b / 100));
    }

    #[test]
    fn t_probabilistic() {
        let mut cnt = [0_isize; 4];
        let array: &[u64] = &[100, 0, 1000, 1];
        let mut rng = get_rng();
        let n_iters = get_iters() as isize;
        for _ in 1..n_iters {
            let r = pick_weighted(&mut rng, array.iter(), |x| **x).unwrap();
            let pos = array.iter().position(|x| x == r);
            cnt[pos.unwrap()] += 1;
        }

        // TODO: Calculate the expected failure rate for this test when
        // using an unseeded RNG.
        assert!(cnt[3] < cnt[0]);
        assert!(cnt[0] < cnt[2]);

        assert_eq!(cnt[1], 0);
        dbg!(cnt);
        check_close(cnt[0], (n_iters * 100) / 1101);
        check_close(cnt[2], (n_iters * 1000) / 1101);
        check_close(cnt[3], (n_iters) / 1101);

        // Now try again, with equal-probability weighting.
        let mut cnt = [0_isize; 4];
        for _ in 1..n_iters {
            let r = pick_weighted(&mut rng, array.iter(), |_| 1).unwrap();
            let pos = array.iter().position(|x| x == r);
            cnt[pos.unwrap()] += 1;
        }
        check_close(cnt[0], n_iters / 4);
        check_close(cnt[1], n_iters / 4);
        check_close(cnt[2], n_iters / 4);
        check_close(cnt[3], n_iters / 4);

        // Try with square-of-value weighting.
        let mut cnt = [0_isize; 4];
        for _ in 1..n_iters {
            let r = pick_weighted(&mut rng, array.iter(), |x| (*x) * (*x)).unwrap();
            let pos = array.iter().position(|x| x == r);
            cnt[pos.unwrap()] += 1;
        }
        fn check_fclose(a: f64, b: f64) {
            assert!((a - b).abs() < (b + 0.0001) / 10.0);
        }
        check_fclose((cnt[0] as f64) / (n_iters as f64), 0.0099);
        check_fclose((cnt[1] as f64) / (n_iters as f64), 0.0);
        check_fclose((cnt[2] as f64) / (n_iters as f64), 0.9901);
        check_fclose((cnt[3] as f64) / (n_iters as f64), 0.0);

        // Try again with huuuge numbers.
        let mut cnt = [0_isize; 4];
        #[cfg(not(feature = "stochastic_tests"))]
        let n_iters = n_iters * 2;
        for _ in 1..n_iters {
            let r = pick_weighted(&mut rng, array.iter(), |_| u64::MAX).unwrap();
            let pos = array.iter().position(|x| x == r);
            cnt[pos.unwrap()] += 1;
        }
        check_close(cnt[0], n_iters / 4);
        check_close(cnt[1], n_iters / 4);
        check_close(cnt[2], n_iters / 4);
        check_close(cnt[3], n_iters / 4);
    }

    /// Try picking at random when no member can be chosen.
    #[test]
    fn zero_prob() {
        // this isn't a stochastic test, we can use a real RNG.
        let mut rng = rand::thread_rng();
        let array: &[&str] = &["Several", "options", "none", "of", "which", "are", "ok"];

        // give every member zero weight
        for _ in 1..1000 {
            let r = pick_weighted(&mut rng, array.iter(), |_| 0);
            assert!(r.is_none());
        }

        // try an empty list with nonzero weights
        let array: &[&str] = &[];
        for _ in 1..1000 {
            let r = pick_weighted(&mut rng, array.iter(), |_| 1);
            assert!(r.is_none());
        }
    }

    /// try with only one element; it should always be picked.
    #[test]
    fn singleton() {
        // this isn't a stochastic test, we can use a real RNG.
        let mut rng = rand::thread_rng();
        let array: &[&str] = &["Singleton"];

        for _ in 1..1000 {
            let r = pick_weighted(&mut rng, array.iter(), |_| 7);
            assert_eq!(r.unwrap(), &"Singleton");
        }
    }
}
