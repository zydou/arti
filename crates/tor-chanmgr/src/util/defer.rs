//! Defer a closure until later.

/// Runs a closure when dropped.
pub(crate) struct Defer<T, F: FnOnce(T)>(Option<DeferInner<T, F>>);

/// Everything contained by a [`Defer`].
struct DeferInner<T, F: FnOnce(T)> {
    /// The argument `f` should be called with when [`Defer`] is dropped.
    arg: T,
    /// The function to call.
    f: F,
}

impl<T, F: FnOnce(T)> Defer<T, F> {
    /// Defer running the provided closure `f` with `arg` until the returned [`Defer`] is dropped.
    #[must_use]
    pub(crate) fn new(arg: T, f: F) -> Self {
        Self(Some(DeferInner { arg, f }))
    }

    /// Return the provided `T` and drop the provided closure without running it.
    pub(crate) fn cancel(mut self) -> T {
        // other than the drop handler, there are no other places that mutate the `Option`, so it
        // should always be `Some` here
        self.0.take().expect("`Defer` is missing a value").arg
    }
}

impl<T, F: FnOnce(T)> std::ops::Drop for Defer<T, F> {
    fn drop(&mut self) {
        if let Some(DeferInner { arg, f }) = self.0.take() {
            f(arg);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn test_drop() {
        let x = AtomicU32::new(0);
        {
            let _defer = Defer::new(5, |inc| {
                x.fetch_add(inc, Ordering::Relaxed);
            });
            assert_eq!(x.load(Ordering::Relaxed), 0);
        }
        assert_eq!(x.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn test_cancel() {
        let x = AtomicU32::new(0);
        {
            let defer = Defer::new(5, |inc| {
                x.fetch_add(inc, Ordering::Relaxed);
            });
            assert_eq!(defer.cancel(), 5);
            assert_eq!(x.load(Ordering::Relaxed), 0);
        }
        assert_eq!(x.load(Ordering::Relaxed), 0);
    }

    #[test]
    #[should_panic]
    fn test_panic() {
        let _ = Defer::new((), |()| {
            panic!("intentional panic");
        });
    }
}
