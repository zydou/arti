//! Code for turning safelogging on and off.
//!
//! By default, safelogging is on.  There are two ways to turn it off: Globally
//! (with [`disable_safe_logging`]) and locally (with
//! [`with_safe_logging_suppressed`]).

use crate::{Error, Result};
use fluid_let::fluid_let;
use std::sync::atomic::{AtomicIsize, Ordering};

/// A global atomic used to track locking guards for enabling and disabling
/// safe-logging.
///
/// The value of this atomic is less than 0 if we have enabled unsafe logging.
/// greater than 0 if we have enabled safe logging, and 0 if nobody cares.
static LOGGING_STATE: AtomicIsize = AtomicIsize::new(0);

fluid_let!(
    /// A dynamic variable used to temporarily disable safe-logging.
    static SAFE_LOGGING_SUPPRESSED_IN_THREAD: bool
);

/// Returns true if we are displaying sensitive values, false otherwise.
pub(crate) fn unsafe_logging_enabled() -> bool {
    LOGGING_STATE.load(Ordering::Relaxed) < 0
        || SAFE_LOGGING_SUPPRESSED_IN_THREAD.get(|v| v == Some(&true))
}

/// Run a given function with the regular `safelog` functionality suppressed.
///
/// The provided function, and everything it calls, will display
/// [`Sensitive`](crate::Sensitive) values as if they were not sensitive.
///
/// # Examples
///
/// ```
/// use safelog::{Sensitive, with_safe_logging_suppressed};
///
/// let string = Sensitive::new("swordfish");
///
/// // Ordinarily, the string isn't displayed as normal
/// assert_eq!(format!("The value is {}", string),
///            "The value is [scrubbed]");
///
/// // But you can override that:
/// assert_eq!(
///     with_safe_logging_suppressed(|| format!("The value is {}", string)),
///     "The value is swordfish"
/// );
/// ```
pub fn with_safe_logging_suppressed<F, V>(func: F) -> V
where
    F: FnOnce() -> V,
{
    // This sets the value of the variable to Some(true) temporarily, for as
    // long as `func` is being called.  It uses thread-local variables
    // internally.
    SAFE_LOGGING_SUPPRESSED_IN_THREAD.set(true, func)
}

/// Enum to describe what kind of a [`Guard`] we've created.
#[derive(Debug, Copy, Clone)]
enum GuardKind {
    /// We are forcing safe-logging to be enabled, so that nobody
    /// can turn it off with `disable_safe_logging`
    Safe,
    /// We have are turning safe-logging off with `disable_safe_logging`.
    Unsafe,
}

/// A guard object used to enforce safe logging, or turn it off.
///
/// For as long as this object exists, the chosen behavior will be enforced.
//
// TODO: Should there be different types for "keep safe logging on" and "turn
// safe logging off"?  Having the same type makes it easier to write code that
// does stuff like this:
//
//     let g = if cfg.safe {
//         enforce_safe_logging()
//     } else {
//         disable_safe_logging()
//     };
#[derive(Debug)]
#[must_use = "If you drop the guard immediately, it won't do anything."]
pub struct Guard {
    /// What kind of guard is this?
    kind: GuardKind,
}

impl GuardKind {
    /// Return an error if `val` (as a value of `LOGGING_STATE`) indicates that
    /// intended kind of guard cannot be created.
    fn check(&self, val: isize) -> Result<()> {
        match self {
            GuardKind::Safe => {
                if val < 0 {
                    return Err(Error::AlreadyUnsafe);
                }
            }
            GuardKind::Unsafe => {
                if val > 0 {
                    return Err(Error::AlreadySafe);
                }
            }
        }
        Ok(())
    }
    /// Return the value by which `LOGGING_STATE` should change while a guard of
    /// this type exists.
    fn increment(&self) -> isize {
        match self {
            GuardKind::Safe => 1,
            GuardKind::Unsafe => -1,
        }
    }
}

impl Guard {
    /// Helper: Create a guard of a given kind.
    fn new(kind: GuardKind) -> Result<Self> {
        let inc = kind.increment();
        loop {
            // Find the current value of LOGGING_STATE and see if this guard can
            // be created.
            let old_val = LOGGING_STATE.load(Ordering::SeqCst);
            // Exit if this guard can't be created.
            kind.check(old_val)?;
            // Otherwise, try changing LOGGING_STATE to the new value that it
            // _should_ have when this guard exists.
            let new_val = match old_val.checked_add(inc) {
                Some(v) => v,
                None => return Err(Error::Overflow),
            };
            if let Ok(v) =
                LOGGING_STATE.compare_exchange(old_val, new_val, Ordering::SeqCst, Ordering::SeqCst)
            {
                // Great, we set the value to what it should be; we're done.
                debug_assert_eq!(v, old_val);
                return Ok(Self { kind });
            }
            // Otherwise, somebody else altered this value concurrently: try
            // again.
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        let inc = self.kind.increment();
        LOGGING_STATE.fetch_sub(inc, Ordering::SeqCst);
    }
}

/// Create a new [`Guard`] to prevent anyone else from disabling safe logging.
///
/// Until the resulting `Guard` is dropped, any attempts to call
/// `disable_safe_logging` will give an error.  This guard does _not_ affect
/// calls to [`with_safe_logging_suppressed`].
///
/// This call will return an error if safe logging is _already_ disabled.
///
/// Note that this function is called "enforce", not "enable", since safe
/// logging is enabled by default.  Its purpose is to make sure that nothing
/// _else_ has called disable_safe_logging().
pub fn enforce_safe_logging() -> Result<Guard> {
    Guard::new(GuardKind::Safe)
}

/// Create a new [`Guard`] to disable safe logging.
///
/// Until the resulting `Guard` is dropped, all [`Sensitive`](crate::Sensitive)
/// values will be displayed as if they were not sensitive.
///
/// This call will return an error if safe logging has been enforced with
/// [`enforce_safe_logging`].
pub fn disable_safe_logging() -> Result<Guard> {
    Guard::new(GuardKind::Unsafe)
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
    // We use "serial_test" to make sure that our tests here run one at a time,
    // since they modify global state.
    use serial_test::serial;

    #[test]
    #[serial]
    fn guards() {
        // Try operations with logging guards turned on and off, in a single
        // thread.
        assert!(!unsafe_logging_enabled());
        let g1 = enforce_safe_logging().unwrap();
        let g2 = enforce_safe_logging().unwrap();

        assert!(!unsafe_logging_enabled());

        let e = disable_safe_logging();
        assert!(matches!(e, Err(Error::AlreadySafe)));
        assert!(!unsafe_logging_enabled());

        drop(g1);
        drop(g2);
        let _g3 = disable_safe_logging().unwrap();
        assert!(unsafe_logging_enabled());
        let e = enforce_safe_logging();
        assert!(matches!(e, Err(Error::AlreadyUnsafe)));
        assert!(unsafe_logging_enabled());
        let _g4 = disable_safe_logging().unwrap();

        assert!(unsafe_logging_enabled());
    }

    #[test]
    #[serial]
    fn suppress() {
        // Try out `with_safe_logging_suppressed` and make sure it does what we want
        // regardless of the initial state of logging.
        {
            let _g = enforce_safe_logging().unwrap();
            with_safe_logging_suppressed(|| assert!(unsafe_logging_enabled()));
            assert!(!unsafe_logging_enabled());
        }

        {
            assert!(!unsafe_logging_enabled());
            with_safe_logging_suppressed(|| assert!(unsafe_logging_enabled()));
            assert!(!unsafe_logging_enabled());
        }

        {
            let _g = disable_safe_logging().unwrap();
            assert!(unsafe_logging_enabled());
            with_safe_logging_suppressed(|| assert!(unsafe_logging_enabled()));
        }
    }

    #[test]
    #[serial]
    fn interfere_1() {
        // Make sure that two threads trying to enforce and disable safe logging
        // can interfere with each other, but will never enter an incorrect
        // state.
        use std::thread::{spawn, yield_now};

        let thread1 = spawn(|| {
            for _ in 0..10_000 {
                if let Ok(_g) = enforce_safe_logging() {
                    assert!(!unsafe_logging_enabled());
                    yield_now();
                    assert!(disable_safe_logging().is_err());
                }
                yield_now();
            }
        });

        let thread2 = spawn(|| {
            for _ in 0..10_000 {
                if let Ok(_g) = disable_safe_logging() {
                    assert!(unsafe_logging_enabled());
                    yield_now();
                    assert!(enforce_safe_logging().is_err());
                }
                yield_now();
            }
        });

        thread1.join().unwrap();
        thread2.join().unwrap();
    }

    #[test]
    #[serial]
    fn interfere_2() {
        // Make sure that two threads trying to disable safe logging don't
        // interfere.
        use std::thread::{spawn, yield_now};

        let thread1 = spawn(|| {
            for _ in 0..10_000 {
                let g = disable_safe_logging().unwrap();
                assert!(unsafe_logging_enabled());
                yield_now();
                drop(g);
                yield_now();
            }
        });

        let thread2 = spawn(|| {
            for _ in 0..10_000 {
                let g = disable_safe_logging().unwrap();
                assert!(unsafe_logging_enabled());
                yield_now();
                drop(g);
                yield_now();
            }
        });

        thread1.join().unwrap();
        thread2.join().unwrap();
    }

    #[test]
    #[serial]
    fn interfere_3() {
        // Make sure that `with_safe_logging_suppressed` only applies to the
        // current thread.
        use std::thread::{spawn, yield_now};

        let thread1 = spawn(|| {
            for _ in 0..10_000 {
                assert!(!unsafe_logging_enabled());
                yield_now();
            }
        });

        let thread2 = spawn(|| {
            for _ in 0..10_000 {
                assert!(!unsafe_logging_enabled());
                with_safe_logging_suppressed(|| {
                    assert!(unsafe_logging_enabled());
                    yield_now();
                });
            }
        });

        thread1.join().unwrap();
        thread2.join().unwrap();
    }
}
