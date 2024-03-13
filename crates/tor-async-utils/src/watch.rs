//! Extension trait for more efficient use of [`postage::watch`].
use std::ops::{Deref, DerefMut};
use void::{ResultVoidExt as _, Void};

/// Extension trait for some `postage::watch::Sender` to provide `maybe_send`
///
/// Ideally these, or something like them, would be upstream:
/// See <https://github.com/austinjones/postage-rs/issues/56>.
///
/// We provide this as an extension trait became the implementation is a bit fiddly.
/// This lets us concentrate on the actual logic, when we use it.
pub trait PostageWatchSenderExt<T> {
    /// Update, by calling a fallible function, sending only if necessary
    ///
    /// Calls `update` on the current value in the watch, to obtain a new value.
    /// If the new value doesn't compare equal, updates the watch, notifying receivers.
    fn try_maybe_send<F, E>(&mut self, update: F) -> Result<(), E>
    where
        T: PartialEq,
        F: FnOnce(&T) -> Result<T, E>;

    /// Update, by calling a function, sending only if necessary
    ///
    /// Calls `update` on the current value in the watch, to obtain a new value.
    /// If the new value doesn't compare equal, updates the watch, notifying receivers.
    fn maybe_send<F>(&mut self, update: F)
    where
        T: PartialEq,
        F: FnOnce(&T) -> T,
    {
        self.try_maybe_send(|t| Ok::<_, Void>(update(t)))
            .void_unwrap();
    }
}

impl<T> PostageWatchSenderExt<T> for postage::watch::Sender<T> {
    fn try_maybe_send<F, E>(&mut self, update: F) -> Result<(), E>
    where
        T: PartialEq,
        F: FnOnce(&T) -> Result<T, E>,
    {
        let lock = self.borrow();
        let new = update(&*lock)?;
        if new != *lock {
            // We must drop the lock guard, because otherwise borrow_mut will deadlock.
            // There is no race, because we hold &mut self, so no-one else can get a look in.
            // (postage::watch::Sender is not one of those facilities which is mereely a
            // handle, and Clone.)
            drop(lock);
            *self.borrow_mut() = new;
        }
        Ok(())
    }
}

#[derive(Debug)]
/// Wrapper for `postage::watch::Sender` that sends `DropNotifyEof::eof()` when dropped
///
/// Derefs to the inner `Sender`.
///
/// Ideally this would be behaviour promised by upstream, or something
/// See <https://github.com/austinjones/postage-rs/issues/57>.
pub struct DropNotifyWatchSender<T: DropNotifyEofSignallable>(Option<postage::watch::Sender<T>>);

/// Values that can signal EOF
///
/// Implemented for `Option`, which is usually what you want to use.
pub trait DropNotifyEofSignallable {
    /// Generate the EOF value
    fn eof() -> Self;

    /// Does this value indicate EOF?
    ///
    /// ### Deprecated
    ///
    /// This method is deprecated.
    /// It should not be called, or defined, in new programs.
    /// It is not required by [`DropNotifyWatchSender`].
    /// The provided implementation always returns `false`.
    #[deprecated]
    fn is_eof(&self) -> bool {
        false
    }
}

impl<T> DropNotifyEofSignallable for Option<T> {
    fn eof() -> Self {
        None
    }

    fn is_eof(&self) -> bool {
        self.is_none()
    }
}

impl<T: DropNotifyEofSignallable> DropNotifyWatchSender<T> {
    /// Arrange to send `T::Default` when `inner` is dropped
    pub fn new(inner: postage::watch::Sender<T>) -> Self {
        DropNotifyWatchSender(Some(inner))
    }

    /// Unwrap the inner sender, defusing the drop notification
    pub fn into_inner(mut self) -> postage::watch::Sender<T> {
        self.0.take().expect("inner was None")
    }
}

impl<T: DropNotifyEofSignallable> Deref for DropNotifyWatchSender<T> {
    type Target = postage::watch::Sender<T>;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("inner was None")
    }
}

impl<T: DropNotifyEofSignallable> DerefMut for DropNotifyWatchSender<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut().expect("inner was None")
    }
}

impl<T: DropNotifyEofSignallable> Drop for DropNotifyWatchSender<T> {
    fn drop(&mut self) {
        if let Some(mut inner) = self.0.take() {
            // None means into_inner() was called
            *inner.borrow_mut() = DropNotifyEofSignallable::eof();
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
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use futures::select_biased;
    use futures_await_test::async_test;

    #[derive(Debug, Eq, PartialEq)]
    struct TestError(char);

    #[async_test]
    async fn postage_sender_ext() {
        use futures::stream::StreamExt;
        use futures::FutureExt;

        let (mut s, mut r) = postage::watch::channel_with(20);
        // Receiver of a fresh watch wakes once, but let's not rely on this
        select_biased! {
            i = r.next().fuse() => assert_eq!(i, Some(20)),
            _ = futures::future::ready(()) => { }, // tolerate nothing
        };
        // Now, not ready
        select_biased! {
            _ = r.next().fuse() => panic!(),
            _ = futures::future::ready(()) => { },
        };

        s.maybe_send(|i| *i);
        // Still not ready
        select_biased! {
            _ = r.next().fuse() => panic!(),
            _ = futures::future::ready(()) => { },
        };

        s.maybe_send(|i| *i + 1);
        // Ready, with 21
        select_biased! {
            i = r.next().fuse() => assert_eq!(i, Some(21)),
            _ = futures::future::ready(()) => panic!(),
        };

        let () = s.try_maybe_send(|_i| Err(())).unwrap_err();
        // Not ready
        select_biased! {
            _ = r.next().fuse() => panic!(),
            _ = futures::future::ready(()) => { },
        };
    }

    #[async_test]
    async fn postage_drop() {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        struct I(i32);

        impl DropNotifyEofSignallable for I {
            fn eof() -> I {
                I(0)
            }
            fn is_eof(&self) -> bool {
                self.0 == 0
            }
        }

        let (s, r) = postage::watch::channel_with(I(20));
        let s = DropNotifyWatchSender::new(s);

        assert_eq!(*r.borrow(), I(20));
        drop(s);
        assert_eq!(*r.borrow(), I(0));

        let (s, r) = postage::watch::channel_with(I(44));
        let s = DropNotifyWatchSender::new(s);

        assert_eq!(*r.borrow(), I(44));
        drop(s.into_inner());
        assert_eq!(*r.borrow(), I(44));
    }
}
