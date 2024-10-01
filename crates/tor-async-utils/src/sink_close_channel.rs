//! [`SinkCloseChannel`]

use std::pin::Pin;

use futures::channel::mpsc;
use futures::Sink;

//---------- principal API ----------

/// A [`Sink`] with a `close_channel` method like [`futures::channel::mpsc::Sender`'s]
pub trait SinkCloseChannel<T>: Sink<T> {
    /// Close the channel from the sending end, giving EOF at the receiver
    ///
    /// This closes *all* clones.
    /// Attempts to send will get a disconnected error.
    ///
    /// The receiver will see EOF, after reading the messages that were successful sent so far.
    ///
    /// MPSC channel senders are `Clone`, and/or you can make new senders from a rceiver.
    fn close_channel(self: Pin<&mut Self>);
}

//---------- impl for futures::channel::mpsc ----------

impl<T> SinkCloseChannel<T> for mpsc::Sender<T> {
    fn close_channel(self: Pin<&mut Self>) {
        let self_: &mut Self = Pin::into_inner(self);
        self_.close_channel();
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
    #![allow(clippy::arithmetic_side_effects)] // don't mind potential panicking ops in tests
    #![allow(clippy::useless_format)] // sorely

    use super::*;
    use futures::{SinkExt as _, StreamExt as _};

    #[test]
    fn close_channel() {
        tor_rtmock::MockRuntime::test_with_various(|_rt| async move {
            let (mut tx, mut rx) = mpsc::channel::<i32>(20);
            tx.send(0).await.unwrap();
            let mut tx2 = tx.clone();
            tx2.send(1).await.unwrap();
            tx2.close_channel();
            let _: mpsc::SendError = tx.send(66).await.unwrap_err();
            for i in 0..=1 {
                assert_eq!(rx.next().await.unwrap(), i);
            }
            assert_eq!(rx.next().await, None);
        });
    }
}
