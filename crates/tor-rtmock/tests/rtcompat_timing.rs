//! Example: tests for the timing features in tor-rtcompat.

use tor_rtcompat::test_with_all_runtimes;
use tor_rtcompat::{SleepProvider, SleepProviderExt, Timeout, TimeoutError};

use tor_rtmock::time::MockSleepProvider;

use futures::FutureExt;
use oneshot_fused_workaround as oneshot;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

#[test]
fn timeouts() {
    fn setup() -> (
        MockSleepProvider,
        oneshot::Sender<()>,
        Timeout<oneshot::Receiver<()>, tor_rtmock::time::Sleeping>,
    ) {
        let start = SystemTime::now();
        let (send, recv) = oneshot::channel::<()>();
        let mock_sp = MockSleepProvider::new(start);
        let ten_min = Duration::new(10 * 60, 0);
        let timeout_future = mock_sp.timeout(ten_min, recv);
        (mock_sp, send, timeout_future)
    }

    // The timeout occurs.
    test_with_all_runtimes!(|_| async {
        let (mock_sp, _send, timeout_future) = setup();
        mock_sp.advance(Duration::new(3600, 0)).await;
        assert!(matches!(timeout_future.await, Err(TimeoutError)));
    });
    // The data is ready immediately.
    test_with_all_runtimes!(|_| async {
        let (_, send, timeout_future) = setup();
        send.send(()).unwrap();
        assert_eq!(timeout_future.await, Ok(Ok(())));
    });
    // The data is ready after a little while
    test_with_all_runtimes!(|_| async {
        let (mock_sp, send, timeout_future) = setup();
        mock_sp.advance(Duration::new(10, 0)).await;
        send.send(()).unwrap();
        assert_eq!(timeout_future.await, Ok(Ok(())));
    });
    // The data is ready _and_ the timeout occurs.
    test_with_all_runtimes!(|_| async {
        let (mock_sp, send, timeout_future) = setup();
        send.send(()).unwrap();
        mock_sp.advance(Duration::new(3600, 0)).await;
        assert_eq!(timeout_future.await, Ok(Ok(())));
    });
    // Make sure that nothing happens too early.
    test_with_all_runtimes!(|_| async {
        let (mock_sp, _send, timeout_future) = setup();
        mock_sp.advance(Duration::new(300, 0)).await;
        assert_eq!(timeout_future.now_or_never(), None);
    });
}

fn start() -> SystemTime {
    use humantime::parse_rfc3339;
    parse_rfc3339("2009-04-13T09:13:00Z").unwrap()
}
const ONE_DAY: Duration = Duration::from_secs(86400);

#[test]
fn wallclock_simple() {
    // Simple case: time goes by.
    test_with_all_runtimes!(|_| async {
        let mock_sp = MockSleepProvider::new(start());
        let b = AtomicBool::new(false);
        futures::join!(
            async {
                mock_sp.sleep_until_wallclock(start() + ONE_DAY).await;
                b.store(true, Ordering::SeqCst);
            },
            async {
                while mock_sp.wallclock() < start() + ONE_DAY {
                    assert!(!b.load(Ordering::SeqCst));
                    mock_sp.advance(Duration::new(413, 0)).await;
                }
            }
        );
        assert!(b.load(Ordering::SeqCst));
    });
}

#[test]
fn wallclock_early() {
    // Simple case 2: time goes by, but not enough of it.
    test_with_all_runtimes!(|_| async {
        let mock_sp = MockSleepProvider::new(start());
        let b = AtomicBool::new(false);
        let (send, mut recv) = oneshot::channel();
        futures::join!(
            async {
                let mut sleep = mock_sp.sleep_until_wallclock(start() + ONE_DAY).fuse();
                futures::select! {
                    _ = sleep => b.store(true, Ordering::SeqCst),
                    _ = recv => (),
                };
            },
            async {
                while mock_sp.wallclock() < start() + (ONE_DAY / 2) {
                    assert!(!b.load(Ordering::SeqCst));
                    mock_sp.advance(Duration::new(413, 0)).await;
                }
                send.send(()).unwrap();
            }
        );
        assert!(!b.load(Ordering::SeqCst));
    });
}

#[test]
fn wallclock_jump_forward() {
    // Clock jumps forward, so event triggers.
    test_with_all_runtimes!(|_| async {
        let mock_sp = MockSleepProvider::new(start());
        let b = AtomicBool::new(false);
        let i1 = mock_sp.now();
        futures::join!(
            async {
                mock_sp.sleep_until_wallclock(start() + ONE_DAY).await;
                b.store(true, Ordering::SeqCst);
            },
            async {
                mock_sp.jump_to(start() + ONE_DAY);
                mock_sp.advance(Duration::new(1000, 0)).await; // have to rest some.
            }
        );
        assert!(b.load(Ordering::SeqCst));
        let i2 = mock_sp.now();
        assert!(i2 - i1 < ONE_DAY);
    });
}

#[test]
fn wallclock_jump_backwards() {
    // Clock jumps backward, so event does not trigger early.
    test_with_all_runtimes!(|_| async {
        let mock_sp = MockSleepProvider::new(start());
        let b = AtomicBool::new(false);
        let (send, mut recv) = oneshot::channel();
        let i1 = mock_sp.now();
        futures::join!(
            async {
                let mut sleep = mock_sp.sleep_until_wallclock(start() + ONE_DAY).fuse();
                futures::select! {
                    _ = sleep => b.store(true, Ordering::SeqCst),
                    _ = recv => (),
                };
            },
            async {
                mock_sp.jump_to(start() - ONE_DAY);
                let mut elapsed = Duration::new(0, 0);
                while elapsed < (3 * ONE_DAY) / 2 {
                    assert!(!b.load(Ordering::SeqCst));
                    mock_sp.advance(Duration::new(413, 0)).await;
                    elapsed += Duration::new(413, 0);
                }
                send.send(()).unwrap();
            }
        );
        assert!(!b.load(Ordering::SeqCst));
        let i2 = mock_sp.now();
        assert!(i2 - i1 > ONE_DAY);
        assert!(mock_sp.wallclock() < start() + ONE_DAY);
    });
}
