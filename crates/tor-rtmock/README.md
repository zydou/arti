# tor-rtmock

Support for mocking with `tor-rtcompat` asynchronous runtimes.

## Overview

The `tor-rtcompat` crate defines a `Runtime` trait that represents
most of the common functionality of .  This crate provides mock
implementations that override a `Runtime`, in whole or in part,
for testing purposes.

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.
It is used to write tests for higher-level
crates in Arti that rely on asynchronous runtimes.

This crate should only be used for writing tests.

The principal entrypoint for writing tests is [`MockRuntime`],
particularly [`test_with_various`](MockRuntime::test_with_various).

It supports mocking the passage of time
(via [`SimpleMockTimeProvider`](simple_time::SimpleMockTimeProvider)
and
[`MockExecutor`](task::MockExecutor)),
and impersonating the internet (via [`MockNetRuntime`]).

## Comprehensive example

Suppose you've written a function that relies on making a
connection to the network and possibly timing out.

With `tor-rtmock` you can test this function,
replacing the internet, _and_ the passage of time.
The test runs instantly, without actually blocking,
even though it tests a timeout.
And it tests the function against your mocked server,
without making any actual network connections.

```rust
# #[cfg(miri)] // miri cannot do CLOCK_REALTIME
# return;
use tor_rtcompat::{Runtime, SleepProviderExt as _n};
use std::{io, net::{IpAddr, SocketAddr}, time::Duration};
use futures::{channel::oneshot, io::{AsyncReadExt as _, AsyncWriteExt as _}, poll};
use futures::StreamExt as _;
use std::io::ErrorKind;
use tor_rtmock::{MockRuntime, /*MockNetRuntime,*/ net::MockNetwork};
use tor_rtcompat::{NetStreamProvider as _, NetStreamListener as _};

// Code to be tested:

/// Connects to `addr`, says hello, and returns whatever the server sent back
async fn converse(runtime: impl Runtime, addr: &SocketAddr) -> io::Result<Vec<u8>> {
   let delay = Duration::new(5,0);
   runtime.timeout(delay, async {
       let mut conn = runtime.connect(addr).await?;
       conn.write_all(b"Hello world!\r\n").await?;
       conn.flush().await?;
       let mut response = vec![];
       conn.read_to_end(&mut response).await?;
       io::Result::Ok(response)
   }).await?
}

// In test module:

MockRuntime::test_with_various(|rt| async move {
    // The provided `rt` has an empty fake network.
    // We wrap it up with views onto a nonempty one we're using for the test:
    let fake_internet = MockNetwork::new();

    // Make a view that pretends we're at the server address
    let sip: IpAddr = "198.51.100.99".parse().unwrap();
    let srt = fake_internet.builder().add_address(sip).runtime(rt.clone());

    // Make a view that pretends we're at the client address
    let cip: IpAddr = "198.51.100.7".parse().unwrap();
    let crt = fake_internet.builder().add_address(cip).runtime(rt.clone());

    // Helper to spawn a task to execute `converse` and report its results
    //
    // Returns a oneshot::Receiver that becomes ready when `converse` has returned
    let spawn_test = |saddr| {
        let (ret_tx, ret_rx) = oneshot::channel();
        let crt = crt.clone();
        rt.spawn_identified("function under test", async move {
            let ret = converse(crt, &saddr).await;
            ret_tx.send(ret).unwrap();
        });
        ret_rx
    };

    eprintln!("First test.  Nothing is listening.");
    let saddr = SocketAddr::new(sip, 1);
    let ret = spawn_test(saddr).await.unwrap();
    assert_eq!(ret.unwrap_err().kind(), ErrorKind::ConnectionRefused);

    eprintln!("Second test.  Listening, but no-one picks up the phone: timeout.");
    let saddr = SocketAddr::new(sip, 2);
    let listener = srt.listen(&saddr).await.unwrap();
    let mut ret_fut = spawn_test(saddr);
    rt.progress_until_stalled().await; // let it run as far as it can get
    assert!(ret_fut.try_recv().unwrap().is_none()); // it hasn't completed right away
    assert!(poll!(&mut ret_fut).is_pending()); // alternative check, works with any future
    rt.advance_by(Duration::from_secs(4)).await; // run for 4 seconds, < timeout
    assert!(ret_fut.try_recv().unwrap().is_none()); // it still hasn't completed
    rt.advance_by(Duration::from_secs(1)).await; // run for 1 more, reaching timeout
    let ret = ret_fut.try_recv().unwrap().unwrap();
    assert_eq!(ret.unwrap_err().kind(), ErrorKind::TimedOut);

    eprintln!("Third test.  Working.");
    let saddr = SocketAddr::new(sip, 3);
    let listener = srt.listen(&saddr).await.unwrap();
    let mut incoming_streams = listener.incoming();
    let mut ret_fut = spawn_test(saddr);
    let (mut conn, caddr) = incoming_streams.next().await.unwrap().unwrap();
    eprintln!("listener accepted from {caddr:?}");
    assert_eq!(caddr.ip(), cip);
    let expect = b"Hello world!\r\n";
    let mut output = vec![b'X'; expect.len()];
    conn.read_exact(&mut output).await.unwrap();
    eprintln!("listener received {output:?}");
    assert_eq!(output, expect);
    let reply_data = b"reply data";
    conn.write(reply_data).await.unwrap();
    conn.close().await.unwrap();
    let ret = ret_fut.await.unwrap();
    assert_eq!(ret.unwrap(), reply_data);
});
```

License: MIT OR Apache-2.0
