#![allow(clippy::unwrap_used, clippy::unnecessary_wraps)]
use crate::Runtime;
use crate::SleepProviderExt;

use crate::traits::*;

use futures::io::{AsyncReadExt, AsyncWriteExt};
use futures::stream::StreamExt;
use std::io::Result as IoResult;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant, SystemTime};

// Test "sleep" with a tiny delay, and make sure that at least that
// much delay happens.
fn small_delay<R: Runtime>(runtime: R) -> IoResult<()> {
    let rt = runtime.clone();
    runtime.block_on(async {
        let i1 = Instant::now();
        let one_msec = Duration::from_millis(1);
        rt.sleep(one_msec).await;
        let i2 = Instant::now();
        assert!(i2 >= i1 + one_msec);
    });
    Ok(())
}

// Try a timeout operation that will succeed.
fn small_timeout_ok<R: Runtime>(runtime: R) -> IoResult<()> {
    let rt = runtime.clone();
    runtime.block_on(async {
        let one_day = Duration::from_secs(86400);
        let outcome = rt.timeout(one_day, async { 413_u32 }).await;
        assert_eq!(outcome, Ok(413));
    });
    Ok(())
}

// Try a timeout operation that will time out.
fn small_timeout_expire<R: Runtime>(runtime: R) -> IoResult<()> {
    use futures::future::pending;

    let rt = runtime.clone();
    runtime.block_on(async {
        let one_micros = Duration::from_micros(1);
        let outcome = rt.timeout(one_micros, pending::<()>()).await;
        assert_eq!(outcome, Err(crate::TimeoutError));
        assert_eq!(
            outcome.err().unwrap().to_string(),
            "Timeout expired".to_string()
        );
    });
    Ok(())
}
// Try a little wallclock delay.
//
// NOTE: This test will fail if the clock jumps a lot while it's
// running.  We should use simulated time instead.
fn tiny_wallclock<R: Runtime>(runtime: R) -> IoResult<()> {
    let rt = runtime.clone();
    runtime.block_on(async {
        let i1 = Instant::now();
        let now = SystemTime::now();
        let one_millis = Duration::from_millis(1);
        let one_millis_later = now + one_millis;

        rt.sleep_until_wallclock(one_millis_later).await;

        let i2 = Instant::now();
        let newtime = SystemTime::now();
        assert!(newtime >= one_millis_later);
        assert!(i2 - i1 >= one_millis);
    });
    Ok(())
}

// Try connecting to ourself and sending a little data.
//
// NOTE: requires Ipv4 localhost.
fn self_connect<R: Runtime>(runtime: R) -> IoResult<()> {
    let localhost = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
    let rt1 = runtime.clone();

    let listener = runtime.block_on(rt1.listen(&(localhost.into())))?;
    let addr = listener.local_addr()?;

    runtime.block_on(async {
        let task1 = async {
            let mut buf = vec![0_u8; 11];
            let (mut con, _addr) = listener.accept().await?;
            con.read_exact(&mut buf[..]).await?;
            IoResult::Ok(buf)
        };
        let task2 = async {
            let mut con = rt1.connect(&addr).await?;
            con.write_all(b"Hello world").await?;
            con.flush().await?;
            IoResult::Ok(())
        };

        let (data, send_r) = futures::join!(task1, task2);
        send_r?;

        assert_eq!(&data?[..], b"Hello world");

        Ok(())
    })
}

// Try out our incoming connection stream code.
//
// We launch a few connections and make sure that we can read data on
// them.
fn listener_stream<R: Runtime>(runtime: R) -> IoResult<()> {
    let localhost = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
    let rt1 = runtime.clone();

    let listener = runtime.block_on(rt1.listen(&(localhost.into()))).unwrap();
    let addr = listener.local_addr().unwrap();
    let mut stream = listener.incoming();

    runtime.block_on(async {
        let task1 = async {
            let mut n = 0_u32;
            loop {
                let (mut con, _addr) = stream.next().await.unwrap()?;
                let mut buf = vec![0_u8; 11];
                con.read_exact(&mut buf[..]).await?;
                n += 1;
                if &buf[..] == b"world done!" {
                    break IoResult::Ok(n);
                }
            }
        };
        let task2 = async {
            for _ in 0_u8..5 {
                let mut con = rt1.connect(&addr).await?;
                con.write_all(b"Hello world").await?;
                con.flush().await?;
            }
            let mut con = rt1.connect(&addr).await?;
            con.write_all(b"world done!").await?;
            con.flush().await?;
            con.close().await?;
            IoResult::Ok(())
        };

        let (n, send_r) = futures::join!(task1, task2);
        send_r?;

        assert_eq!(n?, 6);

        Ok(())
    })
}

// Try listening on an address and connecting there, except using TLS.
//
// Note that since we don't have async tls server support yet, I'm just
// going to use a thread.
fn simple_tls<R: Runtime>(runtime: R) -> IoResult<()> {
    /*
     A simple expired self-signed rsa-2048 certificate.

     Generated using OpenSSL 1.1.1k with:

     openssl genpkey -algorithm RSA > test.key
     openssl req -new -out - -key test.key > test.csr
     openssl x509 -in test.csr -out test.crt -req -signkey test.key -days 0
     openssl pkcs12 -export -out test.pfx -inkey test.key -in test.crt
    */
    static PFX_ID: &[u8] = include_bytes!("test.pfx");
    // Note that we need to set a password on the pkcs12 file, since apparently
    // OSX doesn't support pkcs12 with empty passwords. (That was arti#111).
    static PFX_PASSWORD: &str = "abc";

    let localhost = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
    let listener = std::net::TcpListener::bind(localhost)?;
    let addr = listener.local_addr()?;

    let identity = native_tls::Identity::from_pkcs12(PFX_ID, PFX_PASSWORD).unwrap();

    // See note on function for why we're using a thread here.
    let th = std::thread::spawn(move || {
        // Accept a single TLS connection and run an echo server
        use std::io::{Read, Write};
        let acceptor = native_tls::TlsAcceptor::new(identity).unwrap();
        let (con, _addr) = listener.accept()?;
        let mut con = acceptor.accept(con).unwrap();
        let mut buf = [0_u8; 16];
        loop {
            let n = con.read(&mut buf)?;
            if n == 0 {
                break;
            }
            con.write_all(&buf[..n])?;
        }
        IoResult::Ok(())
    });

    let connector = runtime.tls_connector();

    runtime.block_on(async {
        let text = b"I Suddenly Dont Understand Anything";
        let mut buf = vec![0_u8; text.len()];
        let mut conn = connector.connect_unvalidated(&addr, "Kan.Aya").await?;
        assert!(conn.peer_certificate()?.is_some());
        conn.write_all(text).await?;
        conn.flush().await?;
        conn.read_exact(&mut buf[..]).await?;
        assert_eq!(&buf[..], text);
        conn.close().await?;
        IoResult::Ok(())
    })?;

    th.join().unwrap()?;
    IoResult::Ok(())
}

macro_rules! runtime_tests {
    { $($id:ident),* $(,)? } => {
        #[cfg(feature="tokio")]
        mod tokio_runtime_tests {
            use std::io::Result as IoResult;
            $(
                #[test]
                fn $id() -> IoResult<()> {
                    super::$id(crate::tokio::create_runtime()?)
                }
            )*
        }
        #[cfg(feature="async-std")]
        mod async_std_runtime_tests {
            use std::io::Result as IoResult;
            $(
                #[test]
                fn $id() -> IoResult<()> {
                    super::$id(crate::async_std::create_runtime()?)
                }
            )*
        }
    }
}

runtime_tests! {
    small_delay,
    small_timeout_ok,
    small_timeout_expire,
    tiny_wallclock,
    self_connect,
    listener_stream,
    simple_tls,
}
