//! Download Management for [`super`].
//!
//! This module consists of [`DownloadManager`], a helper for
//! downloading network documents.
//!
//! More information about the proper use can be found in the documentation
//! of the respective data type.

use std::{collections::VecDeque, fmt::Debug, net::SocketAddr};

use rand::{seq::IndexedRandom, Rng};
use retry_error::RetryError;
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tor_basic_utils::retry::RetryDelay;
use tor_dirclient::request::Requestable;
use tor_error::internal;
use tor_rtcompat::{PreferredRuntime, SleepProvider};
use tracing::{debug, warn};

use crate::err::AuthorityCommunicationError;

/// Download manager for authority requests.
///
/// This structure serves as the main interface for downloading documents from
/// a directory authority.  It implements the logic for retrying failed
/// downloads properly.
///
/// Technically, this structure does not need to be a structure and could be a
/// simple method instead.  However, because many settings stay the same across
/// all download attempts throughout the run-time of this program, making this
/// a separate structure is convenient for making the method signature smaller.
/// No state is kept *within* this structure, instead
/// [`DownloadManager::download()`] accepts an optional reference to a preferred
/// authority while returning the actual used authority, which the caller may
/// store in order to use that authority again in the future.
///
/// It may be worth to note that two round-robin loops, with one of them being
/// nested inside the other, are being used here.  The first serves as an
/// implementation of the specification in order to retry a download from a
/// different authority.  The second, inner, round-robin loop serves as an
/// implementation for happy-eyeballs, which, most commonly,  tries to connect
/// to both, the IPv4 and IPv6 (if present), utilizing the first one that
/// succeeds.  Keep in mind that error handling between these two is different.
/// The outer round-robin loop uses [`RetryError`], keeping track of all errors
/// in case that the download fails from all authorities, whereas the inner
/// round-robin loop uses [`TcpStream::connect()`], which only returns the error
/// of the last failed connection attempt, in the case that all attempts have
/// failed.
///
/// # Algorithm
///
/// 1. Shuffle the list of authorities in a randomized fashion.
/// 2. If there is a preferred authority, swap it with the first item in the list.
/// 3. Iterate through the list, calling [`tor_dirclient::send_request`].
///    3.1. If successful, set preferred authority to the current one and return.
///    3.2. If it failed, timeout with [`RetryDelay`] and go to 3.
///
/// # Specifications
///
/// * <https://spec.torproject.org/dir-spec/directory-cache-operation.html#general-download-behavior>
/// * <https://spec.torproject.org/dir-spec/directory-cache-operation.html#retry-as-cache>
#[derive(Debug)]
pub(super) struct DownloadManager<'a, 'b> {
    /// The list of download authorities.
    ///
    /// TODO DIRMIRROR: Consider accepting an AuthorityContacts and extract the
    /// download addresses ourselves?
    authorities: &'a Vec<Vec<SocketAddr>>,

    /// A handle to the runtime that is being used.
    rt: &'b PreferredRuntime,
}

impl<'a, 'b> DownloadManager<'a, 'b> {
    /// Creates a new [`DownloadManager`] with a set of download authorities.
    pub(super) fn new(authorities: &'a Vec<Vec<SocketAddr>>, rt: &'b PreferredRuntime) -> Self {
        Self { authorities, rt }
    }

    /// Performs a download to a single authority.
    ///
    /// To implement the retry algorithm from the spec, `endpoints` must be the
    /// available addresses (for all address families) for a single authority.
    async fn download_single<Req: Requestable + Debug>(
        &self,
        endpoints: &[SocketAddr],
        req: &Req,
    ) -> Result<Vec<u8>, AuthorityCommunicationError> {
        // This check is important because tokio will panic otherwise.
        if endpoints.is_empty() {
            return Err(AuthorityCommunicationError::Bug(internal!(
                "empty endpoints?"
            )));
        }

        // Fortunately, Tokio's TcpStream::connect already offers round-robin.
        let stream = TcpStream::connect(&endpoints).await.map_err(|error| {
            AuthorityCommunicationError::TcpConnect {
                endpoints: endpoints.to_vec(),
                error,
            }
        })?;

        debug!(
            "connected to {}",
            stream
                .peer_addr()
                .map(|x| x.to_string())
                .unwrap_or("N/A".to_string())
        );
        let mut stream = stream.compat();

        // Perform the actual request.
        match tor_dirclient::send_request(self.rt, req, &mut stream, None)
            .await
            .map(|resp| resp.into_output())
        {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(e)) => Err(Box::new(tor_dirclient::Error::RequestFailed(e)).into()),
            Err(e) => Err(Box::new(e).into()),
        }
    }

    /// Downloads a [`Requestable`] from the download authorities.
    ///
    /// The relevant algorithm is non-trivial, but well-documented in the
    /// [`DownloadManager`], which is why we will leave it out here by
    /// just referencing to it.
    ///
    /// Returns the actual used authority as well as the response, or a
    /// collection of errors.
    #[allow(clippy::cognitive_complexity)]
    pub(super) async fn download<Req: Requestable + Debug, R: Rng>(
        &self,
        req: &Req,
        preferred: Option<&'a Vec<SocketAddr>>,
        rng: &mut R,
    ) -> Result<(&'a Vec<SocketAddr>, Vec<u8>), RetryError<AuthorityCommunicationError>> {
        // Because this is a round-robin approach, we want to collect errors.
        let mut err = RetryError::in_attempt_to("request to authority");

        // Use this struct to calculate delays between iterations.
        let mut retry_delay = RetryDelay::default();

        // Shuffle the list of authorities in a randomized order.
        let mut random_auths = self
            .authorities
            .choose_multiple(rng, self.authorities.len())
            .collect::<VecDeque<_>>();

        // If we have a preferred authority, move it to the front.
        if let Some(preferred) = preferred {
            // In this case, we first throw it out and insert it to the start.
            random_auths.retain(|x| *x != preferred);
            random_auths.push_front(preferred);
        }
        assert_eq!(random_auths.len(), self.authorities.len());

        for endpoints in random_auths {
            if endpoints.is_empty() {
                warn!("empty endpoints in authority?");
                continue;
            }

            match self.download_single(endpoints, req).await {
                Ok(resp) => {
                    debug!("request {req:?} to {endpoints:?} succeeded!");
                    return Ok((endpoints, resp));
                }
                Err(e) => {
                    let delay = retry_delay.next_delay(rng);
                    debug!("request {req:?} to {endpoints:?} failed: {e}");
                    debug!("retrying in {}s", delay.as_secs());
                    err.push_timed(e, self.rt.now(), Some(self.rt.wallclock()));
                    tokio::time::sleep(delay).await;
                }
            }
        }

        Err(err)
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

    use std::{
        io::ErrorKind,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tor_basic_utils::test_rng::testing_rng;
    use tor_dirclient::{request::ConsensusRequest, RequestError};
    use tor_netdoc::doc::netstatus::ConsensusFlavor;

    use super::*;

    /// Testing a request that is immediately successful.
    #[tokio::test]
    async fn request_legit() {
        let server = TcpListener::bind("[::]:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        tokio::task::spawn(async move {
            let mut conn = server.accept().await.unwrap().0;
            let mut buf = vec![0; 1024];
            let _ = conn.read(&mut buf).await.unwrap();
            conn.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nfoo")
                .await
                .unwrap();
        });

        let authorities = vec![vec![server_addr]];
        let rt = PreferredRuntime::current().unwrap();

        let mgr = DownloadManager::new(&authorities, &rt);
        let (preferred, resp) = mgr
            .download(
                &ConsensusRequest::new(ConsensusFlavor::Plain),
                None,
                &mut testing_rng(),
            )
            .await
            .unwrap();

        assert_eq!(resp, b"foo");
        assert_eq!(preferred, &authorities[0]);
    }

    /// Testing for a request that initially fails by returning a 404 but later succeeds.
    #[tokio::test(start_paused = true)]
    async fn request_fail_but_succeed() {
        let mut server_addrs = Vec::new();
        let requ_counter = Arc::new(AtomicUsize::new(0));
        let last = Arc::new(Mutex::new(Vec::new()));
        for _ in 0..8 {
            let server = TcpListener::bind("[::]:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();
            let requ_counter = requ_counter.clone();
            let last = last.clone();
            server_addrs.push(vec![server_addr]);

            tokio::task::spawn(async move {
                loop {
                    let (mut conn, _) = server.accept().await.unwrap();

                    // Store which server_addr was active last, because only the
                    // last one will succeed.
                    *last.lock().unwrap() = vec![server_addr];

                    // This read is important!
                    // Otherwise this server will terminate the connection with
                    // RST instead of FIN, causing everything to fail.
                    let mut buf = vec![0; 1024];
                    let _ = conn.read(&mut buf).await.unwrap();

                    let cur_req = requ_counter.fetch_add(1, Ordering::AcqRel);

                    if cur_req < 7 {
                        // Send a failure.
                        conn.write_all(b"HTTP/1.0 404 Not Found\r\n\r\n")
                            .await
                            .unwrap();
                    } else {
                        // Send a success.
                        conn.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nfoo")
                            .await
                            .unwrap();
                    }
                }
            });
        }

        let rt = PreferredRuntime::current().unwrap();
        let mgr = DownloadManager::new(&server_addrs, &rt);

        let (preferred, resp) = mgr
            .download(
                &ConsensusRequest::new(ConsensusFlavor::Plain),
                None,
                &mut testing_rng(),
            )
            .await
            .unwrap();

        assert_eq!(resp, b"foo");
        assert_eq!(*preferred, *last.lock().unwrap());
    }

    /// Request that fails all the time.
    ///
    /// Failures are done by a server accept and then immediately closing the
    /// connection.
    #[tokio::test(start_paused = true)]
    async fn request_fail_ultimately() {
        let mut server_addrs = Vec::new();
        for _ in 0..8 {
            let server = TcpListener::bind("[::]:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();
            server_addrs.push(vec![server_addr]);

            tokio::task::spawn(async move {
                loop {
                    let _ = server.accept().await.unwrap();
                }
            });
        }

        let rt = PreferredRuntime::current().unwrap();
        let mgr = DownloadManager::new(&server_addrs, &rt);

        let errs = mgr
            .download(
                &ConsensusRequest::new(ConsensusFlavor::Plain),
                None,
                &mut testing_rng(),
            )
            .await
            .unwrap_err();

        // This is just a longer loop to assert all errors are either resets or truncated headers.
        //
        // Because the detection of TCP RST in itself tends to be stochastic at best,
        // we also check for TruncatedHeaders, which is what tor-dirclient will return
        // when it performs a successful(!) read(2) returning zero bytes, indicating
        // a successful closure of the connection.
        for err in errs {
            match err {
                AuthorityCommunicationError::Dirclient(e) => match *e {
                    tor_dirclient::Error::RequestFailed(e) => match e.error {
                        RequestError::IoError(e) => match e.kind() {
                            ErrorKind::ConnectionReset => {}
                            e => unreachable!("{e}"),
                        },
                        RequestError::TruncatedHeaders => {}
                        e => unreachable!("{e}"),
                    },
                    e => unreachable!("{e}"),
                },
                e => unreachable!("{e}"),
            }
        }
    }
}
