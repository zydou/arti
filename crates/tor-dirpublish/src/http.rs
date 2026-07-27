//! A generic HTTP uploader.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use tor_error::HasKind;
use tor_rtcompat::{NetStreamProvider, Runtime, SleepProviderExt};

use crate::{UploadError, Uploader};

/// An [`Uploader`] implementation that uses `tor_dirclient` to make a direct HTTP request,
/// not over the Tor network.
///
/// The targets for this uploader are *lists* of IP addresses:
/// Each target represents a *single* directory,
/// so we attempt to upload to at most one address in each target.
pub struct DirectHttpUploader<R> {
    /// A runtime to use for opening TCP connections and creating timers.
    runtime: R,

    /// How long should we delay for 503 responses?
    polite_delay: Duration,
}

/// A failure to upload not counted under some other error type.
#[derive(Clone, Debug, thiserror::Error)]
enum HttpUploadError {
    /// The request required anonymity, and this uploader only supports direct requests.
    #[error("Request type requires anonymity")]
    RequiresAnonymity,

    /// We tried to upload to a Target with no actual addresses.
    #[error("No address for target")]
    NoAddress,
}

impl HasKind for HttpUploadError {
    fn kind(&self) -> tor_error::ErrorKind {
        tor_error::ErrorKind::BadApiUsage
    }
}

#[async_trait]
impl<R: Runtime> Uploader for DirectHttpUploader<R> {
    type Doc = dyn tor_dirclient::request::Requestable;
    type Target = Vec<SocketAddr>;

    async fn upload(
        &self,
        target: Arc<Vec<SocketAddr>>,
        doc: Arc<dyn tor_dirclient::request::Requestable>,
    ) -> Result<(), UploadError> {
        if doc.anonymized() != tor_dirclient::AnonymizedRequest::Direct {
            return Err(UploadError::DocumentFailedPermanently(Arc::new(
                HttpUploadError::RequiresAnonymity,
            ) as _));
        }

        let mut conn = self.connect(target.as_ref()).await?;

        let source_info = None;

        // (This method already checks for timeouts, so we don't have to.)
        let response =
            tor_dirclient::send_request(&self.runtime, &doc, &mut conn, source_info).await;

        UploadError::from_directory_response(response)
            .map_err(|e| e.set_503_delay(self.polite_delay))
    }
}
impl<R: Runtime> DirectHttpUploader<R> {
    /// Create a new [`DirectHttpUploader`].
    ///
    /// Does not launch any requests; use a [`Publisher`](super::Publisher) for that.
    pub fn new(runtime: R) -> Self {
        Self {
            runtime,
            polite_delay: Duration::new(15 * 60, 0), // Arbitrary! Should be lower for authorities!
        }
    }

    /// Open a new connection to one of the addresses in `target`.
    async fn connect(
        &self,
        target: &[SocketAddr],
    ) -> Result<<R as NetStreamProvider>::Stream, UploadError> {
        /// How long should we wait for a given connect attempt to succeed or fail?
        const CONNECT_TIMEOUT: Duration = Duration::new(30, 0);

        let connect_options = Default::default();

        let mut last_error = None;
        // TODO: Happy eyeballs?
        // TODO: Return all errors?
        for addr in target {
            let connect_res = self
                .runtime
                .timeout(
                    CONNECT_TIMEOUT,
                    self.runtime.connect(addr, &connect_options),
                )
                .await;
            match connect_res {
                Ok(Ok(conn)) => return Ok(conn),
                Ok(Err(e)) => last_error = Some(UploadError::Connect(Arc::new(e))),
                Err(_timeout) => last_error = Some(UploadError::Timeout),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            UploadError::DocumentFailedPermanently(Arc::new(HttpUploadError::NoAddress) as _)
        }))
    }
}
