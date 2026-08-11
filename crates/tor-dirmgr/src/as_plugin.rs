//! TEMPORARY, EXPERIMENTAL implementation of a [`Store`]-backed [`DirBackendPlugin`].
//!
//! This is throw-away code. It exists so that arti relays can pretend to be rudimentary directory
//! caches before tor-dirserver is finished.
//!
//! [`Store`]: crate::storage::Store
//
// NOTE: There are several points where we say "LIMITATION" below to indicate a place
// where this implementation falls short of the specified standard.  We are NOT planning
// to fix these, since this is throw-away code.

use std::sync::{Arc, Mutex};
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_netdoc::{
    doc::{
        authcert::AuthCertKeyIds,
        microdesc::{self, MdDigest},
        netstatus::ConsensusFlavor,
    },
    types::FixedB64,
};

use crate::storage::DynStore;
use tor_dircommon::dir_plugin_backend::{DirBackendPlugin, DirBackendPluginError, http};
use tor_error::into_internal;
use web_time_compat::SystemTime;

// LIMITATION: There is no compression support.
//
// LIMITATION: We copy every object that we serve; memory usage would be terrible in production.
// LIMITATION: We grab the DB lock every time we have a request.
// LIMITATION: We make more DB queries than strictly necessary.
//
// LIMITATION: Since the DirMgr downloads on a client's schedule, we will fetch consensuses
// slightly later than a relay properly should.
//
// LIMITATION: We may cause lock contention.

/// An implementation of [`DirBackendPlugin`] based on a [`DirMgr`]'s sqlite database.
///
/// [`DirMgr`]: crate::DirMgr
#[derive(Clone)]
pub struct DirPlugin {
    /// The underlying storage.
    ///
    /// Typically this uses an underlying sqlite database.
    pub(crate) store: Arc<Mutex<DynStore>>,
}

impl DirBackendPlugin for DirPlugin {
    fn get(
        &self,
        request: &http::Request<()>,
    ) -> Result<http::Response<Box<[u8]>>, DirBackendPluginError> {
        match self.handle_request(request) {
            Ok(v) => Ok(v),
            Err(e) => e.into_response(),
        }
    }
}

impl DirPlugin {
    /// As [`DirBackendPlugin::get`], but return a [`ReqError`] on failure.
    fn handle_request(
        &self,
        request: &http::Request<()>,
    ) -> Result<http::Response<Box<[u8]>>, ReqError> {
        if request.method() != http::Method::GET {
            return Err(ReqError::Unhandled);
        }
        let what = UriInterpretation::interpret(request.uri().path())?;

        match what {
            UriInterpretation::MdsByDigest(items) => self.get_mds(&items[..]),
            UriInterpretation::LatestMdConsensus => self.get_md_consensus(request),
            UriInterpretation::AuthCertsByFpSk(items) => self.get_certs(&items[..]),
        }
    }

    /// Try to handle a request for microdescriptors
    fn get_mds(&self, items: &[MdDigest]) -> Result<http::Response<Box<[u8]>>, ReqError> {
        let store = self.store.lock().expect("poisoned lock");

        let mds = store.microdescs(items)?;
        if mds.is_empty() {
            Err(ReqError::NotFound)
        } else {
            let s: String = mds.values().map(|v| v.as_str()).collect();
            let mut r = http::Response::new(s.into_bytes().into());
            *r.status_mut() = http::StatusCode::OK;
            Ok(r)
        }
    }

    /// Try to handle a request for a microdescriptor consensus.
    fn get_md_consensus(
        &self,
        request: &http::Request<()>,
    ) -> Result<http::Response<Box<[u8]>>, ReqError> {
        // LIMITATION: We ignore which authority FPs the client believes in.
        // LIMITATION: We ignore any diff requests.

        let if_modified_since: Option<SystemTime> = request
            .headers()
            .get("If-Modified-Since")
            .map(|hv| parse_date(hv.as_bytes()))
            .transpose()?;
        let store = self.store.lock().expect("poisoned lock");

        if let Some(ims) = if_modified_since {
            let meta = store.latest_consensus_meta(ConsensusFlavor::Microdesc)?;
            let Some(meta) = meta else {
                return Err(ReqError::NotFound);
            };
            if meta.lifetime().valid_after() < ims {
                return Err(ReqError::NotModified);
            }
        }

        let pending_ok = Some(false);
        let latest = store.latest_consensus(ConsensusFlavor::Microdesc, pending_ok)?;
        let Some(latest) = latest else {
            return Err(ReqError::NotFound);
        };

        // LIMITATION: We just copy the whole whole multi-megabyte consensus.
        let body = latest.as_ref().into();
        let mut r = http::Response::new(body);
        *r.status_mut() = http::StatusCode::OK;
        Ok(r)
    }

    /// Try to handle a request for certificates.
    fn get_certs(&self, items: &[AuthCertKeyIds]) -> Result<http::Response<Box<[u8]>>, ReqError> {
        let store = self.store.lock().expect("poisoned lock");

        let certs = store.authcerts(items)?;
        if certs.is_empty() {
            Err(ReqError::NotFound)
        } else {
            let s: String = certs.values().map(|v| v.as_str()).collect();
            let mut r = http::Response::new(s.into_bytes().into());
            *r.status_mut() = http::StatusCode::OK;
            Ok(r)
        }
    }
}

/// An accepted interpretation of a directory URI.
enum UriInterpretation {
    /// A request for one or more microdescriptors by their SHA256 digest.
    MdsByDigest(Vec<MdDigest>),
    /// A request for the latest MD consensus.
    LatestMdConsensus,
    /// A request for one or more authcerts by fingerprint digest and signing-key digest.
    AuthCertsByFpSk(Vec<AuthCertKeyIds>),
}

impl UriInterpretation {
    /// Based on a relative path, figure out what the client is asking for.
    fn interpret(path: &str) -> Result<Self, ReqError> {
        // Remove optional "tor" part.
        // LIMITATION: Maybe this is no longer optional? I didn't check. It will be fine.
        let path = path.strip_prefix("/tor").unwrap_or(path);

        // LIMITATION: We ignore the ".z" suffix since we're not doing compression.
        let (path, _dot_z) = match path.strip_suffix(".z") {
            Some(p) => (p, true),
            None => (path, false),
        };

        if path.starts_with("/status-vote/current/consensus-md") {
            // LIMITATION: We don't handle the "/diff" URIs.
            // LIMITATION: We don't serve "ns" consensuses.
            // LIMITATION: We ignore the list of fingerprints that follow this part of the path.
            // LIMITATION: We behave incorrectly if asked for a flavor that begins with, but is not,
            //    "md".

            Ok(Self::LatestMdConsensus)
        } else if let Some(remainder) = path.strip_prefix("/micro/d/") {
            let mut digests: Vec<_> = remainder
                .split('-')
                .map(decode_md_digest)
                .collect::<Result<Vec<_>, _>>()
                .map_err(ReqError::Invalid)?;
            digests.sort();
            Ok(UriInterpretation::MdsByDigest(digests))
        } else if let Some(remainder) = path.strip_prefix("/keys/fp-sk/") {
            // LIMITATION: we don't handle other "keys" URIs, since I think clients don't use them.
            let mut pairs: Vec<_> = remainder
                .split('+')
                .map(decode_fp_pair)
                .collect::<Result<Vec<_>, _>>()
                .map_err(ReqError::Invalid)?;
            pairs.sort();
            Ok(UriInterpretation::AuthCertsByFpSk(pairs))
        } else {
            // This is some type of URI we don't handle.
            Err(ReqError::Unhandled)
        }
    }
}

/// Try to parse a base64 MD digest as it appears in URIs.
fn decode_md_digest(s: &str) -> Result<MdDigest, &'static str> {
    let d: FixedB64<{ microdesc::DOC_DIGEST_LEN }> = s.parse().map_err(|_| "Invalid MD base64")?;
    Ok(d.0)
}

/// Try to parse an authority fingerprint pair as it appears in URIs.
fn decode_fp_pair(s: &str) -> Result<AuthCertKeyIds, &'static str> {
    let Some((fp, sk)) = s.split_once('-') else {
        return Err("misformed fingerprint pair");
    };
    let fp = RsaIdentity::from_hex(fp).ok_or("Invalid fp in fingerprint pair")?;
    let sk = RsaIdentity::from_hex(sk).ok_or("Invalid sk in fingerprint pair")?;
    Ok(AuthCertKeyIds {
        id_fingerprint: fp,
        sk_fingerprint: sk,
    })
}

/// Try to parse an HTTP date.
fn parse_date(b: &[u8]) -> Result<SystemTime, ReqError> {
    let s = str::from_utf8(b).map_err(|_| ReqError::Invalid("invalid date"))?;
    httpdate::parse_http_date(s).map_err(|_| ReqError::Invalid("invalid date"))
}

/// An error that has occurred while trying to answer a request.
#[derive(Clone, Debug, thiserror::Error)]
#[allow(clippy::large_enum_variant)] // LIMITATION
enum ReqError {
    /// We found an error while parsing the request.
    #[error("Request was not valid: {0}")]
    Invalid(&'static str),

    /// The user specified an If-Modified-Since header, and the
    /// document was older than that.
    #[error("Not modified since If-Modified-Since")]
    NotModified,

    /// We tried looking for the requested document but it wasn't there.
    #[error("No document present")]
    NotFound,

    /// Some kind of error occurred while looking up an object in the `Store`.
    #[error("Database failure")]
    DbFailed(#[from] crate::Error),

    /// The URI or method was something we don't  deal with.
    #[error("We don't handle this kind of request")]
    Unhandled,
}

impl ReqError {
    /// Convert this error into _either_ a response (if we know what to tell the client)
    /// or a [`DirBackendPluginError`] (if we don't).
    fn into_response(self) -> Result<http::Response<Box<[u8]>>, DirBackendPluginError> {
        match self {
            ReqError::Invalid(msg) => {
                let mut r = http::Response::new(msg.as_bytes().into());
                *r.status_mut() = http::StatusCode::BAD_REQUEST;
                Ok(r)
            }
            ReqError::NotModified => {
                let mut r = http::Response::new("Not modified".as_bytes().into());
                *r.status_mut() = http::StatusCode::NOT_MODIFIED;
                Ok(r)
            }
            ReqError::NotFound => {
                let mut r = http::Response::new("Not found".as_bytes().into());
                *r.status_mut() = http::StatusCode::NOT_FOUND;
                Ok(r)
            }
            ReqError::Unhandled => Err(DirBackendPluginError::UriNotHandledByPlugin),
            ReqError::DbFailed(e) => Err(DirBackendPluginError::Bug(into_internal!(
                "Database failed"
            )(e))),
        }
    }
}
