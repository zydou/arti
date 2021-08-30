//! Descriptions objects for different kinds of directory requests
//! that we can make.

use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_netdoc::doc::authcert::AuthCertKeyIds;
use tor_netdoc::doc::microdesc::MdDigest;
use tor_netdoc::doc::netstatus::ConsensusFlavor;
use tor_netdoc::doc::routerdesc::RdDigest;

use crate::Result;

use std::iter::FromIterator;
use std::time::SystemTime;

/// A request for an object that can be served over the Tor directory system.
pub trait Requestable {
    /// Build an [`http::Request`] from this Requestable, if
    /// it is well-formed.
    fn make_request(&self) -> Result<http::Request<()>>;

    /// Return true if partial downloads are potentially useful.  This
    /// is true for request types where we're going to be downloading
    /// multiple documents.
    fn partial_docs_ok(&self) -> bool;

    /// Return the maximum allowable response length we'll accept for this
    /// request.
    fn max_response_len(&self) -> usize {
        (16 * 1024 * 1024) - 1
    }
}

/// A Request for a consensus directory.
#[derive(Debug, Clone)]
pub struct ConsensusRequest {
    /// What flavor of consensus are we asking for?  Right now, only
    /// "microdesc" and "ns" are supported.
    flavor: ConsensusFlavor,
    /// A list of the authority identities that we believe in.  We tell the
    /// directory cache only to give us a consensus if it is signed by enough
    /// of these authorities.
    authority_ids: Vec<RsaIdentity>,
    /// The publication time of the most recent consensus we have.  Used to
    /// generate an If-Modified-Since header so that we don't get a document
    /// we already have.
    last_consensus_published: Option<SystemTime>,
    /// A set of SHA3-256 digests of the _signed portion_ of consensuses we have.
    /// Used to declare what diffs we would accept.
    ///
    /// (Currently we don't send this, since we can't handle diffs.)
    last_consensus_sha3_256: Vec<[u8; 32]>,
}

impl ConsensusRequest {
    /// Create a new request for a consensus directory document.
    pub fn new(flavor: ConsensusFlavor) -> Self {
        ConsensusRequest {
            flavor,
            authority_ids: Vec::new(),
            last_consensus_published: None,
            last_consensus_sha3_256: Vec::new(),
        }
    }

    /// Add `id` to the list of authorities that this request should
    /// say we believe in.
    pub fn push_authority_id(&mut self, id: RsaIdentity) {
        self.authority_ids.push(id);
    }

    /// Add `d` to the list of consensus digests this request should
    /// say we already have.
    pub fn push_old_consensus_digest(&mut self, d: [u8; 32]) {
        self.last_consensus_sha3_256.push(d);
    }

    /// Set the publication time we should say we have for our last
    /// consensus to `when`.
    pub fn set_last_consensus_date(&mut self, when: SystemTime) {
        self.last_consensus_published = Some(when);
    }

    /// Return a slice of the consensus digests that we're saying we
    /// already have.
    pub fn old_consensus_digests(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.last_consensus_sha3_256.iter()
    }

    /// Return an iterator of the authority identities that this request
    /// is saying we believe in.
    pub fn authority_ids(&self) -> impl Iterator<Item = &RsaIdentity> {
        self.authority_ids.iter()
    }

    /// Return the date we're reporting for our most recent consensus.
    pub fn last_consensus_date(&self) -> Option<SystemTime> {
        self.last_consensus_published
    }
}

impl Default for ConsensusRequest {
    fn default() -> Self {
        Self::new(ConsensusFlavor::Microdesc)
    }
}

impl Requestable for ConsensusRequest {
    fn make_request(&self) -> Result<http::Request<()>> {
        // Build the URL.
        let mut uri = "/tor/status-vote/current/consensus".to_string();
        match self.flavor {
            ConsensusFlavor::Ns => {}
            flav => {
                uri.push('-');
                uri.push_str(flav.name());
            }
        }
        if !self.authority_ids.is_empty() {
            let mut ids = self.authority_ids.clone();
            ids.sort_unstable();
            uri.push('/');
            let ids: Vec<String> = ids.iter().map(|id| hex::encode(id.as_bytes())).collect();
            uri.push_str(&ids.join("+"));
        }
        uri.push_str(".z");

        let mut req = http::Request::builder().method("GET").uri(uri);
        req = add_common_headers(req);

        // Possibly, add an if-modified-since header.
        if let Some(when) = self.last_consensus_date() {
            req = req.header(
                http::header::IF_MODIFIED_SINCE,
                httpdate::fmt_http_date(when),
            );
        }

        // Possibly, add an X-Or-Diff-From-Consensus header.
        if !self.last_consensus_sha3_256.is_empty() {
            let mut digests = self.last_consensus_sha3_256.clone();
            digests.sort_unstable();
            let digests: Vec<String> = digests.iter().map(hex::encode).collect();
            req = req.header("X-Or-Diff-From-Consensus", &digests.join(", "));
        }

        Ok(req.body(())?)
    }

    fn partial_docs_ok(&self) -> bool {
        false
    }
}

/// A request for one or more authority certificates.
#[derive(Debug, Clone)]
pub struct AuthCertRequest {
    /// The identity/signing keys of the certificates we want.
    ids: Vec<AuthCertKeyIds>,
}

impl AuthCertRequest {
    /// Create a new request, asking for no authority certificates.
    pub fn new() -> Self {
        AuthCertRequest { ids: Vec::new() }
    }

    /// Add `ids` to the list of certificates we're asking for.
    pub fn push(&mut self, ids: AuthCertKeyIds) {
        self.ids.push(ids);
    }

    /// Return a list of the keys that we're asking for.
    pub fn keys(&self) -> impl Iterator<Item = &AuthCertKeyIds> {
        self.ids.iter()
    }
}

impl Default for AuthCertRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl Requestable for AuthCertRequest {
    fn make_request(&self) -> Result<http::Request<()>> {
        let mut ids = self.ids.clone();
        ids.sort_unstable();

        let ids: Vec<String> = ids
            .iter()
            .map(|id| {
                format!(
                    "{}-{}",
                    hex::encode(id.id_fingerprint.as_bytes()),
                    hex::encode(id.sk_fingerprint.as_bytes())
                )
            })
            .collect();

        let uri = format!("/tor/keys/fp-sk/{}.z", &ids.join("+"));

        let req = http::Request::builder().method("GET").uri(uri);
        let req = add_common_headers(req);

        Ok(req.body(())?)
    }

    fn partial_docs_ok(&self) -> bool {
        self.ids.len() > 1
    }

    fn max_response_len(&self) -> usize {
        // TODO: Pick a more principled number; I just made this one up.
        self.ids.len().saturating_mul(16 * 1024)
    }
}

impl FromIterator<AuthCertKeyIds> for AuthCertRequest {
    fn from_iter<I: IntoIterator<Item = AuthCertKeyIds>>(iter: I) -> Self {
        let mut req = Self::new();
        for i in iter {
            req.push(i);
        }
        req
    }
}

/// A request for one or more microdescriptors
#[derive(Debug, Clone)]
pub struct MicrodescRequest {
    /// The SHA256 digests of the microdescriptors we want.
    digests: Vec<MdDigest>,
}

impl MicrodescRequest {
    /// Construct a request for no microdescriptors.
    pub fn new() -> Self {
        MicrodescRequest {
            digests: Vec::new(),
        }
    }
    /// Add `d` to the list of microdescriptors we want to request.
    pub fn push(&mut self, d: MdDigest) {
        self.digests.push(d)
    }

    /// Return a list of the microdescriptor digests that we're asking for.
    pub fn digests(&self) -> impl Iterator<Item = &MdDigest> {
        self.digests.iter()
    }
}

impl Default for MicrodescRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl Requestable for MicrodescRequest {
    fn make_request(&self) -> Result<http::Request<()>> {
        // TODO: require that self.digests is nonempty.
        let mut digests = self.digests.clone();
        digests.sort_unstable();

        let ids: Vec<String> = digests
            .iter()
            .map(|d| base64::encode_config(d, base64::STANDARD_NO_PAD))
            .collect();
        let uri = format!("/tor/micro/d/{}.z", &ids.join("-"));
        let req = http::Request::builder().method("GET").uri(uri);

        let req = add_common_headers(req);

        Ok(req.body(())?)
    }

    fn partial_docs_ok(&self) -> bool {
        self.digests.len() > 1
    }

    fn max_response_len(&self) -> usize {
        // TODO: Pick a more principled number; I just made this one up.
        self.digests.len().saturating_mul(8 * 1024)
    }
}

impl FromIterator<MdDigest> for MicrodescRequest {
    fn from_iter<I: IntoIterator<Item = MdDigest>>(iter: I) -> Self {
        let mut req = Self::new();
        for i in iter {
            req.push(i);
        }
        req
    }
}

/// A request for one, many or all router descriptors.
#[derive(Debug, Clone)]
pub struct RouterDescRequest {
    /// If this is set, we just ask for all the descriptors.
    // TODO: maybe this should be an enum, or maybe this case should
    // be a different type.
    all_descriptors: bool,
    /// A list of digests to download.
    digests: Vec<RdDigest>,
}

impl Default for RouterDescRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl RouterDescRequest {
    /// Construct a request for all router descriptors.
    pub fn all() -> Self {
        RouterDescRequest {
            all_descriptors: true,
            digests: Vec::new(),
        }
    }
    /// Construct a new empty request.
    pub fn new() -> Self {
        RouterDescRequest {
            all_descriptors: false,
            digests: Vec::new(),
        }
    }
    /// Add `d` to the list of digests we want to request.
    pub fn push(&mut self, d: RdDigest) {
        if !self.all_descriptors {
            self.digests.push(d)
        }
    }

    /// Return an iterator over the descriptor digests that we're asking for.
    pub fn digests(&self) -> impl Iterator<Item = &RdDigest> {
        self.digests.iter()
    }
}

impl Requestable for RouterDescRequest {
    fn make_request(&self) -> Result<http::Request<()>> {
        let mut uri = "/tor/server/".to_string();

        if self.all_descriptors {
            uri.push_str("all");
        } else {
            uri.push_str("d/");
            // TODO: require that self.digests is nonempty.
            let mut digests = self.digests.clone();
            digests.sort_unstable();
            let ids: Vec<String> = digests.iter().map(hex::encode).collect();
            uri.push_str(&ids.join("+"));
        }
        uri.push_str(".z");

        let req = http::Request::builder().method("GET").uri(uri);
        let req = add_common_headers(req);

        Ok(req.body(())?)
    }

    fn partial_docs_ok(&self) -> bool {
        self.digests.len() > 1 || self.all_descriptors
    }

    fn max_response_len(&self) -> usize {
        // TODO: Pick a more principled number; I just made these up.
        if self.all_descriptors {
            64 * 1024 * 1024 // big but not impossible
        } else {
            self.digests.len().saturating_mul(8 * 1024)
        }
    }
}

impl FromIterator<RdDigest> for RouterDescRequest {
    fn from_iter<I: IntoIterator<Item = RdDigest>>(iter: I) -> Self {
        let mut req = Self::new();
        for i in iter {
            req.push(i);
        }
        req
    }
}

/// List the encodings we accept
fn encodings() -> String {
    let mut encodings = "deflate, identity".to_string();
    #[cfg(feature = "xz")]
    {
        encodings += ", x-tor-lzma";
    }
    #[cfg(feature = "zstd")]
    {
        encodings += ", x-zstd";
    }

    encodings
}

/// Add commonly used headers to the HTTP request.
///
/// (Right now, this is only Accept-Encoding.)
fn add_common_headers(req: http::request::Builder) -> http::request::Builder {
    // TODO: gzip, brotli
    req.header(http::header::ACCEPT_ENCODING, encodings())
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_md_request() -> Result<()> {
        let d1 = b"This is a testing digest. it isn";
        let d2 = b"'t actually SHA-256.............";

        let mut req = MicrodescRequest::default();
        req.push(*d1);
        assert!(!req.partial_docs_ok());
        req.push(*d2);
        assert!(req.partial_docs_ok());
        assert_eq!(req.max_response_len(), 16 << 10);

        let req = crate::util::encode_request(&req.make_request()?);

        assert_eq!(req,
                   format!("GET /tor/micro/d/J3QgYWN0dWFsbHkgU0hBLTI1Ni4uLi4uLi4uLi4uLi4-VGhpcyBpcyBhIHRlc3RpbmcgZGlnZXN0LiBpdCBpc24.z HTTP/1.0\r\naccept-encoding: {}\r\n\r\n", encodings()));

        // Try it with FromIterator, and use some accessors.
        let req2: MicrodescRequest = vec![*d1, *d2].into_iter().collect();
        let ds: Vec<_> = req2.digests().collect();
        assert_eq!(ds, vec![d1, d2]);
        let req2 = crate::util::encode_request(&req2.make_request()?);
        assert_eq!(req, req2);

        Ok(())
    }

    #[test]
    fn test_cert_request() -> Result<()> {
        let d1 = b"This is a testing dn";
        let d2 = b"'t actually SHA-256.";
        let key1 = AuthCertKeyIds {
            id_fingerprint: (*d1).into(),
            sk_fingerprint: (*d2).into(),
        };

        let d3 = b"blah blah blah 1 2 3";
        let d4 = b"I like pizza from Na";
        let key2 = AuthCertKeyIds {
            id_fingerprint: (*d3).into(),
            sk_fingerprint: (*d4).into(),
        };

        let mut req = AuthCertRequest::default();
        req.push(key1);
        assert!(!req.partial_docs_ok());
        req.push(key2);
        assert!(req.partial_docs_ok());
        assert_eq!(req.max_response_len(), 32 << 10);

        let keys: Vec<_> = req.keys().collect();
        assert_eq!(keys, vec![&key1, &key2]);

        let req = crate::util::encode_request(&req.make_request()?);

        assert_eq!(req,
                   format!("GET /tor/keys/fp-sk/5468697320697320612074657374696e6720646e-27742061637475616c6c79205348412d3235362e+626c616820626c616820626c6168203120322033-49206c696b652070697a7a612066726f6d204e61.z HTTP/1.0\r\naccept-encoding: {}\r\n\r\n", encodings()));

        let req2: AuthCertRequest = vec![key1, key2].into_iter().collect();
        let req2 = crate::util::encode_request(&req2.make_request()?);
        assert_eq!(req, req2);

        Ok(())
    }

    #[test]
    fn test_consensus_request() -> Result<()> {
        let d1 = RsaIdentity::from_bytes(
            &hex::decode("03479E93EBF3FF2C58C1C9DBF2DE9DE9C2801B3E").unwrap(),
        )
        .unwrap();

        let d2 = b"blah blah blah 12 blah blah blah";
        let d3 = SystemTime::now();
        let mut req = ConsensusRequest::default();

        let when = httpdate::fmt_http_date(d3);

        req.push_authority_id(d1);
        req.push_old_consensus_digest(*d2);
        req.set_last_consensus_date(d3);
        assert!(!req.partial_docs_ok());
        assert_eq!(req.max_response_len(), (16 << 20) - 1);
        assert_eq!(req.old_consensus_digests().next(), Some(d2));
        assert_eq!(req.authority_ids().next(), Some(&d1));
        assert_eq!(req.last_consensus_date(), Some(d3));

        let req = crate::util::encode_request(&req.make_request()?);

        assert_eq!(req,
                   format!("GET /tor/status-vote/current/consensus-microdesc/03479e93ebf3ff2c58c1c9dbf2de9de9c2801b3e.z HTTP/1.0\r\naccept-encoding: {}\r\nif-modified-since: {}\r\nx-or-diff-from-consensus: 626c616820626c616820626c616820313220626c616820626c616820626c6168\r\n\r\n", encodings(), when));

        Ok(())
    }

    #[test]
    fn test_rd_request_all() -> Result<()> {
        let req = RouterDescRequest::all();
        assert!(req.partial_docs_ok());
        assert_eq!(req.max_response_len(), 1 << 26);

        let req = crate::util::encode_request(&req.make_request()?);

        assert_eq!(
            req,
            format!(
                "GET /tor/server/all.z HTTP/1.0\r\naccept-encoding: {}\r\n\r\n",
                encodings()
            )
        );

        Ok(())
    }

    #[test]
    fn test_rd_request() -> Result<()> {
        let d1 = b"at some point I got ";
        let d2 = b"of writing in hex...";

        let mut req = RouterDescRequest::default();
        req.push(*d1);
        assert!(!req.partial_docs_ok());
        req.push(*d2);
        assert!(req.partial_docs_ok());
        assert_eq!(req.max_response_len(), 16 << 10);

        let req = crate::util::encode_request(&req.make_request()?);

        assert_eq!(req,
                   format!("GET /tor/server/d/617420736f6d6520706f696e74204920676f7420+6f662077726974696e6720696e206865782e2e2e.z HTTP/1.0\r\naccept-encoding: {}\r\n\r\n", encodings()));

        // Try it with FromIterator, and use some accessors.
        let req2: RouterDescRequest = vec![*d1, *d2].into_iter().collect();
        let ds: Vec<_> = req2.digests().collect();
        assert_eq!(ds, vec![d1, d2]);
        let req2 = crate::util::encode_request(&req2.make_request()?);
        assert_eq!(req, req2);
        Ok(())
    }
}
