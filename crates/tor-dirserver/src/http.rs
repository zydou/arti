//! Module for helping with dirserver's HTTP interface.
//!
//! This module is unfortunately necessary as a middleware due to some obscure
//! things in Tor, most notably the ".z" extensions.

#[allow(unused_imports)]
use std::pin::Pin;
use strum::EnumString;
#[allow(unused_imports)]
use tokio::sync::RwLock;
use tor_error::internal;

use std::{
    collections::VecDeque,
    convert::Infallible,
    panic::{catch_unwind, AssertUnwindSafe},
    str::FromStr,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use deadpool::managed::Pool;
use deadpool_sqlite::Manager;
use futures::{Stream, StreamExt};
use http::{header, Method, Request, Response, StatusCode};
use http_body::{Body, Frame};
use hyper::{
    body::Incoming,
    server::conn::http1::{self},
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use rusqlite::{params, Transaction};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    task::JoinSet,
    time,
};
use tracing::warn;
use weak_table::WeakValueHashMap;

use crate::{
    err::{BuilderError, DatabaseError, StoreCacheError},
    schema::Sha256,
};

/// A type alias for the functions implementing endpoint logic.
///
/// An endpoint function is a function of the following form:
/// ```rust,ignore
/// fn get_consensus(
///     tx: &Transaction<'_>,
///     requ: &Request<Incoming>
/// ) -> Result<Response<Vec<Sha256>>, Box<dyn std::error::Error + Send>>;
/// ```
///
/// The arguments give the endpoint function access to fixed state of the
/// database ([`Transaction`]) and the incoming [`Request`].  The return type is
/// a [`Result`] with an arbitrary error that implements [`Send`] and gets logged
/// but not returned to the client, which will just receive an `Internal Server Error`.
/// The [`Ok`] type of the [`Result`] is a [`Vec`] consisting of [`Sha256`]
/// hashsums identifying (uncompressed) objects in the `store` table.
///
/// Changes to the database within the [`Transaction`] will (for now) get rolled
/// back, thereby giving the endpoint functions just read-only access to the
/// database.
///
/// TODO DIRMIRROR: Document the responsibilities here.
///
/// TODO DIRMIRROR: The error handling of endpoint functions may need further
/// discussions.  Maybe take a look at what other frameworks do?
type EndpointFn = fn(
    &Transaction,
    &Request<Incoming>,
) -> Result<Response<Vec<Sha256>>, Box<dyn std::error::Error + Send>>;

/// Representation of the encoding of the network document the client has requested.
#[derive(Debug, Clone, Copy, PartialEq, EnumString, strum::Display)]
#[strum(serialize_all = "kebab-case", ascii_case_insensitive)]
enum ContentEncoding {
    /// RFC2616 section 3.5.
    Identity,
    /// RFC2616 section 3.5.
    Deflate,
    /// RFC2616 section 3.5.
    Gzip,
    /// The zstandard compression algorithm (www.zstd.net).
    XZstd,
    /// The lzma compression algorithm with a "present" value no higher than 6.
    XTorLzma,
}

/// A type that implements [`Body`] for a list of [`Arc<[u8]>`] data.
///
/// This is required because we use the reference counts as first-level return
/// types in order to avoid duplicate entires of the same data in memory.
/// See the documentation of [`StoreCache`] for more information on that.
struct DocumentBody(VecDeque<Arc<[u8]>>);

/// Representation of an endpoint, uniquely identified by a [`Method`] and path
/// pair followed by an appropriate [`EndpointFn`].
///
/// TODO: Replace the [`Vec`] with a [`str`] and do splitting in the core code.
type Endpoint = (Method, Vec<&'static str>, EndpointFn);

/// Representation of the core HTTP server.
pub(crate) struct HttpServer {
    /// The [`HttpServerBuilder`] used to generate this [`HttpServer`].
    builder: HttpServerBuilder,
}

/// A builder for [`HttpServer`].
///
/// TODO DIRMIRROR: Get rid of this structure and just access the stuff in
/// [`HttpServer`] directly, which is fine given that this is an internal module
/// anyways.
#[derive(Default)]
pub(crate) struct HttpServerBuilder {
    /// The [`Pool`] from deapool to manage database connections.
    pool: Option<Pool<Manager>>,
    /// The HTTP endpoints.
    endpoints: Vec<Endpoint>,
}

/// Representation of the store cache.
///
/// The cache serves the purpose to not store the same document multiple times
/// in memory, when multiple clients request it simultanously.
///
/// It *DOES NOT* serve the purpose to reduce the amount of read system calls.
/// We believe that SQLite and the operating system itself do a good job at
/// buffering reads for us here.
///
/// The cache itself is wrapped in an [`Arc`] as well as in a [`Mutex`],
/// meaning it is safe to share and access around threads/tasks.
///
/// All hash lookups in the `store` table should be performed through this
/// interface, because it will automatically select them from the database in
/// case they are missing.
#[derive(Debug, Clone)]
pub(crate) struct StoreCache {
    /// The actual data of the cache.
    ///
    /// We use a [`Mutex`] instead of an [`RwLock`], because we want to assure
    /// that a concurrent cache miss does not lead into two simultanous database
    /// reads and copies into memory.
    data: Arc<Mutex<WeakValueHashMap<Sha256, Weak<[u8]>>>>,
}

impl Body for DocumentBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(
            self.0
                .pop_front()
                .map(|bytes| Ok(Frame::data(Bytes::from_owner(bytes)))),
        )
    }
}

impl HttpServer {
    /// Creates a new [`HttpServerBuilder`].
    pub(crate) fn builder() -> HttpServerBuilder {
        HttpServerBuilder::default()
    }

    /// Runs the server endlessly in the current task.
    ///
    /// This function does not fail, because all errors that could potentially
    /// occur, occur in further sub-tasks spawned by it and handled appropriately,
    /// that is ususally logging the error and continuing the exeuction.
    #[allow(clippy::cognitive_complexity)]
    pub(crate) async fn serve<I, S, E>(self, mut listener: I) -> Result<(), Infallible>
    where
        I: Stream<Item = Result<S, E>> + Unpin,
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        E: std::error::Error,
    {
        let cache = StoreCache::new();
        let endpoints: Arc<[Endpoint]> = self.builder.endpoints.into();
        let pool = self.builder.pool.expect("builder ensured this is Some");

        // We operate exclusively in JoinSets so that everything gets aborted
        // nicely in order without causing any sort of leaks.
        let mut hyper_tasks: JoinSet<Result<(), hyper::Error>> = JoinSet::new();
        let mut misc_tasks: JoinSet<()> = JoinSet::new();

        // Spawn a simple garbage collection task that periodically removes
        // dead references, just in case, from the StoreCache.
        misc_tasks.spawn({
            let mut cache = cache.clone();
            async move {
                loop {
                    match cache.gc() {
                        Ok(()) => {}
                        Err(e) => warn!("gc failed: {e}"),
                    };
                    time::sleep(Duration::from_secs(60)).await;
                }
            }
        });

        loop {
            tokio::select! {
                res = listener.next() => match res {
                    // Connection successfully accepted.
                    Some(Ok(s)) => Self::dispatch_stream(&cache, &endpoints, &pool, &mut hyper_tasks, s),

                    // There has been an error in accepting the connection.
                    Some(Err(e)) => {
                        warn!("listener accept failure: {e}");
                        continue;
                    }

                    // This should not happen due to ownership.
                    // TODO DIRMIRROR: Replace this with an error by all means.
                    None => unreachable!("listener was closed externally?"),
                },

                // A hyper task we monitored in our tasks has exiteed.
                //
                // We distinguish between graceful and ungraceful errors, with
                // the latter one being errors related to a failure in tokio's
                // joining itself, such as if the underlying task panic'ed;
                // whereas graceful errors are logical application level errors.
                Some(res) = hyper_tasks.join_next() => match res {
                    Ok(Ok(())) => {},
                    Ok(Err(e)) => warn!("client task encountered an error: {e}"),
                    Err(e) => warn!("client task exited ungracefully: {e}"),
                },

            }
        }
    }

    /// Dispatches a new [`Stream`] into an existing [`JoinSet`].
    fn dispatch_stream<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        cache: &StoreCache,
        endpoints: &Arc<[Endpoint]>,
        pool: &Pool<Manager>,
        tasks: &mut JoinSet<Result<(), hyper::Error>>,
        stream: S,
    ) {
        let stream = TokioIo::new(stream);

        // Create the `service_fn` to pass to `hyper`.
        //
        // Unfortunately, we have to clone the reference counter of all shared
        // objects two times here.  The first clone is required to not move
        // it into the `service_fn`, the second one is required to
        // circumvent a hyper limitation, namely that a service function
        // requires a `Fn`, not an `FnMut`, which would allow capturing values
        // from the environment natively.
        let cache = cache.clone();
        let endpoints = endpoints.clone();
        let pool = pool.clone();
        let service = service_fn(move |requ| {
            let cache = cache.clone();
            let endpoints = endpoints.clone();
            let pool = pool.clone();
            async move { Self::handler(cache, endpoints, pool, requ).await }
        });

        tasks.spawn(http1::Builder::new().serve_connection(stream, service));
    }

    /// A small wrapper function that creates a [`Transaction`] and continues
    /// execution in [`Self::handler_tx`].
    async fn handler(
        cache: StoreCache,
        endpoints: Arc<[Endpoint]>,
        pool: Pool<Manager>,
        requ: Request<Incoming>,
    ) -> Result<Response<DocumentBody>, Infallible> {
        // Obtain a database pool object (database connection).
        let conn = match pool.get().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!("database pool error: {e}");
                return Ok(Self::empty_response(StatusCode::INTERNAL_SERVER_ERROR));
            }
        };

        // Create a transaction and pass it to `handler_tx`.
        let res = conn
            .interact(move |conn| {
                let tx = match conn.transaction() {
                    Ok(tx) => tx,
                    Err(e) => {
                        warn!("transaction creation error: {e}");
                        return Ok(Self::empty_response(StatusCode::INTERNAL_SERVER_ERROR));
                    }
                };

                let res = Self::handler_tx(cache, &endpoints, tx, &requ);
                Ok(res)
            })
            .await;

        // Compose the result.
        match res {
            Ok(res) => res,
            Err(e) => {
                warn!("endpoint function error: {e}");
                Ok(Self::empty_response(StatusCode::INTERNAL_SERVER_ERROR))
            }
        }
    }

    /// A big monolithic function that handles incoming request with a consist
    /// view upon the database.
    ///
    /// The function works in eight steps which are documented with more detail
    /// within the code:
    /// 1. Determine the compression algorithm
    /// 2. Select an [`EndpointFn`] by matching the path component
    /// 3. Call the [`EndpointFn`] to obtain various [`Sha256`] hashsums
    /// 4. Map the [`Sha256`] hashsums to their compressed counterpart
    /// 5. Query the [`StoreCache`] with the [`Sha256`] and [`Transaction`] handle
    ///    to store the document ref
    /// 6. Compose the [`Response`]
    /// 7. Commit or drop the transaction, based on the [`Method`]
    ///
    /// TODO DIRMIRROR: Implement [`Method::HEAD`].
    #[allow(clippy::cognitive_complexity)]
    fn handler_tx(
        mut cache: StoreCache,
        endpoints: &[Endpoint],
        tx: Transaction,
        requ: &Request<Incoming>,
    ) -> Response<DocumentBody> {
        // (1) Determine the compression algorithm
        //
        // This step determines the compression algorithm, according to:
        // https://spec.torproject.org/dir-spec/standards-compliance.html#http-headers.
        let (encoding, advertise_encoding) = Self::determine_encoding(requ);

        // (2) Select an `EndpointFn` by matching the path component
        let endpoint_fn = match Self::match_endpoint(endpoints, requ) {
            Some((_, _, endpoint_fn)) => endpoint_fn,
            None => return Self::empty_response(StatusCode::NOT_FOUND),
        };

        // (3) Call the `EndpointFn` to obtain various `Sha256` hashsums
        let endpoint_fn_resp = match catch_unwind(AssertUnwindSafe(|| endpoint_fn(&tx, requ))) {
            // Everything went successful.
            Ok(Ok(r)) => r,

            // The endpoint function gracefully failed with an error.
            Ok(Err(e)) => {
                warn!(
                    "{} {}: endpoint function failed: {e}",
                    requ.method(),
                    requ.uri()
                );
                return Self::empty_response(StatusCode::INTERNAL_SERVER_ERROR);
            }

            // The endpoint function unexpectedly crashed.
            Err(_) => {
                warn!(
                    "{} {}: endpoint function crashed",
                    requ.method(),
                    requ.uri()
                );
                return Self::empty_response(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };
        let (endpoint_fn_parts, sha256sums) = endpoint_fn_resp.into_parts();

        // (4) Map the sha256sums to their compressed counterpart
        let sha256sums = sha256sums
            .iter()
            .map(|sha256| Self::map_encoding(&tx, sha256, encoding))
            .collect::<Result<Vec<_>, _>>();
        let sha256sums = match sha256sums {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    "{} {}: unable to find compressed document: {e}",
                    requ.method(),
                    requ.uri()
                );
                return Self::empty_response(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

        // (5) Query the [`StoreCache`] with the [`Sha256`] and [`Transaction`] handle
        //     to store the document ref
        let mut documents = VecDeque::new();
        for sha256 in &sha256sums {
            let document = match cache.get(&tx, sha256) {
                Ok(document) => document,
                Err(e) => {
                    warn!(
                        "{} {}: unable to access the cache: {e}",
                        requ.method(),
                        requ.uri()
                    );
                    return Self::empty_response(StatusCode::INTERNAL_SERVER_ERROR);
                }
            };

            documents.push_back(document);
        }

        // (6) Compose the `Response`.
        //
        // The composing primarily consists of building a response from the parts
        // of the intermediate response plus optionally adding a Content-Encoding
        // header.
        let mut resp = Response::from_parts(endpoint_fn_parts, DocumentBody(documents));
        if advertise_encoding {
            // Add the Content-Encoding header, if necessary.
            resp.headers_mut().insert(
                header::CONTENT_ENCODING,
                encoding
                    .to_string()
                    .try_into()
                    .expect("strum serialized a non-valid header?!?"),
            );
        }

        // (7) Commit or drop the transaction, based on the `Method`
        //
        // For now, we just drop it.
        match tx.rollback() {
            Ok(()) => {}
            Err(e) => warn!("rollback error: {e}"),
        }

        resp
    }

    /// Determines the [`ContentEncoding`] based on the path and the value of [`header::ACCEPT_ENCODING`].
    ///
    /// This function returns a tuple containing the determined [`ContentEncoding`]
    /// alongside a boolean that indicates whether [`header::CONTENT_ENCODING`]
    /// should be set or not with the value of the just determined
    /// [`ContentEncoding`].
    fn determine_encoding<B: Body>(requ: &Request<B>) -> (ContentEncoding, bool) {
        let z_suffix = requ.uri().path().ends_with(".z");

        // TODO: Refactor this in a flat fashion once we get stable If-Let-Chains
        // by upgrading MSVC to 1.88.
        //
        // This works by branching the parameters into the following four branches:
        // 1. Accept-Encoding && ".z" URL
        // 2. Accept-Encoding && No ".z" URL
        // 3. No Accept-Encoding && ".z" URL
        // 4. No Accept-Encoding && No "z" URL

        // Technically we could use an else-if here, but given the branching
        // I explained above, I would like to keep it in the nested fashion
        // once we got stable If-Let.
        #[allow(clippy::collapsible_else_if)]
        if let Some(accept_encoding) = requ.headers().get(header::ACCEPT_ENCODING) {
            // Parse the accept_encoding value by splitting it at "," and then
            // parse each trimmed component as a ContentEncoding.  Unsupported
            // ContentEncodings are ignored.
            let encodings = accept_encoding
                .to_str()
                .unwrap_or("")
                .split(",")
                .filter_map(|encoding| ContentEncoding::from_str(encoding.trim()).ok())
                .collect::<Vec<_>>();

            if z_suffix {
                // (1) Accept-Encoding && ".z" URL
                //
                // From the specification:
                // > If the client does send an Accept-Encoding header along with
                // > a .z URL, the server SHOULD treat the request the same way
                // > as for the URL without the .z.  If deflate is included in the
                // > Accept-Encoding, the response MUST be encoded, once, with
                // > an encoding advertised by the client, and be accompanied by
                // > an appropriate Content-Encoding.

                // We do not check whether Accept-Encoding contains deflate,
                // because the specification gives us the assurance.
                // TODO: Maybe we should?
                (ContentEncoding::Deflate, true)
            } else {
                // (2) Accept-Encoding && No ".z" URL
                if let Some(encoding) = encodings.first() {
                    // Pick the first found encoding and include it in the header,
                    // if it is not the identity encoding.
                    let include_in_header = *encoding != ContentEncoding::Identity;
                    (*encoding, include_in_header)
                } else {
                    // No supported encodings were found, fallback to identity
                    // and do not provide a Content-Encoding header.
                    // This is effectively equivalent to (4).
                    (ContentEncoding::Identity, false)
                }
            }
        } else {
            if z_suffix {
                // (3) No Accept-Encoding && ".z" URL
                //
                // From the specification:
                // > If the client does not send an Accept-Encoding header along
                // > with a .z URL, the server MUST send the response compressed
                // > with deflate and SHOULD NOT send a Content-Encoding header.
                (ContentEncoding::Deflate, false)
            } else {
                // (4) No Accept-Encoding && No ".z" URL
                (ContentEncoding::Identity, false)
            }
        }
    }

    /// Matches an incoming request to an existing endpoint.
    ///
    /// The matching works in a first-match wins fashion.
    /// An endpoint is said to be matched when the following two properties for
    /// the incoming request hold true:
    /// * Both [`Method`] values are the same.
    /// * Each component of the URL path is equal at the respective position or,
    ///   in the case of the endpoint path, is a wildcard.
    fn match_endpoint<'a, B: Body>(
        endpoints: &'a [Endpoint],
        requ: &Request<B>,
    ) -> Option<&'a Endpoint> {
        let requ_path = requ.uri().path();
        let requ_path = requ_path.strip_suffix(".z").unwrap_or(requ_path);
        let requ_path = requ_path.split('/').collect::<Vec<_>>();
        let mut res = None;
        for tuple in endpoints.iter() {
            let (method, path, _endpoint_fn) = tuple;

            // Filter the method out first.
            if requ.method() != method {
                continue;
            }

            // Now that the method is filtered out, perform the path matching
            // algorithm.
            //
            // The path algorithm works as follows:
            // 1. Check whether `path.len() == requ_path.len()`, for a match,
            //    two paths must have the same number of path components.
            // 2. Initialize `is_match = true`.
            // 3. Walk over the path components in pairs (i.e. compare first
            //    component of `path` with the first component of `requ_path`, ...)
            //    and check for each component tuple, whether they are equal or
            //    whether the component at the current position in path is a
            //    wildcard component, that is, a component that equals `*`.
            //
            //    Stop immediately the moment
            //    `path[i] == requ_path[i] || path[i] == "*"` yields `false`;
            //     set `is_match = false`.
            // 4. Check the result of `is_match`.

            // Paths must have the same number of components in order to match.
            // An inequality here means instant disqualification.
            if path.len() != requ_path.len() {
                continue;
            }

            // Iterate over the path component for component until we disqualify
            // for a match.
            let mut is_match = true;
            for (this, incoming) in path.iter().zip(&requ_path) {
                if this == incoming || *this == "*" {
                    continue;
                } else {
                    is_match = false;
                    break;
                }
            }

            // Stop on the first match, propagate the match to the outside.
            if is_match {
                res = Some(tuple);
                break;
            }
        }

        res
    }

    /// Looks up the corresponding [`Sha256`] for a given [`Sha256`] and a [`ContentEncoding`].
    fn map_encoding(
        tx: &Transaction,
        sha256: &Sha256,
        encoding: ContentEncoding,
    ) -> Result<Sha256, DatabaseError> {
        let sha256 = sha256.clone();

        // If the encoding is the identity, do not bother about it any further.
        if encoding == ContentEncoding::Identity {
            return Ok(sha256);
        }

        let mut stmt = tx.prepare_cached(
            "
        SELECT compressed_sha256
        FROM compressed_document
        WHERE identity_sha256 = ?1 AND algorithm = ?2",
        )?;
        let compressed_sha256 =
            stmt.query_one(params![sha256, encoding.to_string()], |row| row.get(0))?;

        Ok(compressed_sha256)
    }

    /// Generates an empty response with a given [`StatusCode`].
    fn empty_response(status: StatusCode) -> Response<DocumentBody> {
        // TODO DIRMIRROR: Statically assert that.
        Response::builder()
            .status(status)
            .body(DocumentBody(VecDeque::new()))
            .expect("response builder for empty response failed?!?")
    }
}

impl HttpServerBuilder {
    /// Creates a new [`HttpServerBuilder`] with default values.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Sets the database pool which is mandatory.
    pub(crate) fn pool(mut self, pool: Pool<Manager>) -> Self {
        self.pool = Some(pool);
        self
    }

    /// Adds a new [`Method::GET`] endpoint.
    ///
    /// `path` is a special string that refers to the endpoint at which this
    /// resource should be available.  It supports a pattern-matching like
    /// syntax through the use of the asterisk `*` character.
    ///
    /// For example:
    /// `/tor/status-vote/current/consensus` will match the URL exactly, whereas
    /// `/tor/status-vote/current/*` will match every string that is in the
    /// fourth component; such as `/tor/status-vote/current/consensus` or
    /// `/tor/status-vote/current/consensus-microdesc`; it will however not
    /// match in a prefix-like syntax, such as
    /// `/tor/status-vote/current/consensus-microdesc/diff`.
    ///
    /// In the case of non-unique matches, the first match wins.  Also, because
    /// of wildcards, matching takes place in a `O(n)` fashion, so be sure to
    /// to keep the `n` at a reasonable size.  This should not be much of a
    /// problem for Tor applications though, because the list of endpoints is
    /// reasonable (less than 30).
    ///
    /// TODO: The entire asterisk matching is not so super nice, primarily because
    /// it removes compile-time semantic checks; however, I cannot really think
    /// of a much cleaner way that would not involve lots of boilerplate.
    /// The most minimal "clean" way could be to do `path: &Option<&'static str>`
    /// but I am not sure if this overhead is worth it, i.e.:
    /// * `/tor/status-vote/current/*/diff/*/*`
    /// * `[Some(""), Some("tor"), Some("status-vote"), Some("current"), None, ...]`
    ///   Maybe a macro could help here though ...
    pub(crate) fn get(mut self, path: &'static str, endpoint_fn: EndpointFn) -> Self {
        self.endpoints
            .push((Method::GET, path.split('/').collect(), endpoint_fn));
        self
    }

    /// Consumes the [`HttpServerBuilder`] to build an [`HttpServer`].
    pub(crate) fn build(self) -> Result<HttpServer, BuilderError> {
        // Check the presence of mandatory fields.
        if self.pool.is_none() {
            return Err(BuilderError::MissingField("pool"));
        }

        Ok(HttpServer { builder: self })
    }
}

impl StoreCache {
    /// Creates a new empty [`StoreCache`].
    pub(crate) fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(WeakValueHashMap::new())),
        }
    }

    /// Removes all mappings whose values have expired.
    ///
    /// Takes O(n) time.
    pub(crate) fn gc(&mut self) -> Result<(), StoreCacheError> {
        self.data
            .lock()
            .map_err(|_| internal!("poisoned lock"))?
            .remove_expired();
        Ok(())
    }

    /// Looks up a [`Sha256`] in the cache or the database.
    ///
    /// If we got a cache miss, this function automatically queries the database
    /// and inserts the result into the cache, before returning it.
    pub(crate) fn get(
        &mut self,
        tx: &Transaction,
        sha256: &Sha256,
    ) -> Result<Arc<[u8]>, StoreCacheError> {
        // TODO DIRMIRROR: Do we want to keep the lock while doing db queries?
        let mut lock = self.data.lock().map_err(|_| internal!("poisoned lock"))?;

        // Query the cache for the relevant document.
        if let Some(document) = lock.get(sha256) {
            return Ok(document);
        }

        // Cache miss, let us query the database.
        let document = Self::get_db(tx, sha256)?;

        // Insert it into the cache.
        lock.insert(sha256.clone(), document.clone());

        Ok(document)
    }

    /// Obtains a [`Sha256`] from the database without consulting the cache first.
    ///
    /// TODO DIRMIRROR: This function is only intended for use in [`StoreCache::get`].
    /// Consider to either remove it entirely or move [`StoreCache`] into its own
    /// module.
    fn get_db(tx: &Transaction, sha256: &Sha256) -> Result<Arc<[u8]>, StoreCacheError> {
        let mut stmt = tx
            .prepare_cached("SELECT content FROM store WHERE sha256 = ?1")
            .map_err(DatabaseError::from)?;
        let document: Vec<u8> = stmt
            .query_one(params![sha256], |row| row.get(0))
            .map_err(DatabaseError::from)?;
        Ok(Arc::from(document))
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

    use std::{
        io::{Cursor, Write},
        str::FromStr,
    };

    use deadpool_sqlite::Config;
    use flate2::{
        write::{DeflateDecoder, DeflateEncoder, GzEncoder},
        Compression,
    };
    use http::Version;
    use http_body_util::{BodyExt, Empty};
    use rusqlite::Connection;
    use sha2::{digest::Update, Digest};
    use tokio::{
        net::{TcpListener, TcpStream},
        task,
    };
    use tokio_stream::wrappers::TcpListenerStream;

    use crate::schema::prepare_db;

    const IDENTITY: &str = "Lorem ipsum dolor sit amet.";
    const IDENTITY_SHA256: &str =
        "DD14CBBF0E74909AAC7F248A85D190AFD8DA98265CEF95FC90DFDDABEA7C2E66";
    const DEFLATE_SHA256: &str = "07564DD13A7F4A6AD98B997F2938B1CEE11F8C7F358C444374521BA54D50D05E";
    const GZIP_SHA256: &str = "1518107D3EF1EC6EAC3F3249DF26B2F845BC8226C326309F4822CAEF2E664104";
    const XZ_STD_SHA256: &str = "17416948501F8E627CC9A8F7EFE7A2F32788D53CB84A5F67AC8FD4C1B59184CF";
    const X_TOR_LZMA_SHA256: &str =
        "B5549F79A69113BDAF3EF0AD1D7D339D0083BC31400ECEE1B673F331CF26E239";

    async fn create_test_db_pool() -> Pool<Manager> {
        let pool = Config::new("")
            .create_pool(deadpool::Runtime::Tokio1)
            .unwrap();

        pool.get()
            .await
            .unwrap()
            .interact(init_test_db)
            .await
            .unwrap();

        pool
    }

    fn create_test_db_connection() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        init_test_db(&mut conn);
        conn
    }

    fn init_test_db(conn: &mut Connection) {
        prepare_db(conn).unwrap();

        // Create a document and compressed versions of it.
        let identity_sha256 = hex::encode_upper(sha2::Sha256::new().chain(IDENTITY).finalize());
        assert_eq!(identity_sha256, IDENTITY_SHA256);

        let deflate = {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(IDENTITY.as_bytes()).unwrap();
            encoder.finish().unwrap()
        };
        let deflate_sha256 = hex::encode_upper(sha2::Sha256::new().chain(&deflate).finalize());
        assert_eq!(deflate_sha256, DEFLATE_SHA256);

        let gzip = {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(IDENTITY.as_bytes()).unwrap();
            encoder.finish().unwrap()
        };
        let gzip_sha256 = hex::encode_upper(sha2::Sha256::new().chain(&gzip).finalize());
        assert_eq!(gzip_sha256, GZIP_SHA256);

        let xz_std = zstd::encode_all(IDENTITY.as_bytes(), 3).unwrap();
        let xz_std_sha256 = hex::encode_upper(sha2::Sha256::new().chain(&xz_std).finalize());
        assert_eq!(xz_std_sha256, XZ_STD_SHA256);

        let mut x_tor_lzma = Vec::new();
        lzma_rs::lzma_compress(&mut Cursor::new(IDENTITY), &mut x_tor_lzma).unwrap();
        let x_tor_lzma_sha256 =
            hex::encode_upper(sha2::Sha256::new().chain(&x_tor_lzma).finalize());
        assert_eq!(x_tor_lzma_sha256, X_TOR_LZMA_SHA256);

        let tx = conn.transaction().unwrap();
        tx.execute(
            "
                        INSERT INTO store(sha256, content) VALUES
                        (?1, ?2), -- identity
                        (?3, ?4), -- deflate
                        (?5, ?6), -- gzip
                        (?7, ?8), -- xzstd
                        (?9, ?10); -- lzma
                    ",
            params![
                identity_sha256,
                IDENTITY.as_bytes().to_vec(),
                deflate_sha256,
                deflate,
                gzip_sha256,
                gzip,
                xz_std_sha256,
                xz_std,
                x_tor_lzma_sha256,
                x_tor_lzma
            ],
        )
        .unwrap();

        tx.execute("
                INSERT INTO compressed_document(algorithm, identity_sha256, compressed_sha256) VALUES
                ('deflate', ?1, ?2),
                ('gzip', ?1, ?3),
                ('x-zstd', ?1, ?4),
                ('x-tor-lzma', ?1, ?5);
                ",
                params![identity_sha256, deflate_sha256, gzip_sha256, xz_std_sha256, x_tor_lzma_sha256]).unwrap();

        tx.commit().unwrap();
    }

    #[test]
    fn content_encoding() {
        assert_eq!(ContentEncoding::Identity.to_string(), "identity");
        assert_eq!(
            ContentEncoding::from_str("identity").unwrap(),
            ContentEncoding::Identity
        );

        assert_eq!(ContentEncoding::Deflate.to_string(), "deflate");
        assert_eq!(
            ContentEncoding::from_str("DeFlaTe").unwrap(),
            ContentEncoding::Deflate
        );

        assert_eq!(ContentEncoding::Gzip.to_string(), "gzip");
        assert_eq!(
            ContentEncoding::from_str("GzIP").unwrap(),
            ContentEncoding::Gzip
        );
        assert_eq!(ContentEncoding::XZstd.to_string(), "x-zstd");
        assert_eq!(
            ContentEncoding::from_str("x-zStD").unwrap(),
            ContentEncoding::XZstd
        );

        assert_eq!(ContentEncoding::XTorLzma.to_string(), "x-tor-lzma");
        assert_eq!(
            ContentEncoding::from_str("x-tOr-lzMa").unwrap(),
            ContentEncoding::XTorLzma
        );
    }

    #[test]
    fn determine_encoding() {
        // 1. Accept-Encoding && ".z" URL.
        let requ = Request::builder()
            .header("Accept-Encoding", "deflate,identity  ,  gzip")
            .uri("/foo.z")
            .body(String::new())
            .unwrap();
        assert_eq!(
            HttpServer::determine_encoding(&requ),
            (ContentEncoding::Deflate, true)
        );

        // 2a. Valid Accept-Encoding && No ".z" URL.
        let requ = Request::builder()
            .header("Accept-Encoding", "  gzip   ")
            .uri("/foo")
            .body(String::new())
            .unwrap();
        assert_eq!(
            HttpServer::determine_encoding(&requ),
            (ContentEncoding::Gzip, true)
        );

        // 2b. Identity Accept-Encoding && No ".z" URL.
        let requ = Request::builder()
            .header("Accept-Encoding", "identity")
            .uri("/foo")
            .body(String::new())
            .unwrap();
        assert_eq!(
            HttpServer::determine_encoding(&requ),
            (ContentEncoding::Identity, false)
        );

        // 2c. Invalid Accept-Encoding && No ".z" URL.
        let requ = Request::builder()
            .header("Accept-Encoding", "  unSuppOrtEd_EncODing_SCHEMA , yeah   ")
            .uri("/foo")
            .body(String::new())
            .unwrap();
        assert_eq!(
            HttpServer::determine_encoding(&requ),
            (ContentEncoding::Identity, false)
        );

        // 3. No Accept-Encoding && ".z" URL
        let requ = Request::builder()
            .uri("/foo.z")
            .body(String::new())
            .unwrap();
        assert_eq!(
            HttpServer::determine_encoding(&requ),
            (ContentEncoding::Deflate, false)
        );

        // 4. No Accept-Encoding && No ".z" URL
        let requ = Request::builder().uri("/foo").body(String::new()).unwrap();
        assert_eq!(
            HttpServer::determine_encoding(&requ),
            (ContentEncoding::Identity, false)
        );
    }

    #[test]
    fn match_endpoint() {
        /// Dummy call back that does nothing and is not even called.
        fn dummy(
            _: &Transaction,
            _: &Request<Incoming>,
        ) -> Result<Response<Vec<Sha256>>, Box<dyn std::error::Error + Send>> {
            todo!()
        }

        let endpoints: Vec<Endpoint> = vec![
            (Method::GET, vec!["", "foo", "bar", "baz"], dummy),
            (Method::GET, vec!["", "foo", "*", "baz"], dummy),
            (Method::GET, vec!["", "bar", "*"], dummy),
            (Method::GET, vec!["", ""], dummy),
        ];

        /// Basically a domain specific [`assert_eq`] that works by comparing
        /// pointers instead of a deep comparison.
        macro_rules! check_match {
            ($uri:literal, $endpoint:literal) => {
                let requ = Request::builder().uri($uri).body(String::new()).unwrap();
                let left: *const Endpoint = HttpServer::match_endpoint(&endpoints, &requ).unwrap();
                let right: *const Endpoint = &endpoints[$endpoint];
                assert_eq!(left, right);
            };
        }

        macro_rules! check_no_match {
            ($uri:literal) => {
                let requ = Request::builder().uri($uri).body(String::new()).unwrap();
                assert!(HttpServer::match_endpoint(&endpoints, &requ).is_none());
            };
        }

        check_match!("/foo/bar/baz", 0);
        check_match!("/foo/bar/baz.z", 0);
        check_no_match!("/foo/bar/baz1");
        check_no_match!("/foo/bar/baz/");

        check_match!("/foo/I_DONT_CARE/baz", 1);
        check_match!("/foo/I_DONT_CARE/baz.z", 1);
        check_match!("/foo//baz", 1);
        check_no_match!("/foo/");
        check_no_match!("/foo/foo");
        check_no_match!("/foo/foo/foo");

        check_match!("/bar/", 2);
        check_match!("/bar/.z", 2);
        check_match!("/bar/foo", 2);
        check_match!("/bar/foo.z", 2);
        check_no_match!("/bar/foo/");
        check_no_match!("/bar/foo/foo");

        check_match!("/", 3);
        check_match!("/.z", 3);
    }

    #[test]
    fn map_encoding() {
        let mut conn = create_test_db_connection();

        let data = [
            (ContentEncoding::Identity, IDENTITY_SHA256),
            (ContentEncoding::Deflate, DEFLATE_SHA256),
            (ContentEncoding::Gzip, GZIP_SHA256),
            (ContentEncoding::XZstd, XZ_STD_SHA256),
            (ContentEncoding::XTorLzma, X_TOR_LZMA_SHA256),
        ];

        let tx = conn.transaction().unwrap();
        for (encoding, compressed_sha256) in data {
            println!("{encoding}");
            assert_eq!(
                HttpServer::map_encoding(&tx, &IDENTITY_SHA256.to_string(), encoding).unwrap(),
                compressed_sha256
            );
        }
    }

    #[tokio::test]
    async fn basic_http_server() {
        // This is a stupid clippy false positive.
        #[allow(clippy::unnecessary_wraps)]
        fn identity(
            _tx: &Transaction<'_>,
            _requ: &Request<Incoming>,
        ) -> Result<Response<Vec<Sha256>>, Box<dyn std::error::Error + Send>> {
            Ok(Response::new(vec![IDENTITY_SHA256.into()]))
        }

        let pool = create_test_db_pool().await;
        let server = HttpServer::builder()
            .pool(pool)
            .get("/tor/status-vote/current/consensus", identity)
            .build()
            .unwrap();

        let listener = TcpListener::bind("[::]:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let listener = TcpListenerStream::new(listener);

        task::spawn(async move {
            server.serve(listener).await.unwrap();
        });

        let stream = TcpStream::connect(local_addr).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();

        task::spawn(async move {
            if let Err(e) = conn.await {
                println!("Connection failed: {e:?}");
            }
        });

        // Perform a simple request.
        // TODO: Put this into one function for making requests or use reqwest.
        let requ = Request::builder()
            .version(Version::HTTP_11)
            .uri("/tor/status-vote/current/consensus")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let mut resp = sender.send_request(requ).await.unwrap();
        let mut resp_body: Vec<u8> = Vec::new();
        while let Some(next) = resp.frame().await {
            resp_body.append(&mut next.unwrap().data_ref().unwrap().as_ref().to_vec());
        }
        assert_eq!(IDENTITY, String::from_utf8_lossy(&resp_body));

        // Perform a ".z" request.
        let requ = Request::builder()
            .version(Version::HTTP_11)
            .uri("/tor/status-vote/current/consensus.z")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let mut resp = sender.send_request(requ).await.unwrap();
        let mut resp_body: Vec<u8> = Vec::new();
        while let Some(next) = resp.frame().await {
            resp_body.append(&mut next.unwrap().data_ref().unwrap().as_ref().to_vec());
        }
        let mut decoder = DeflateDecoder::new(Vec::new());
        decoder.write_all(&resp_body).unwrap();
        let decoded_resp = decoder.finish().unwrap();
        assert_eq!(IDENTITY, String::from_utf8_lossy(&decoded_resp));
    }

    #[test]
    fn store_cache() {
        let mut conn = create_test_db_connection();
        let mut cache = StoreCache::new();

        let tx = conn.transaction().unwrap();

        // Obtain the lipsum entry.
        let entry = cache.get(&tx, &String::from(IDENTITY_SHA256)).unwrap();
        assert_eq!(entry.as_ref(), IDENTITY.as_bytes());
        assert_eq!(Arc::strong_count(&entry), 1);

        // Obtain the lipsum entry again but ensure it is not copied in memory.
        let entry2 = cache.get(&tx, &String::from(IDENTITY_SHA256)).unwrap();
        assert_eq!(Arc::strong_count(&entry), 2);
        assert_eq!(Arc::as_ptr(&entry), Arc::as_ptr(&entry2));
        assert_eq!(entry, entry2);

        // Perform a garbage collection and ensure that entry is not removed.
        assert!(cache
            .data
            .lock()
            .unwrap()
            .contains_key(&String::from(IDENTITY_SHA256)));
        cache.gc().unwrap();
        assert!(cache
            .data
            .lock()
            .unwrap()
            .contains_key(&String::from(IDENTITY_SHA256)));

        // Now drop entry and entry2 and perform the gc again.
        let weak_entry = Arc::downgrade(&entry);
        assert_eq!(weak_entry.strong_count(), 2);
        drop(entry);
        drop(entry2);
        assert_eq!(weak_entry.strong_count(), 0);

        // The strong count zero should already make it impossible to access the element ...
        assert!(!cache
            .data
            .lock()
            .unwrap()
            .contains_key(&String::from(IDENTITY_SHA256)));
        // ... but it should not reduce the total size of the hash map ...
        assert_eq!(cache.data.lock().unwrap().len(), 1);
        cache.gc().unwrap();
        // ... however, the garbage collection should actually do.
        assert_eq!(cache.data.lock().unwrap().len(), 0);
    }
}
