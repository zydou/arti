//! Directory Mirror Operation.
//!
//! # Specifications
//!
//! * [Directory cache operation](https://spec.torproject.org/dir-spec/directory-cache-operation.html).
//!
//! # Rationale
//!
//! This module implements the "core operation" of a directory mirror.
//! "Core operation" primarily refers to the logic involved in downloading
//! network documents from an upstream authority and inserting them into the
//! database.  This module notably **DOES NOT** provide any public (in the HTTP
//! sense) endpoints for querying documents.  This is purposely behind a different
//! module, so that the directory authority implementation can also make use of it.
//! You can think of this module as the one implementing the things unique
//! to directory mirrors.

use std::{
    collections::{HashSet, VecDeque},
    net::SocketAddr,
};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rand::{seq::SliceRandom, Rng};
use rusqlite::Transaction;
use strum::IntoEnumIterator;
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tor_basic_utils::retry::RetryDelay;
use tor_dirclient::request::{AuthCertRequest, ConsensusRequest, Requestable};
use tor_dircommon::{authority::AuthorityContacts, config::DirTolerance};
use tor_error::{internal, into_internal};
use tor_netdoc::{
    doc::{
        authcert::{AuthCertKeyIds, AuthCertUnverified},
        netstatus::ConsensusFlavor,
    },
    parse2::{
        self,
        poc::netstatus::{cons, md, NdiDirectorySignature},
        NetdocParseable, NetdocUnverified, ParseInput,
    },
};
use tor_rtcompat::PreferredRuntime;
use tracing::{debug, warn};

use crate::{
    database::{self as db, AuthCertMeta, ConsensusMeta, ContentEncoding, Timestamp},
    err::{AuthorityRequestError, DatabaseError, IsFatal, OperationError},
};

/// The various states for the [`StaticEngine`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::Display)]
enum State {
    /// Loads the most recent valid (and verified) consensus from the database
    /// into memory.
    ///
    /// Transitions from:
    /// * Start, if a recent valid consensus exists in the database.
    /// * [`State::StoreConsensus`], if successfully finished.
    ///
    /// Transitions into:
    /// * [`State::Descriptors`]
    LoadConsensus,

    /// Downloads the most recent consensus from a directory authority.
    ///
    /// Transitions from:
    /// * Start, if no recent valid consensus exists in the database.
    /// * [`State::Descriptors`], if lifetime is over.
    /// * [`State::Hibernate`], if lifetime is over.
    ///
    /// Transitions into:
    /// * [`State::AuthCerts`], if we miss authority certificates.
    /// * [`State::StoreConsensus`], if all authority certificates exist in the
    ///   database.
    // TODO DIRMIRROR: What to do in the case of getting an invalid consensus
    // such as junk data?  The normal retry logic sounds reasonable here.
    FetchConsensus,

    /// Downloads, validates, and stores the missing authority certificates from
    /// the downloaded unvalidated consensus into the database.
    ///
    /// Transitions from:
    /// * [`State::FetchConsensus`], if we miss authority certificates.
    /// * [`State::AuthCerts`], if we still miss authority certificates.
    ///
    /// Transitions into:
    /// * [`State::AuthCerts`], if we still miss authority certificates.
    /// * [`State::StoreConsensus`], if we got all authority certificates.
    // TODO DIRMIRROR: What to do in the case of a MITM attack where an attacker
    // adds lots of invalid signature items at the bottom, leading to lots of
    // queries for directory authority certificates, which may succeed or not?
    // Best idea is probably to only download authcerts whose id fingerprints
    // are configured in our AuthorityContacts, because then we have an upper
    // limit.
    AuthCerts,

    /// Validates and stores the downloaded unvalidated consensus into the
    /// database.
    ///
    /// Transitions from:
    /// * [`State::FetchConsensus`], if we have all authority certificates.
    /// * [`State::AuthCerts`], if we have all authority certificates.
    ///
    /// Transitions into:
    /// * [`State::LoadConsensus`]
    StoreConsensus,

    /// Downloads missing network documents (descriptors) from a directory
    /// authority.
    ///
    /// Transitions from:
    /// * [`State::LoadConsensus`], if we initialize.
    /// * [`State::Descriptors`], if we still have missing descriptors left.
    ///
    /// Transitions into:
    /// * [`State::FetchConsensus`], if lifetime is over.
    /// * [`State::Descriptors`], if we still have missing descriptors left.
    /// * [`State::Hibernate`], if nothing is left.
    Descriptors,

    /// Hibernate because nothing is left.
    ///
    /// Transitions from:
    /// * [`State::Descriptors`]
    ///
    /// Transitions into:
    /// * [`State::FetchConsensus`], if the lifetime is over.
    Hibernate,
}

/// The execution engine for the finite state machine.
///
/// The states themselves are explained in [`State`].
///
/// This data structure itself is static and contains no state, but merely
/// configuration primitives that stay constant throughout the runtime of the
/// program, such as the [`ConsensusFlavor`], the [`AuthorityContacts`], and the
/// [`DirTolerance`].  It can be kept throughout the entire runtime and only
/// consists for convience in order to not give each state machine related
/// (then static) method a super long signature containing these fields.
///
/// The state itself is computed fully deterministically from the data found
/// within the database and [`ConsensusBoundData`].
///
/// This is the reason on why this structure is not called `StateMachine`,
/// because this implies that the type in itself carries state, which is not
/// true, because the state is stored entirely external, with this engine
/// only processing and modifying it.
///
/// See [`StaticEngine::determine_state()`] for more details.
#[derive(Debug)]
struct StaticEngine {
    /// The flavor of the consensus we are serving.
    flavor: ConsensusFlavor,

    /// The authorities we are acknowledging.
    authorities: AuthorityContacts,

    /// The document tolerance we are accepting.
    tolerance: DirTolerance,

    /// The preferred runtime for compatibility with other arti crates.
    ///
    /// Generally obtained through [`PreferredRuntime::current()`].
    rt: PreferredRuntime,
}

/// Additional state machine data concering a single consensus.
///
/// This enum stores and keeps track of the consensus we are serving and in
/// which ✨state✨ it is currently in, such as whether it is verified or not,
/// or if we even have a state loaded in memory in the first place.
#[derive(Debug, Clone)]
enum ConsensusBoundData {
    /// No state is loaded in memory at the moment.
    None,

    /// We have downloaded a consensus but it is not yet verified.
    Unverified {
        /// The unverified parsed consensus we have.
        // TODO DIRMIRROR: Make this optional, see comment in
        // StaticEngine::execute.
        consensus: FlavoredConsensusSigned,

        /// The unparsed raw consensus we have.
        raw: String,
    },

    /// We have downloaded and verified a consensus.
    Verified {
        /// The verified consensus we have.
        consensus: FlavoredConsensus,

        /// When to stop dealing with this consensus and fetching a new one.
        lifetime: Timestamp,

        /// SHA-1 digests of the missing server descriptors in the consensus.
        server_queue: HashSet<db::Sha1>,

        /// SHA-1 digests of the missing extra-info descriptors in the server
        /// descriptors of the consensus.
        ///
        /// extra-info documents are only transitively related to a consensus
        /// through consensus -> server descriptors -> extra-info descriptors
        extra_queue: HashSet<db::Sha1>,

        /// SHA-256 digests of the missing micro descriptors in the consensus.
        ///
        /// This field is technically mutually exclusive to server_queue and
        /// extra_queue because micro descriptors are only found in
        /// [`ConsensusFlavor::Microdesc`] and server plus extra-info
        /// descriptors only in [`ConsensusFlavor::Plain`].  However, because
        /// we used a queue based design, we just leave the queue empty instead
        /// of wrapping this behind an enum variant for true mutual exclusivity.
        /// This makes coding much easier with less boilerplate and neglectable
        /// additional runtime cost.
        micro_queue: HashSet<db::Sha256>,
    },
}

/// A [`ConsensusFlavor`]-like wrapper for verified network statuses.
///
/// This is required because we need to obtain, at least partial, data from
/// each consensus, such as the signature (although not this type), the router
/// descriptors, validity, and other information.
///
/// At the current moment, [`tor_netdoc`] itself does not offer things such as
/// a common trait for retrieving the common fields, making this structure
/// necessary, or alternatively lots of macro magic similar to [`tor_netdoc`].
///
/// TODO DIRMIRROR: Either add a trait for [`tor_netdoc`] or figure out if the
/// fields we require are all of the same type in both, so we can only store
/// the fields we are interested in, though this is probably only possible once
/// we reached later stages of code.
///
/// And no, [`std::any::Any`] is not an alternative I am willing to do.
#[derive(Debug, Clone)]
enum FlavoredConsensus {
    /// For plain consensuses.
    Ns(cons::NetworkStatus),

    /// For microdescriptor consensuses.
    Md(md::NetworkStatus),
}

/// A [`ConsensusFlavor`]-like wrapper for unverified network statuses.
///
/// TODO DIRMIRROR: See the [`FlavoredConsensus`] trait comment.
#[derive(Debug, Clone)]
enum FlavoredConsensusSigned {
    /// For plain consensuses.
    Ns(cons::NetworkStatusUnverified),

    /// For microdescriptor consensus.
    Md(md::NetworkStatusUnverified),
}

impl StaticEngine {
    /// Determines the [`State`] only from the database and [`ConsensusBoundData`].
    ///
    /// This method is fully idempotent, meaning it only depends upon the data
    /// found within the database and the [`ConsensusBoundData`]; there is no
    /// internal `state` variable or something contained within [`StaticEngine`].
    fn determine_state(
        &self,
        tx: &Transaction<'_>,
        data: &ConsensusBoundData,
        now: Timestamp,
    ) -> Result<State, DatabaseError> {
        // Determine the state primarily upon ConsensusBoundData combined with
        // a few database queries, as well as the current time of course.
        let state = match data {
            // ConsensusBoundData::None means that we currently have no
            // consensus in memory.  This may be the case because we just
            // started up or because we just downloaded, validated, and inserted
            // a consensus into the database and resetted ConsensusBoundData to
            // None afterwards.
            ConsensusBoundData::None => {
                // Check whether there is a valid consensus in the database at all.
                //
                // Yes, it is kinda redundant querying a consensus here
                // and potentially again when loading the consensus, but SQLite
                // is very fast and having to maintain two different queries,
                // one for checking and one for selecting, is prone to get
                // out-of-sync.
                match ConsensusMeta::query_recent(tx, self.flavor, &self.tolerance, now)? {
                    // Some consensus means we can load it.
                    Some(_) => State::LoadConsensus,

                    // None means we must download it.
                    None => State::FetchConsensus,
                }
            }

            // ConsensusBoundData::Unverified means that we recently downloaded
            // a consensus through State::FetchConsensus.  It is not fully
            // validated yet and we may not even be able due to missing
            // authority certificates.
            ConsensusBoundData::Unverified { consensus, .. } => {
                // Check whether there any missing authority certificates that
                // have signed the consensus.
                let missing_certs = !AuthCertMeta::query_recent(
                    tx,
                    &consensus.signatories(),
                    &self.tolerance,
                    now,
                )?
                .1
                .is_empty();

                if missing_certs {
                    // Missing authority certificates means we must download
                    // them.
                    State::AuthCerts
                } else {
                    // If we have all authority certificates, we can validate
                    // and store it inside the database.
                    State::StoreConsensus
                }
            }

            // ConsensusBoundData::Verified means that we have successfully
            // loaded a recent valid consensus from the database using
            // State::LoadConsensus.  Depending on this, we download the missing
            // network documents (descriptors) from a directory authority, if
            // any.
            ConsensusBoundData::Verified {
                lifetime,
                server_queue: servers,
                extra_queue: extras,
                micro_queue: micros,
                ..
            } => {
                if *lifetime <= now {
                    // The lifetime has been surpassed, download a new
                    // consensus.  It is very important TO NOT transition to
                    // State::LoadConsensus here, because the current consensus
                    // may still be valid but not fresh anymore, in which case
                    // State::LoadConsensus will continue to obtain it from the
                    // database until valid-after has been surpassed, which is
                    // most definitely not what we want.
                    State::FetchConsensus
                } else if servers.is_empty() && extras.is_empty() && micros.is_empty() {
                    // All queues are empty, meaning we are done, until lifetime
                    // ends.
                    State::Hibernate
                } else {
                    // The lifetime has not been surpassed and we have stuff
                    // to download, so we need to obtain the descriptors.
                    State::Descriptors
                }
            }
        };
        Ok(state)
    }

    /// Executes a single state iteration in the finite state machine.
    ///
    /// The return value is of type [`Result<(), OperationError>`].
    /// The success type is not of much interest for calling applications.
    /// However, the error case itself should be passed towards
    /// [`crate::err::IsFatal::is_fatal()`] in order to either abort the
    /// application or retry with an appropriate timeout.
    ///
    // TODO: Use tracing instrumentation here.
    // TODO DIRMIRROR: Document the state transition check which we have to do
    // because of database invariances no longer holding true.
    async fn execute<R: Rng>(
        &self,
        pool: &Pool<SqliteConnectionManager>,
        data: &mut ConsensusBoundData,
        endpoint: &[SocketAddr],
        now: Timestamp,
        rng: &mut R,
    ) -> Result<(), OperationError> {
        // TODO: Should we return DatabaseError or something like
        // StateDeterminationError?  Either way, both cases should be seriously
        // fatal.
        let state = db::read_tx(pool, |tx| self.determine_state(tx, data, now))??;
        debug!("state is {state}");

        match state {
            State::LoadConsensus => self.load_consensus(pool, data, now, rng),
            State::FetchConsensus => Ok(self.fetch_consensus(data, endpoint).await?),
            State::AuthCerts => self.auth_certs(pool, data, endpoint, now).await,
            State::StoreConsensus => todo!(),
            State::Descriptors => todo!(),
            State::Hibernate => self.hibernate(data, now).await,
        }
    }

    /// Executes [`State::LoadConsensus`].
    ///
    /// This method does the following:
    /// * Load the most recent valid consensus from the database.
    /// * Compute the lifetime for it.
    /// * Compute the missing descriptors for it.
    fn load_consensus<R: Rng>(
        &self,
        pool: &Pool<SqliteConnectionManager>,
        data: &mut ConsensusBoundData,
        now: Timestamp,
        rng: &mut R,
    ) -> Result<(), OperationError> {
        // Load the most recent valid consensus from the database.
        //
        // If there is no consensus, we should have not entered the state, which
        // means that the database must have been externally verified.
        // In this case, it is probably better to return a bug, as external
        // applications arbitrarily modifying the database while we are running
        // leaves too much room for wrong/weird behavior.
        let (server_queue, extra_queue, micro_queue, lifetime, consensus) =
            db::read_tx(pool, |tx| {
                let meta = ConsensusMeta::query_recent(tx, self.flavor, &self.tolerance, now)?
                    .ok_or(internal!("database externally modified?"))?;
                let server_queue = meta.missing_servers(tx)?;
                let extra_queue = meta.missing_extras(tx)?;
                let micro_queue = meta.missing_micros(tx)?;
                let lifetime = meta.lifetime(rng);
                let consensus = meta.data(tx)?;
                Ok::<_, DatabaseError>((
                    server_queue,
                    extra_queue,
                    micro_queue,
                    lifetime,
                    consensus,
                ))
            })??;

        // Parse the most recent valid consensus from the database.
        //
        // TODO DIRMIRROR:
        // Because only valid documents may exist in the database, it should
        // succeed.  However, there is this weird edge-case where we may have
        // inserted a document with a field we do not understand because of
        // using an old version.  After upgrading our version we may now
        // understand the field and realize it is wrong, leading to a violation
        // of this constraint.  Handling this is not very easy; I suppose adding
        // an additional column to the meta table storing the last used crate
        // version is a sensible idea, with upgrades and downgrades leading to
        // a parsing of all network documents within the database, throwing the
        // ones out we do not understand (anymore).
        let consensus = match self.flavor {
            ConsensusFlavor::Plain => FlavoredConsensus::Ns(
                parse2::parse_netdoc(&ParseInput::new(&consensus, ""))
                    .map_err(into_internal!("invalid netdoc in database?"))?,
            ),
            ConsensusFlavor::Microdesc => FlavoredConsensus::Md(
                parse2::parse_netdoc(&ParseInput::new(&consensus, ""))
                    .map_err(into_internal!("invalid netdoc in database?"))?,
            ),
        };

        *data = ConsensusBoundData::Verified {
            consensus,
            lifetime,
            server_queue,
            extra_queue,
            micro_queue,
        };
        Ok(())
    }

    /// Fetches a consensus from an upstream authority.
    // TODO DIRMIRROR: Add logging.
    async fn fetch_consensus(
        &self,
        data: &mut ConsensusBoundData,
        endpoint: &[SocketAddr],
    ) -> Result<(), AuthorityRequestError> {
        // Obtain the consensus.
        let mut consensus: VecDeque<_> = match self.flavor {
            ConsensusFlavor::Plain => self
                .send_request(endpoint, ConsensusRequest::new(self.flavor))
                .await
                .map(|(raw, doc)| {
                    doc.into_iter()
                        .map(|(doc, start, end)| {
                            (raw[start..end].to_owned(), FlavoredConsensusSigned::Ns(doc))
                        })
                        .collect()
                }),
            ConsensusFlavor::Microdesc => self
                .send_request(endpoint, ConsensusRequest::new(self.flavor))
                .await
                .map(|(raw, doc)| {
                    doc.into_iter()
                        .map(|(doc, start, end)| {
                            (raw[start..end].to_owned(), FlavoredConsensusSigned::Md(doc))
                        })
                        .collect()
                }),
        }?;

        // Check for the correct number of results.
        if consensus.len() != 1 {
            return Err(AuthorityRequestError::Response(
                "invalid number of consensus?",
            ));
        }

        // expect is fine because we checked the length for one above.
        let (raw, consensus) = consensus.pop_front().expect("pop_front");

        // And store it.
        *data = ConsensusBoundData::Unverified { consensus, raw };

        Ok(())
    }

    /// Fetches, validates, and stores authority certificates.
    //
    // TODO DIRMIRROR: Right now, there is a torspec DoS issue.
    // An attacker may add lots of garbage signatures and we will fetch them
    // Even checking the ID PK against v3idents is not useful because an
    // attacker may still use the same ID PK dozens of times with various
    // SK PKs.  A good fix would include checking that no ID PK is duplicate
    // AND to ignore all ID PKs we do not recognize.  Also, it would probably
    // be best to move the v3idents structure to a HashMap based implementation,
    // as well as the signatories result.
    async fn auth_certs(
        &self,
        pool: &Pool<SqliteConnectionManager>,
        data: &mut ConsensusBoundData,
        endpoint: &[SocketAddr],
        now: Timestamp,
    ) -> Result<(), OperationError> {
        // Obtain the signatories of the current unverified consensus.
        let signatories = match data {
            ConsensusBoundData::Unverified { consensus, .. } => consensus.signatories(),
            _ => return Err(OperationError::Bug(internal!("data is not unverified"))),
        };

        // Obtain the missing certificate identifiers.
        let (_, missing) = db::read_tx(pool, |tx| {
            AuthCertMeta::query_recent(tx, &signatories, &self.tolerance, now)
        })??;
        if missing.is_empty() {
            // Although not technically fatal, retrying when the database was
            // externally modified does not make much sense.
            return Err(OperationError::Bug(internal!(
                "database externally modified?"
            )));
        }

        // Compose the request.
        let mut requ = AuthCertRequest::new();
        for kp in missing.iter().copied() {
            requ.push(kp);
        }

        // Fire it off.
        let (resp, certs) = self
            .send_request::<_, AuthCertUnverified>(endpoint, requ)
            .await?;

        // Verify each certificate.
        for (unverified, start, end) in certs {
            let unverified_body = unverified.inspect_unverified().0;
            let kp = AuthCertKeyIds {
                id_fingerprint: unverified_body.dir_identity_key.to_rsa_identity(),
                sk_fingerprint: unverified_body.dir_signing_key.to_rsa_identity(),
            };

            // Skip certficates we did not asked for.
            //
            // Not much of an issue because certificate verification will
            // usually fail anyways, except for this weird edge-case where we
            // actually have that id fingerprint in the v3idents.
            if !missing.contains(&kp) {
                debug!("authority returned certificate we did not asked for: {kp:?}");
                continue;
            }

            let verified = unverified.verify_self_signed(
                self.authorities.v3idents(),
                self.tolerance.pre_valid_tolerance(),
                self.tolerance.post_valid_tolerance(),
                now.into(),
            );
            let verified = match verified {
                Ok(v) => v,
                Err(e) => {
                    // TODO DIRMIRROR: Log the actual cert.
                    warn!("received invalid auth cert: {e}",);
                    continue;
                }
            };

            // We commit each certificate in its own transaction in order to
            // not fail with zero progress.  Might be a bit more expensive but
            // I do not think it matters a lot.
            db::rw_tx(pool, |tx| {
                AuthCertMeta::insert(tx, ContentEncoding::iter(), &verified, &resp[start..end])
            })??;
        }

        Ok(())
    }

    /// Hibernates for the remaining lifetime of the consensus.
    async fn hibernate(
        &self,
        data: &mut ConsensusBoundData,
        now: Timestamp,
    ) -> Result<(), OperationError> {
        match data {
            ConsensusBoundData::None | ConsensusBoundData::Unverified { .. } => {
                // This should not happen, we only enter hibernation in a state
                // that already has a verified consensus.
                return Err(internal!("hibernating without a verified consensus?").into());
            }
            ConsensusBoundData::Verified { lifetime, .. } => {
                let timeout = *lifetime - now;
                debug!("hibernating for {}s", timeout.as_secs());
                tokio::time::sleep(timeout).await;
            }
        }

        Ok(())
    }

    /// Convenience wrapper around [`tor_dirclient::send_request()`].
    ///
    /// It opens a TCP connection, performs the request, and parses the result.
    ///
    /// Returns the raw response alongside the output of
    /// [`parse2::parse_netdoc_multiple_with_offsets()`].
    ///
    /// The output is required because we need the raw document alongside the
    /// offsets to have the actual data we will insert into the database later
    /// on.
    async fn send_request<R: Requestable, T: NetdocParseable>(
        &self,
        endpoint: &[SocketAddr],
        requ: R,
    ) -> Result<(String, Vec<(T, usize, usize)>), AuthorityRequestError> {
        // The check is required to not let Tokio panic.
        if endpoint.is_empty() {
            return Err(AuthorityRequestError::Bug(internal!("empty endpoint?")));
        }

        // Open the TCP connection.
        let mut stream = TcpStream::connect(endpoint)
            .await
            .map_err(AuthorityRequestError::TcpConnect)?
            .compat();

        // Perform the request and map the result nicely.
        let resp = tor_dirclient::send_request(&self.rt, &requ, &mut stream, None)
            .await
            .map(|resp| resp.output_string().map(|resp| resp.to_owned()));

        // We can immediately drop the connection now, no need to occupy even
        // more resources from the authority.
        drop(stream);

        // Returning all request failed errors is okay; they all imply that
        // retrying from a different authority is fine.
        // TODO MSRV: If possible, use Result::flatten once MSRV 1.89.
        let resp = match resp {
            Ok(Ok(r)) => Ok(r),
            Ok(Err(e)) => Err(e),
            Err(tor_dirclient::Error::RequestFailed(e)) => Err(e),
            Err(e) => {
                return Err(AuthorityRequestError::Bug(internal!(
                    "unhandled dirclient error: {e}"
                )))
            }
        }?;

        // Parse the response.
        let parsed = parse2::parse_netdoc_multiple_with_offsets(&ParseInput::new(&resp, ""))?;

        Ok((resp, parsed))
    }
}

impl FlavoredConsensusSigned {
    /// Wrapper to obtain the signatories of a flavored consensus.
    fn signatories(&self) -> Vec<AuthCertKeyIds> {
        let sigs = match &self {
            Self::Ns(ns) => &ns.signatures.directory_signature,
            Self::Md(md) => &md.signatures.directory_signature,
        };
        sigs.iter()
            .filter_map(|sig| match sig {
                NdiDirectorySignature::Known {
                    h_kp_auth_id_rsa,
                    h_kp_auth_sign_rsa,
                    ..
                } => Some(AuthCertKeyIds {
                    id_fingerprint: *h_kp_auth_id_rsa,
                    sk_fingerprint: *h_kp_auth_sign_rsa,
                }),
                // TODO DIRMIRROR: This is inappropriate, but because we are
                // using poc, we have to refactor this either way.
                _ => None,
            })
            .collect()
    }
}

/// Proof-of-concept main execution function for this module
///
/// Right now, this is a proof-of-concept that just panics in the case of a
/// fatal error, but does proper retry handling for non-fatal errors.
// TODO DIRMIRROR: Make this not a poc.
// TODO DIRMIRROR: Add logging.
pub(super) async fn serve<R: Rng, F: Fn() -> Timestamp>(
    pool: &Pool<SqliteConnectionManager>,
    flavor: ConsensusFlavor,
    authorities: AuthorityContacts,
    tolerance: DirTolerance,
    rng: &mut R,
    now_fn: F,
) {
    let mut data = ConsensusBoundData::None;
    let engine = StaticEngine {
        flavor,
        authorities,
        tolerance,
        rt: PreferredRuntime::current().expect("unable to get runtime"),
    };

    // Shuffle the list of download endpoints.
    let mut downloads = engine.authorities.downloads().clone();
    downloads.shuffle(rng);
    // Keeps track of the authority we currently use, i.e. preferred authority.
    let mut current = 0;

    let mut retry = RetryDelay::default();
    loop {
        let endpoint = downloads.get(current).expect("attempted all authorities");

        // Perform the FSM execution.
        let res = engine
            .execute(pool, &mut data, endpoint, now_fn(), rng)
            .await;

        match res {
            Ok(()) => {
                retry.reset();

                // Swap the currently used authority with the front and reset
                // current to zero.
                //
                // With this design, we will loose track on which authorities
                // were successful and which were not on every successful
                // return.  At one point, we have to do this.  Probably after
                // every consensus, but not after every Ok.  However, for this
                // we would need a way to learn when we got a new consensus.
                // It would probably make most sense to modify the return type
                // of execute() to return something like the next state plus
                // previous state or maybe an even simpler bool that returns
                // true when the consensus got replaced.
                downloads.swap(0, current);
            }
            Err(e) => {
                // Check whether the error is fatal.
                if e.is_fatal() {
                    panic!("fatal error: {e}");
                }

                // Non-fatal error means we should wait and try again.
                current += 1;
                let delay = retry.next_delay(rng);
                tokio::time::sleep(delay).await;
            }
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use std::time::{Duration, SystemTime};

    use rusqlite::named_params;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tor_basic_utils::test_rng::testing_rng;
    use tor_netdoc::parse2::NetdocUnverified;

    use crate::database::sql;

    use super::*;

    fn create_dummy_db() -> Pool<SqliteConnectionManager> {
        let pool = db::open("").unwrap();

        let mut conn = pool.get().unwrap();
        let tx = conn.transaction().unwrap();

        let cons_docid = db::store_insert(
            &tx,
            include_bytes!("../../testdata/consensus-ns"),
            std::iter::empty(),
        )
        .unwrap();
        let ns1_docid = db::store_insert(
            &tx,
            include_bytes!("../../testdata/descriptor1-ns"),
            std::iter::empty(),
        )
        .unwrap();
        let extra1_docid = db::store_insert(
            &tx,
            include_bytes!("../../testdata/descriptor1-extra-info"),
            std::iter::empty(),
        )
        .unwrap();

        tx.execute(
            sql!(
                "
                INSERT INTO router_extra_info (docid, unsigned_sha1, kp_relay_id_rsa_sha1)
                VALUES
                (:docid, :sha1, :fingerprint)
                "
            ),
            named_params! {
                ":docid": extra1_docid,
                ":sha1": db::Sha1::digest(include_bytes!("../../testdata/descriptor1-extra-info-unsigned")),
                ":fingerprint": "000004ACBB9D29BCBA17256BB35928DDBFC8ABA9"
            },
        )
        .unwrap();
        tx.execute(
            sql!(
                "
                INSERT INTO router_descriptor
                (docid, unsigned_sha1, unsigned_sha2, kp_relay_id_rsa_sha1, flavor, extra_unsigned_sha1)
                VALUES
                (:docid, :sha1, :sha2, :fingerprint, 'ns', :extra)
                "
            ),
            named_params! {
                ":docid": ns1_docid,
                ":sha1": db::Sha1::digest(include_bytes!("../../testdata/descriptor1-ns-unsigned")),
                ":sha2": db::Sha256::digest(include_bytes!("../../testdata/descriptor1-ns-unsigned")),
                ":fingerprint": "000004ACBB9D29BCBA17256BB35928DDBFC8ABA9",
                ":extra": db::Sha1::digest(include_bytes!("../../testdata/descriptor1-extra-info-unsigned")),
            },
        )
        .unwrap();

        tx.execute(
            sql!(
                "
                INSERT INTO consensus
                (docid, unsigned_sha3_256, flavor, valid_after, fresh_until, valid_until)
                VALUES
                (:docid, :sha3, 'ns', :valid_after, :fresh_until, :valid_until)
                "
            ),
            named_params! {
                ":docid": cons_docid,
                ":sha3": "0000000000000000000000000000000000000000000000000000000000000000",
                ":valid_after": 1769698800,
                ":fresh_until": 1769702400,
                ":valid_until": 1769709600,
            },
        )
        .unwrap();

        tx.execute(
            sql!(
                "
                INSERT INTO consensus_router_descriptor_member
                (consensus_docid, unsigned_sha1, unsigned_sha2)
                VALUES
                (:cons_docid, :ns1_sha1, :ns1_sha2),
                (:cons_docid, :ns2_sha1, :ns2_sha2)
                "
            ),
            named_params! {
                ":cons_docid": cons_docid,
                ":ns1_sha1": db::Sha1::digest(include_bytes!("../../testdata/descriptor1-ns-unsigned")),
                ":ns1_sha2": db::Sha256::digest(include_bytes!("../../testdata/descriptor1-ns-unsigned")),
                ":ns2_sha1": db::Sha1::digest(include_bytes!("../../testdata/descriptor2-ns-unsigned")),
                ":ns2_sha2": db::Sha256::digest(include_bytes!("../../testdata/descriptor2-ns-unsigned")),
            },
        )
        .unwrap();

        tx.commit().unwrap();

        pool
    }

    #[tokio::test]
    async fn state_load_consensus() {
        let pool = create_dummy_db();
        let mut data = ConsensusBoundData::None;
        let engine = StaticEngine {
            flavor: ConsensusFlavor::Plain,
            authorities: AuthorityContacts::default(),
            tolerance: DirTolerance::default(),
            rt: PreferredRuntime::current().unwrap(),
        };

        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(1769700600); // 2026-01-29 15:30:00
        let time: Timestamp = time.into();
        let fresh_until = time + Duration::from_secs(60 * 30);
        let fresh_until_half = fresh_until + Duration::from_secs(60 * 60);

        engine
            .load_consensus(&pool, &mut data, time, &mut testing_rng())
            .unwrap();

        // El-cheapo assert_eq due to lack of PartialEq for tor-netdoc poc.
        match data {
            ConsensusBoundData::Verified {
                consensus,
                lifetime,
                server_queue,
                extra_queue,
                micro_queue,
            } => {
                match consensus {
                    FlavoredConsensus::Ns(_) => {}
                    _ => panic!("consensus not ns"),
                }
                assert_eq!(
                    server_queue,
                    HashSet::from([db::Sha1::digest(include_bytes!(
                        "../../testdata/descriptor2-ns-unsigned"
                    ))])
                );
                assert!(lifetime >= fresh_until);
                assert!(lifetime <= fresh_until_half);
                assert!(extra_queue.is_empty());
                assert!(micro_queue.is_empty());
            }
            _ => panic!("data is not verified"),
        }
    }

    #[tokio::test]
    async fn state_fetch_consensus() {
        let pool = create_dummy_db();
        let mut data = ConsensusBoundData::None;
        let engine = StaticEngine {
            flavor: ConsensusFlavor::Plain,
            authorities: AuthorityContacts::default(),
            tolerance: DirTolerance::default(),
            rt: PreferredRuntime::current().unwrap(),
        };

        let state = db::read_tx(&pool, |tx| {
            engine.determine_state(tx, &data, SystemTime::UNIX_EPOCH.into())
        })
        .unwrap()
        .unwrap();
        assert_eq!(state, State::FetchConsensus);

        let server = TcpListener::bind("[::]:0").await.unwrap();
        let saddr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = server.accept().await.unwrap();
            let mut buf = vec![0; 1024];
            let _ = stream.read(&mut buf).await.unwrap();

            let consensus = include_str!("../../testdata/consensus-ns");
            let resp = format!(
                "HTTP/1.0 200 OK\r\nContent-Encoding: identity\r\nContent-Length: {}\r\n\r\n{consensus}",
                consensus.len()
            );
            stream.write_all(resp.as_bytes()).await.unwrap();
        });

        engine.fetch_consensus(&mut data, &[saddr]).await.unwrap();
        match data {
            ConsensusBoundData::Unverified { consensus, raw } => match consensus {
                FlavoredConsensusSigned::Ns(ns) => {
                    // El-cheapo verification, this is not a parser unit test.
                    assert_eq!(ns.unwrap_unverified().0.r.len(), 2);
                    assert_eq!(raw, include_str!("../../testdata/consensus-ns"));
                }
                _ => panic!("data is not unverified ns consensus"),
            },
            _ => panic!("data is not unverified"),
        }
    }

    #[tokio::test]
    async fn state_auth_certs() {
        let pool = create_dummy_db();
        let mut data = ConsensusBoundData::Unverified {
            consensus: FlavoredConsensusSigned::Ns(
                parse2::parse_netdoc(&ParseInput::new(
                    include_str!("../../testdata/consensus-ns"),
                    "",
                ))
                .unwrap(),
            ),
            raw: include_str!("../../testdata/consensus-ns").to_owned(),
        };
        let engine = StaticEngine {
            flavor: ConsensusFlavor::Plain,
            authorities: AuthorityContacts::default(),
            tolerance: DirTolerance::default(),
            rt: PreferredRuntime::current().unwrap(),
        };

        assert_eq!(
            db::read_tx(&pool, |tx| engine.determine_state(
                tx,
                &data,
                SystemTime::UNIX_EPOCH.into()
            ))
            .unwrap()
            .unwrap(),
            State::AuthCerts
        );

        let server = TcpListener::bind("[::]:0").await.unwrap();
        let saddr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0; 1024];
            let (mut stream, _) = server.accept().await.unwrap();
            let _ = stream.read(&mut buf).await.unwrap();

            let authcerts = include_str!("../../testdata/authcert-all");

            stream.write_all(format!(
                "HTTP/1.0 200 OK\r\nContent-Encoding: identity\r\nContent-Length: {}\r\n\r\n{authcerts}",
                authcerts.len()
            ).as_bytes()).await.unwrap();
        });

        // Fetch all authcerts.
        engine
            .auth_certs(
                &pool,
                &mut data,
                &[saddr],
                (SystemTime::UNIX_EPOCH + Duration::from_secs(1770639454)).into(), // Mon Feb  9 12:17:34 UTC 2026
            )
            .await
            .unwrap();

        // Check whether we are done with all authcerts.
        assert_eq!(
            db::read_tx(&pool, |tx| engine.determine_state(
                tx,
                &data,
                (SystemTime::UNIX_EPOCH + Duration::from_secs(1770639454)).into(), // Mon Feb  9 12:17:34 UTC 2026
            ))
            .unwrap()
            .unwrap(),
            State::StoreConsensus
        );
        let recent_authcerts = db::read_tx(&pool, |tx| {
            AuthCertMeta::query_recent(
                tx,
                &FlavoredConsensusSigned::Ns(
                    parse2::parse_netdoc(&ParseInput::new(
                        include_str!("../../testdata/consensus-ns"),
                        "",
                    ))
                    .unwrap(),
                )
                .signatories(),
                &DirTolerance::default(),
                (SystemTime::UNIX_EPOCH + Duration::from_secs(1770639454)).into(), // Mon Feb  9 12:17:34 UTC 2026
            )
        })
        .unwrap()
        .unwrap();
        // TODO DIRMIRROR: Compare more than just length.
        assert_eq!(
            recent_authcerts.0.len(),
            engine.authorities.v3idents().len()
        );
        assert!(recent_authcerts.1.is_empty());
    }
}
