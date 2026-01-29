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

use std::{collections::VecDeque, net::SocketAddr};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rand::Rng;
use rusqlite::Transaction;
use tor_dircommon::{authority::AuthorityContacts, config::DirTolerance};
use tor_error::{internal, into_internal};
use tor_netdoc::{
    doc::{authcert::AuthCertKeyIds, netstatus::ConsensusFlavor},
    parse2::{
        self,
        poc::netstatus::{cons, md, NdiDirectorySignature},
        ParseInput,
    },
};
use tracing::debug;

use crate::{
    database::{self as db, AuthCertMeta, ConsensusMeta, Timestamp},
    err::{DatabaseError, OperationError},
};

mod download;

/// The various states for the [`StaticEngine`].
#[derive(Debug, Clone, Copy, strum::Display)]
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
        /// The unverified consensus we have.
        // TODO DIRMIRROR: Make this optional, see comment in
        // StaticEngine::execute.
        consensus: FlavoredConsensusSigned,

        /// The authority we have downloaded it from.
        preferred: Vec<SocketAddr>,
    },

    /// We have downloaded and verified a consensus.
    Verified {
        /// The verified consensus we have.
        consensus: FlavoredConsensus,

        /// The authority we prefer downloading from.
        preferred: Option<Vec<SocketAddr>>,

        /// When to stop dealing with this consensus and fetching a new one.
        lifetime: Timestamp,

        /// SHA-1 digests of the missing server descriptors in the consensus.
        server_queue: VecDeque<[u8; 20]>,

        /// SHA-1 digests of the missing extra-info descriptors in the server
        /// descriptors of the consensus.
        ///
        /// extra-info documents are only transitively related to a consensus
        /// through consensus -> server descriptors -> extra-info descriptors
        extra_queue: VecDeque<[u8; 20]>,

        /// SHA-1 digests of the missing micro descriptors in the consensus.
        ///
        /// This field is technically mutually exclusive to server_queue and
        /// extra_queue because micro descriptors are only found in
        /// [`ConsensusFlavor::Microdesc`] and server plus extra-info
        /// descriptors only in [`ConsensusFlavor::Plain`].  However, because
        /// we used a queue based design, we just leave the queue empty instead
        /// of wrapping this behind an enum variant for true mutual exclusivity.
        /// This makes coding much easier with less boilerplate and neglectable
        /// additional runtime cost.
        micro_queue: VecDeque<[u8; 32]>,
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
    /// [`OperationError::is_fatal()`] in order to either abort the application
    /// or retry with an appropriate timeout.
    ///
    // TODO: Use tracing instrumentation here.
    // TODO DIRMIRROR: Document the state transition check which we have to do
    // because of database invariances no longer holding true.
    async fn execute<R: Rng>(
        &self,
        pool: &Pool<SqliteConnectionManager>,
        data: &mut ConsensusBoundData,
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
            State::FetchConsensus => todo!(),
            State::AuthCerts => todo!(),
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
    /// * ...
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
        let (_meta, consensus) = db::read_tx(pool, |tx| {
            let meta = ConsensusMeta::query_recent(tx, self.flavor, &self.tolerance, now)?
                .ok_or(internal!("database externally modified?"))?;
            let consensus = meta.data(tx)?;
            Ok::<_, DatabaseError>((meta, consensus))
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
            preferred: None,
            lifetime: todo!(),
            server_queue: todo!(),
            extra_queue: todo!(),
            micro_queue: todo!(),
        };
    }

    // Hibernates for the remaining lifetime of the consensus.
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
