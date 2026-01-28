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
use rusqlite::{named_params, OptionalExtension, Transaction};
use strum::IntoEnumIterator;
use tor_dirclient::request::AuthCertRequest;
use tor_dircommon::{authority::AuthorityContacts, config::DirTolerance};
use tor_error::{internal, into_internal};
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_netdoc::{
    doc::{
        authcert::{AuthCert, AuthCertKeyIds, AuthCertUnverified},
        netstatus::ConsensusFlavor,
    },
    parse2::{
        self,
        poc::netstatus::{cons, md, NdiDirectorySignature},
        NetdocUnverified, ParseInput,
    },
};
use tracing::{debug, warn};

use crate::{
    database::{self, sql, Consensus, ContentEncoding, Timestamp},
    err::{DatabaseError, NetdocRequestError, OperationError},
    mirror::operation::download::DownloadManager,
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
                match Consensus::query_recent(tx, self.flavor, &self.tolerance, now)? {
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
                let missing_certs = !get_recent_authority_certificates(
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
        let state = database::read_tx(pool, |tx| self.determine_state(tx, data, now))??;
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
        let (_meta, consensus) = database::read_tx(pool, |tx| {
            let meta = Consensus::query_recent(tx, self.flavor, &self.tolerance, now)?
                .ok_or(internal!("database externally modified?"))?;
            let consensus = meta.raw(tx)?;
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

/// Obtain the most recently published and valid certificate for each authority.
///
/// Returns the found [`AuthCert`] items as well as the missing [`AuthCertKeyIds`]
/// not present within the database.
///
/// # Performance
///
/// This function has a performance between `O(n * log n)` and `O(n^2)` because
/// it performs `signatories.len()` database queries, which each database query
/// potentially taking something between `O(log n)` to `O(n)` to execute.
/// However, given that this respective value is oftentimes fairly small, it
/// should not be much of a big concern.  However, interfacing code shall ensure
/// that it is not **too big** either, because a MITM may add lots of garbage
/// signatures, just to make this larger, as it is usually called within the
/// context of obtaining the certificates for a given consensus.
///
/// Because the database has the invariance that all entires inside are
/// valid, we do not bother about validating the signatures there again, hence
/// why the return type is not [`AuthCertUnverified`].
fn get_recent_authority_certificates(
    tx: &Transaction,
    signatories: &[AuthCertKeyIds],
    tolerance: &DirTolerance,
    now: Timestamp,
) -> Result<(Vec<AuthCert>, Vec<AuthCertKeyIds>), DatabaseError> {
    // For every key pair in `signatories`, get the most recent valid cert.
    //
    // This query selects the most recent timestamp valid certificate from the
    // database for a single given key pair.  It means that this query has to be
    // executed as many times as there are entires in `signatories`.
    //
    // Unfortunately, there is no neater way to do this, because the alternative
    // would involve using a nested set which SQLite does not support, even with
    // the carray extension.  An alternative might be to precompute that string
    // and then insert it here using `format!` but that feels hacky, error- and
    // injection-prone.
    //
    // Parameters:
    // :id_rsa: The RSA identity key fingerprint in uppercase hexadecimal.
    // :sk_rsa: The RSA signing key fingerprint in uppercase hexadecimal.
    // :now: The current system timestamp.
    // :pre_tolerance: The tolerance for not-yet-valid certificates.
    // :post_tolerance: The tolerance for expired certificates.
    let mut stmt = tx.prepare_cached(sql!(
        "
        SELECT s.content
        FROM
          authority_key_certificate AS a
          INNER JOIN store AS s ON s.docid = a.docid
        WHERE
          (:id_rsa, :sk_rsa) = (a.kp_auth_id_rsa_sha1, a.kp_auth_sign_rsa_sha1)
          AND :now >= a.dir_key_published - :pre_tolerance
          AND :now <= a.dir_key_expires + :post_tolerance
        ORDER BY dir_key_published DESC
        LIMIT 1
        "
    ))?;

    // Keep track of the found (and parsed) certificates and the missing ones.
    let mut found = Vec::new();
    let mut missing = Vec::new();

    // Iterate over every key pair and query it, adding it to found if it exists
    // and was parsed successfully or to missing if it does not exist within the
    // database.
    for kp in signatories {
        // Query the certificate from the database.
        let raw_cert = stmt
            .query_one(
                named_params! {
                    ":id_rsa": kp.id_fingerprint.as_hex_upper(),
                    ":sk_rsa": kp.sk_fingerprint.as_hex_upper(),
                    ":now": now,
                    ":pre_tolerance": tolerance.pre_valid_tolerance().as_secs().try_into().unwrap_or(i64::MAX),
                    ":post_tolerance": tolerance.post_valid_tolerance().as_secs().try_into().unwrap_or(i64::MAX),
                },
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;

        // Unwrap the Some (or None).
        let raw_cert = match raw_cert {
            Some(c) => {
                String::from_utf8(c).map_err(|e| internal!("utf-8 constraint violation? {e}"))?
            }
            None => {
                missing.push(*kp);
                continue;
            }
        };

        // This match statement is a bit tricky, but important.
        //
        // In the case that some newer version of arti may not be able to parse
        // an older certificate, such as due to missing a field or an older
        // version having inserted it because not knowing about it, we must not
        // fail.  Instead, we mark the certificate as missing, because it is
        // not usable for us.
        let cert = parse2::parse_netdoc::<AuthCertUnverified>(&ParseInput::new(&raw_cert, ""));
        match cert {
            Ok(cert) => {
                // Mark the cert as found.
                // We assume all certificates in the database to be
                // cryptographically valid, hence why we use unwrap_unverified.
                found.push(cert.unwrap_unverified().0);
            }
            Err(e) => {
                warn!("invalid authcert found in database? {e}");
                missing.push(*kp);
                continue;
            }
        }
    }

    Ok((found, missing))
}

/// Downloads (missing) directory authority certificates from an authority.
///
/// The key pairs (identity and signing keys) are specified in `missing`.
/// This function will then use the [`DownloadManager`] to download
/// the missing certificates from a directory authority.
async fn download_authority_certificates<'a, 'b, R: Rng>(
    missing: &[AuthCertKeyIds],
    downloader: &DownloadManager<'a, 'b>,
    preferred: Option<&'a Vec<SocketAddr>>,
    rng: &mut R,
) -> Result<(&'a Vec<SocketAddr>, String), NetdocRequestError> {
    let mut requ = AuthCertRequest::new();
    missing.iter().for_each(|kp| requ.push(*kp));

    let (preferred, resp) = downloader
        .download(&requ, preferred, rng)
        .await
        .map_err(NetdocRequestError::Download)?;
    let resp = String::from_utf8(resp)?;

    Ok((preferred, resp))
}

/// Parses multiple raw directory authority certificates.
///
/// Returns the parsed [`AuthCertUnverified`] alongside their raw plain-text
/// representation.
fn parse_authority_certificates<'a>(
    certs: &'a str,
) -> Result<Vec<(AuthCertUnverified, &'a str)>, parse2::ParseError> {
    parse2::parse_netdoc_multiple_with_offsets::<AuthCertUnverified>(&ParseInput::new(certs, ""))?
        .into_iter()
        // Creating the slice is fine, parse2 guarantees it is in-bounds.
        .map(|(cert, start, end)| Ok((cert, &certs[start..end])))
        .collect()
}

/// Verifies multiple raw directory authority certificates.
///
/// Returns the verified [`AuthCertUnverified`] values as [`AuthCert`] values.
/// The [`str`] slice will remain unmodified, meaning that it will still include
/// the signature parts in plain-text.
/// This function is mostly used in conjunction with
/// [`parse_authority_certificates()`] in order to ensure its outputs were
/// correct.
fn verify_authority_certificates<'a>(
    certs: Vec<(AuthCertUnverified, &'a str)>,
    v3idents: &[RsaIdentity],
    tolerance: &DirTolerance,
    now: Timestamp,
) -> Result<Vec<(AuthCert, &'a str)>, parse2::VerifyFailed> {
    certs
        .into_iter()
        .map(|(cert, raw)| {
            cert.verify_self_signed(
                v3idents,
                tolerance.pre_valid_tolerance(),
                tolerance.post_valid_tolerance(),
                now.into(),
            )
            .map(|cert| (cert, raw))
        })
        .collect()
}

/// Inserts the verified certificates into the database.
///
/// This function is mostly used in conjunction with
/// [`verify_authority_certificates()`] in order to make the data persistent
/// to disk.
fn insert_authority_certificates(
    tx: &Transaction,
    certs: &[(AuthCert, &str)],
) -> Result<(), DatabaseError> {
    // Inserts an authority certificate into the meta table.
    //
    // Parameters:
    // :docid - The docid as found in the store table.
    // :id_rsa - The identity key fingerprint.
    // :sign_rsa - The signing key fingerprint.
    // :published - The published timestamp.
    // :expires - The expires timestamp.
    let mut stmt = tx.prepare_cached(sql!(
        "
        INSERT INTO authority_key_certificate
          (docid, kp_auth_id_rsa_sha1, kp_auth_sign_rsa_sha1, dir_key_published, dir_key_expires)
        VALUES
          (:docid, :id_rsa, :sign_rsa, :published, :expires)
        "
    ))?;

    // Compress and insert all certificates into the store within the context of
    // our (still pending) transaction.  Keep track of the uncompressed docid
    // too.
    let certs = certs
        .iter()
        .map(|(cert, raw)| {
            // For now, we encode the authcerts in all encodings.
            // TODO: This is probably not a good idea, but it will also not be
            // the end of the world if we change this later -- at worst, clients
            // will simply get it in a different encoding they prefer less, but
            // that should not be super critical.
            let docid = database::store_insert(tx, raw.as_bytes(), ContentEncoding::iter())?;
            Ok::<_, DatabaseError>((docid, cert))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Insert every certificate, after it has been inserted into the store, into
    // the authority certificates meta table.
    for (docid, cert) in certs {
        stmt.execute(named_params! {
            ":docid": docid,
            ":id_rsa": cert.fingerprint.as_hex_upper(),
            ":sign_rsa": cert.dir_signing_key.to_rsa_identity().as_hex_upper(),
            ":published": Timestamp::from(cert.dir_key_published.0),
            ":expires": Timestamp::from(cert.dir_key_expires.0),
        })?;
    }

    Ok(())
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

    use crate::database::{self, DocumentId};

    use super::*;
    use lazy_static::lazy_static;
    use rusqlite::params;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tor_basic_utils::test_rng::testing_rng;
    use tor_dircommon::authority::AuthorityContactsBuilder;
    use tor_llcrypto::pk::rsa::RsaIdentity;
    use tor_rtcompat::PreferredRuntime;

    const CERT_CONTENT: &[u8] = include_bytes!("../../testdata/authcert-longclaw");

    lazy_static! {
        static ref CERT_DOCID: DocumentId = DocumentId::digest(CERT_CONTENT);
    }

    fn create_dummy_db() -> Pool<SqliteConnectionManager> {
        let pool = database::open("").unwrap();
        database::rw_tx(&pool, |tx| {
            tx.execute(
                sql!("INSERT INTO store (docid, content) VALUES (?1, ?2)"),
                params![*CERT_DOCID, CERT_CONTENT],
            )
            .unwrap();


            tx.execute(sql!(
                "
                INSERT INTO authority_key_certificate
                  (docid, kp_auth_id_rsa_sha1, kp_auth_sign_rsa_sha1, dir_key_published, dir_key_expires)
                VALUES
                  (:docid, :id_rsa, :sk_rsa, :published, :expires)
                "
                ),
                named_params! {
                ":docid": *CERT_DOCID,
                ":id_rsa": "49015F787433103580E3B66A1707A00E60F2D15B",
                ":sk_rsa": "C5D153A6F0DA7CC22277D229DCBBF929D0589FE0",
                ":published": 1764543578,
                ":expires": 1772492378,
            }).unwrap();
        })
        .unwrap();

        pool
    }

    #[test]
    fn get_auth_cert() {
        let pool = create_dummy_db();

        // Empty.
        let (found, missing) = database::read_tx(&pool, |tx| {
            get_recent_authority_certificates(
                tx,
                &[],
                &DirTolerance::default(),
                (SystemTime::UNIX_EPOCH + Duration::from_secs(1765900013)).into(),
            )
        })
        .unwrap()
        .unwrap();
        assert!(found.is_empty());
        assert!(missing.is_empty());

        // Find one and two missing ones.
        let (found, missing) = database::read_tx(&pool, |tx| {
            get_recent_authority_certificates(
                tx,
                &[
                    // Found one.
                    AuthCertKeyIds {
                        id_fingerprint: RsaIdentity::from_hex(
                            "49015F787433103580E3B66A1707A00E60F2D15B",
                        )
                        .unwrap(),
                        sk_fingerprint: RsaIdentity::from_hex(
                            "C5D153A6F0DA7CC22277D229DCBBF929D0589FE0",
                        )
                        .unwrap(),
                    },
                    // Missing.
                    AuthCertKeyIds {
                        id_fingerprint: RsaIdentity::from_hex(
                            "0000000000000000000000000000000000000000",
                        )
                        .unwrap(),
                        sk_fingerprint: RsaIdentity::from_hex(
                            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                        )
                        .unwrap(),
                    },
                    // Missing.
                    AuthCertKeyIds {
                        id_fingerprint: RsaIdentity::from_hex(
                            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                        )
                        .unwrap(),
                        sk_fingerprint: RsaIdentity::from_hex(
                            "0000000000000000000000000000000000000000",
                        )
                        .unwrap(),
                    },
                ],
                &DirTolerance::default(),
                (SystemTime::UNIX_EPOCH + Duration::from_secs(1765900013)).into(),
            )
        })
        .unwrap()
        .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(missing.len(), 2);

        // Now make one invalid and see that it will get set to missing.
        pool.get()
            .unwrap()
            .execute(
                sql!(
                    "
                    UPDATE store
                    SET content = X'61'
                    WHERE docid = (SELECT docid FROM authority_key_certificate)
                    "
                ),
                params![],
            )
            .unwrap();
        let (found, missing) = database::read_tx(&pool, |tx| {
            get_recent_authority_certificates(
                tx,
                &[
                    // Found one.
                    AuthCertKeyIds {
                        id_fingerprint: RsaIdentity::from_hex(
                            "49015F787433103580E3B66A1707A00E60F2D15B",
                        )
                        .unwrap(),
                        sk_fingerprint: RsaIdentity::from_hex(
                            "C5D153A6F0DA7CC22277D229DCBBF929D0589FE0",
                        )
                        .unwrap(),
                    },
                ],
                &DirTolerance::default(),
                (SystemTime::UNIX_EPOCH + Duration::from_secs(1765900013)).into(),
            )
        })
        .unwrap()
        .unwrap();
        assert!(found.is_empty());
        assert_eq!(
            missing[0],
            AuthCertKeyIds {
                id_fingerprint: RsaIdentity::from_hex("49015F787433103580E3B66A1707A00E60F2D15B",)
                    .unwrap(),
                sk_fingerprint: RsaIdentity::from_hex("C5D153A6F0DA7CC22277D229DCBBF929D0589FE0",)
                    .unwrap(),
            }
        );
    }

    /// Tests the combination of the following functions:
    ///
    /// * [`download_authority_certificates()`]
    /// * [`verify_authority_certificates()`]
    /// * [`insert_authority_certificates()`]
    #[tokio::test]
    async fn missing_certificates() {
        // Don't use the dummy db because we will download.
        let pool = database::open("").unwrap();

        // Create server.
        let listener = TcpListener::bind("[::]:0").await.unwrap();
        let sa = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let raw_cert = include_str!("../../testdata/authcert-longclaw");
            let resp = format!(
                "HTTP/1.1 200 Ok\r\nContent-Length: {}\r\n\r\n{raw_cert}",
                raw_cert.len()
            )
            .as_bytes()
            .to_vec();

            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0; 1024];
            let _ = stream.read(&mut buf).await.unwrap();
            stream.write_all(&resp).await.unwrap();
            stream.flush().await.unwrap();
        });

        let mut authorities = AuthorityContactsBuilder::default();
        authorities.set_v3idents(vec![RsaIdentity::from_hex(
            "49015F787433103580E3B66A1707A00E60F2D15B",
        )
        .unwrap()]);
        authorities.set_uploads(vec![]);
        authorities.set_downloads(vec![vec![sa]]);
        let authorities = authorities.build().unwrap();

        // Download certificate.
        let rt = PreferredRuntime::current().unwrap();
        let downloader = DownloadManager::new(authorities.downloads(), &rt);
        let (preferred, certs_raw) = download_authority_certificates(
            &[AuthCertKeyIds {
                id_fingerprint: RsaIdentity::from_hex("49015F787433103580E3B66A1707A00E60F2D15B")
                    .unwrap(),
                sk_fingerprint: RsaIdentity::from_hex("C5D153A6F0DA7CC22277D229DCBBF929D0589FE0")
                    .unwrap(),
            }],
            &downloader,
            None,
            &mut testing_rng(),
        )
        .await
        .unwrap();
        assert_eq!(preferred, &authorities.downloads()[0]);
        assert_eq!(certs_raw, include_str!("../../testdata/authcert-longclaw"));

        // Parse certificate.
        let certs = parse_authority_certificates(&certs_raw).unwrap();
        assert_eq!(certs[0].1, certs_raw);

        // Verify certificate.
        let certs = verify_authority_certificates(
            certs,
            authorities.v3idents(),
            &DirTolerance::default(),
            (SystemTime::UNIX_EPOCH + Duration::from_secs(1765900013)).into(),
        )
        .unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(
            certs[0].0.fingerprint.0,
            RsaIdentity::from_hex("49015F787433103580E3B66A1707A00E60F2D15B").unwrap()
        );
        assert_eq!(
            certs[0].0.dir_signing_key.to_rsa_identity(),
            RsaIdentity::from_hex("C5D153A6F0DA7CC22277D229DCBBF929D0589FE0").unwrap()
        );

        // Insert the stuff into the database.
        database::rw_tx(&pool, |tx| insert_authority_certificates(tx, &certs))
            .unwrap()
            .unwrap();

        // Verify it is actually there.
        let (id_rsa, sign_rsa, published, expires, raw) = database::read_tx(&pool, |tx| {
            tx.query_one(
                sql!(
                    "
                    SELECT
                      a.kp_auth_id_rsa_sha1, a.kp_auth_sign_rsa_sha1, a.dir_key_published, a.dir_key_expires, s.content
                    FROM
                      authority_key_certificate AS a
                    INNER JOIN
                      store AS s ON a.docid = s.docid
                    "
                ),
                params![],
                |row| Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Timestamp>(2)?,
                    row.get::<_, Timestamp>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                )),
            )
        })
        .unwrap().unwrap();

        assert_eq!(id_rsa, certs[0].0.fingerprint.as_hex_upper());
        assert_eq!(
            sign_rsa,
            certs[0].0.dir_signing_key.to_rsa_identity().as_hex_upper()
        );
        assert_eq!(published, certs[0].0.dir_key_published.0.into());
        assert_eq!(expires, certs[0].0.dir_key_expires.0.into());
        assert_eq!(raw, include_bytes!("../../testdata/authcert-longclaw"));

        // Now (just to be sure) verify that compressed stuff also exists.
        let count = database::read_tx(&pool, |tx| {
            tx.query_one(
                sql!(
                    "
                    SELECT COUNT(*)
                    FROM compressed_document
                    "
                ),
                params![],
                |row| row.get::<_, i64>(0),
            )
        })
        .unwrap()
        .unwrap();
        assert_eq!(count, 4);
    }
}
