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

use std::{collections::VecDeque, marker::PhantomData, net::SocketAddr, time::Duration};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rand::Rng;
use rusqlite::Transaction;
use strum::IntoEnumIterator;
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tor_checkable::TimeBound;
use tor_dirclient::request::{AuthCertRequest, ConsensusRequest, Requestable};
use tor_dircommon::{authority::AuthorityContacts, config::DirTolerance};
use tor_error::internal;
use tor_netdoc::{
    doc::{
        authcert::{AuthCert, AuthCertKeyIds, AuthCertUnverified},
        netstatus::ConsensusVerifiabilityError,
    },
    parse2::{self, NetdocParseable, NetdocParseableUnverified, ParseInput},
};
use tor_rtcompat::PreferredRuntime;
use tracing::debug;

use crate::{
    database::{self as db, AuthCertMeta, ConsensusMeta, ContentEncoding, Timestamp},
    err::{AuthorityRequestError, DatabaseError, OperationError},
    types::FlavoredConsensusUnverified,
};

mod poc;

/// The duration to try verifying an unverified consensus.
///
/// This exists primarily to properly handle the
/// [`ConsensusVerifiabilityError::InsufficientTrustedSigners`] error.  Besides,
/// it also serves as an upper-limit for the time we can spend in the phase for
/// fetching authority certificates, which could otherwise run for a very long
/// time, as long as every request makes progress and finishes before a
/// connection timeout is reached.
///
/// Obviously, we cannot use the values inside the consensus, as they are
/// untrusted.
const UNVERIFIED_TTL: Duration = Duration::from_mins(10);

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
    /// * [`State::Descriptors`], if ttl is over.
    /// * [`State::Hibernate`], if ttl is over.
    ///
    /// Transitions into:
    /// * [`State::AuthCerts`], if we miss authority certificates.
    /// * [`State::StoreConsensus`], if all authority certificates exist in the
    ///   database.
    /// * [`State::Hibernate`], if we have insufficient trusted authorities.
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
    /// * [`State::FetchConsensus`], if ttl is over.
    /// * [`State::Descriptors`], if we still have missing descriptors left.
    /// * [`State::Hibernate`], if nothing is left.
    Descriptors,

    /// Hibernate because nothing is left.
    ///
    /// Transitions from:
    /// * [`State::FetchConsensus`], if we have insufficient trusted
    ///   authorities.
    /// * [`State::Descriptors`], if we have downloaded all descriptors.
    ///
    /// Transitions into:
    /// * [`State::FetchConsensus`], if the ttl is over.
    Hibernate,
}

/// The execution engine for the finite state machine.
///
/// The states themselves are explained in [`State`].
///
/// This data structure itself is static and contains no state, but merely
/// configuration primitives that stay constant throughout the runtime of the
/// program, such as the [`AuthorityContacts`], and the
/// [`DirTolerance`].  It can be kept throughout the entire runtime and only
/// consists for convenience in order to not give each state machine related
/// (then static) method a super long signature containing these fields.
///
/// Besides these dynamic fields, there is also a generic parameter specifying
/// the consensus flavor that is being used.
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
struct StaticEngine<T> {
    /// The authorities we are acknowledging.
    authorities: AuthorityContacts,

    /// The document tolerance we are accepting.
    tolerance: DirTolerance,

    /// The preferred runtime for compatibility with other arti crates.
    ///
    /// Generally obtained through [`PreferredRuntime::current()`].
    rt: PreferredRuntime,

    /// Utilizes the generic type parameter.
    _phantom: PhantomData<T>,
}

/// Additional state machine data concerning a single consensus.
///
/// This enum stores and keeps track of the consensus we are serving and in
/// which ✨state✨ it is currently in, such as whether it is verified or not,
/// or if we even have a state loaded in memory in the first place.
#[derive(Debug, Clone)]
enum ConsensusBoundData<T: FlavoredConsensusUnverified> {
    /// No state is loaded in memory at the moment.
    None,

    /// We have downloaded a consensus but it is not yet verified.
    Unverified {
        /// The unverified parsed consensus we have.
        // TODO DIRMIRROR: Make this optional, see comment in
        // StaticEngine::execute.
        consensus: T,

        /// The unparsed raw consensus we have.
        raw: String,

        /// When to stop dealing with this consensus and download again.
        ///
        /// Useful to have in order to not stuck forever in a verification
        /// loop, i.e. due to unavailable authentication certificates, etc.
        ttl: Timestamp,
    },

    /// We have downloaded and verified a consensus.
    Verified {
        /// The verified consensus we have.
        consensus: ConsensusMeta<T>,

        /// When to stop dealing with this consensus and fetching a new one.
        ttl: Timestamp,
    },
}

impl<T: FlavoredConsensusUnverified> StaticEngine<T> {
    /// Determines the [`State`] only from the database and [`ConsensusBoundData`].
    ///
    /// This method is fully idempotent, meaning it only depends upon the data
    /// found within the database and the [`ConsensusBoundData`]; there is no
    /// internal `state` variable or something contained within [`StaticEngine`].
    fn determine_state(
        &self,
        tx: &Transaction<'_>,
        data: &ConsensusBoundData<T>,
        now: Timestamp,
    ) -> Result<State, DatabaseError> {
        // Determine the state primarily upon ConsensusBoundData combined with
        // a few database queries, as well as the current time of course.
        let state = match data {
            // ConsensusBoundData::None means that we currently have no
            // consensus in memory.  This may be the case because we just
            // started up or because we just downloaded, validated, and inserted
            // a consensus into the database and reset ConsensusBoundData to
            // None afterwards.
            ConsensusBoundData::None => {
                // Check whether there is a valid consensus in the database at all.
                match self.recent_consensus(tx, now)? {
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
            ConsensusBoundData::Unverified { consensus, ttl, .. } if now < *ttl => {
                let certs_already = self.certs_already(tx, now)?;
                match consensus.can_verify(self.authorities.v3idents(), &certs_already) {
                    // We can verify and insert the consensus.
                    Ok(()) => State::StoreConsensus,

                    // We will never be able to verify the consensus, better
                    // times may come ...
                    Err(ConsensusVerifiabilityError::InsufficientTrustedSigners) => {
                        State::Hibernate
                    }

                    // We need to fetch more authority certificates from the
                    // network.
                    Err(ConsensusVerifiabilityError::MissingAuthCerts { .. }) => State::AuthCerts,
                }
            }

            ConsensusBoundData::Unverified { .. } => State::FetchConsensus,

            // ConsensusBoundData::Verified means that we have successfully
            // loaded a recent valid consensus from the database using
            // State::LoadConsensus.  Depending on this, we download the missing
            // network documents (descriptors) from a directory authority, if
            // any.
            ConsensusBoundData::Verified { consensus, ttl, .. } => {
                if *ttl <= now {
                    // The ttl has been surpassed, download a new
                    // consensus.  It is very important TO NOT transition to
                    // State::LoadConsensus here, because the current consensus
                    // may still be valid but not fresh anymore, in which case
                    // State::LoadConsensus will continue to obtain it from the
                    // database until valid-after has been surpassed, which is
                    // most definitely not what we want.
                    State::FetchConsensus
                } else if consensus.missing_servers(tx, Some(1))?.is_empty()
                    && consensus.missing_micros(tx, Some(1))?.is_empty()
                    && consensus.missing_extras(tx, Some(1))?.is_empty()
                {
                    // All queues are empty, meaning we are done, until ttl
                    // ends.
                    State::Hibernate
                } else {
                    // The ttl has not been surpassed and we have stuff
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
        data: &mut ConsensusBoundData<T>,
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
            State::FetchConsensus => Ok(self.fetch_consensus(data, endpoint, now).await?),
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
    /// * Compute the ttl for it.
    /// * Compute the missing descriptors for it.
    fn load_consensus<R: Rng>(
        &self,
        pool: &Pool<SqliteConnectionManager>,
        data: &mut ConsensusBoundData<T>,
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
        let consensus = db::read_tx(pool, |tx| self.recent_consensus(tx, now))??
            .ok_or(internal!("database externally modified?"))?;
        let ttl = consensus.ttl(rng);

        *data = ConsensusBoundData::Verified { consensus, ttl };
        Ok(())
    }

    /// Fetches a consensus from an upstream authority.
    // TODO DIRMIRROR: Add logging.
    #[allow(clippy::string_slice)] // TODO
    async fn fetch_consensus(
        &self,
        data: &mut ConsensusBoundData<T>,
        endpoint: &[SocketAddr],
        now: Timestamp,
    ) -> Result<(), AuthorityRequestError> {
        // Obtain the consensus.
        let (raw, consensus) = self
            .send_request(endpoint, ConsensusRequest::new(T::flavor()))
            .await?;
        let mut consensus = consensus
            .into_iter()
            .map(|(doc, start, end)| (raw[start..end].to_owned(), doc))
            .collect::<VecDeque<_>>();

        // Check for the correct number of results.
        if consensus.len() != 1 {
            return Err(AuthorityRequestError::Response(
                "invalid number of consensus?",
            ));
        }

        // expect is fine because we checked the length for one above.
        let (raw, consensus) = consensus.pop_front().expect("pop_front");

        let ttl = now + UNVERIFIED_TTL;

        // And store it.
        *data = ConsensusBoundData::Unverified {
            consensus,
            raw,
            ttl,
        };

        Ok(())
    }

    /// Fetches, validates, and stores authority certificates.
    #[allow(clippy::string_slice)] // TODO
    async fn auth_certs(
        &self,
        pool: &Pool<SqliteConnectionManager>,
        data: &mut ConsensusBoundData<T>,
        endpoint: &[SocketAddr],
        now: Timestamp,
    ) -> Result<(), OperationError> {
        let certs_already = db::read_tx(pool, |tx| self.certs_already(tx, now))??;

        // Obtain the missing authority certificate identifiers.
        let missing = match data {
            ConsensusBoundData::Unverified { consensus, .. } => {
                match consensus.can_verify(self.authorities.v3idents(), &certs_already) {
                    Err(ConsensusVerifiabilityError::MissingAuthCerts { missing, .. }) => missing,
                    _ => return Err(OperationError::Bug(internal!("we have all auth certs"))),
                }
            }
            _ => return Err(OperationError::Bug(internal!("data is not unverified"))),
        };

        // Compose the request.
        let mut requ = AuthCertRequest::new();
        for kp in missing.iter().copied() {
            requ.push(kp);
        }

        // Fire it off.
        let (resp, certs) = self
            .send_request::<_, AuthCertUnverified>(endpoint, requ)
            .await?;

        // Verify each certificate.  Invalid certificates and other problems get
        // logged and filtered out, with the result being then inserted into
        // the database.
        let certs = certs
            .into_iter()
            .filter_map(|(unverified, start, end)| {
                let kp = unverified.inspect_unverified().0.key_ids();

                // Skip certificates we did not asked for.
                //
                // Not much of an issue because certificate verification will
                // usually fail anyways, except for this weird edge-case where we
                // actually have that id fingerprint in the v3idents.
                if !missing.contains(&kp) {
                    debug!("authority returned certificate we did not asked for: {kp:?}");
                    return None;
                }

                let verified = match unverified.verify(self.authorities.v3idents()) {
                    Ok(c) => c,
                    Err(e) => {
                        debug!("received invalid auth cert ({kp:?}): {e}");
                        return None;
                    }
                };

                let timely = match self
                    .tolerance
                    .extend_tolerance(verified)
                    .if_valid_at(&now.into())
                {
                    Ok(c) => c,
                    Err(e) => {
                        debug!("received non-timely auth cert ({kp:?}): {e}");
                        return None;
                    }
                };

                Some((timely, &resp[start..end]))
            })
            .collect::<Vec<_>>();

        // When we have reached this, it means that this call made no progress,
        // i.e. the authority only returned certificates we were not interested
        // in.
        if certs.is_empty() {
            Err(Box::new(AuthorityRequestError::Response(
                "response lead to no progress",
            )))?;
        }

        // Finally, insert them all into the database.
        db::rw_tx(pool, |tx| {
            for (cert, data) in certs {
                AuthCertMeta::insert(tx, ContentEncoding::iter(), &cert, data)?;
            }
            Ok::<_, DatabaseError>(())
        })??;

        Ok(())
    }

    /// Hibernates for the remaining ttl of the consensus.
    async fn hibernate(
        &self,
        data: &mut ConsensusBoundData<T>,
        now: Timestamp,
    ) -> Result<(), OperationError> {
        match data {
            ConsensusBoundData::None => {
                return Err(internal!("hibernating without a consensus?").into());
            }
            // TODO DIRMIRROR: Should the Unverified case be an error or a
            // success? In other words: Should we exclude the current authority
            // from the set of the next authorities to try?
            ConsensusBoundData::Verified { ttl, .. }
            | ConsensusBoundData::Unverified { ttl, .. } => {
                let timeout = *ttl - now;
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
    /// [`parse2::parse_netdoc_multiple_sophisticated()`] with the results being
    /// filtered.
    ///
    /// Invalid documents are ignored but a warning is logged.
    ///
    /// The output is required because we need the raw document alongside the
    /// offsets to have the actual data we will insert into the database later
    /// on.
    async fn send_request<R: Requestable, D: NetdocParseable>(
        &self,
        endpoint: &[SocketAddr],
        requ: R,
    ) -> Result<(String, Vec<(D, usize, usize)>), AuthorityRequestError> {
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
        // more resources from the authority.  Doing so is fine, it is HTTP/1.0
        // and there is no connection reuse anyways.
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
                )));
            }
        }?;

        // Parse the response.
        let parsed = parse2::parse_netdoc_multiple_sophisticated(&ParseInput::new(&resp, ""))?
            .into_iter()
            .filter_map(|(res, start, end)| match res {
                Ok(doc) => Some((doc, start, end)),
                Err(e) => {
                    debug!("ignoring invalid netdoc: {e}");
                    None
                }
            })
            .collect();

        Ok((resp, parsed))
    }

    /// Queries and validates the most recent consensus from the database.
    fn recent_consensus(
        &self,
        tx: &Transaction<'_>,
        now: Timestamp,
    ) -> Result<Option<ConsensusMeta<T>>, DatabaseError> {
        let meta = match ConsensusMeta::<T>::query(tx)?.as_slice() {
            &[front] | &[front, ..] => front,
            &[] => return Ok(None),
        };
        let raw = meta.data(tx)?;

        let unverified = match parse2::parse_netdoc::<T>(&ParseInput::new(&raw, "<database>")) {
            Ok(unverified) => unverified,
            Err(e) => {
                // TODO DIRMIRROR: Perhaps we should remove it?
                debug!("unparseable consensus in database: {meta:?} {e}");
                return Ok(None);
            }
        };

        let certs_already = self.certs_already(tx, now)?;
        let verified = match unverified.verify(self.authorities.v3idents(), &certs_already) {
            Ok(verified) => verified,
            Err(e) => {
                // TODO DIRMIRROR: Perhaps we should remove it?
                debug!("ignoring invalid consensus in database: {meta:?} {e}");
                return Ok(None);
            }
        };

        match self
            .tolerance
            .extend_tolerance(verified)
            .if_valid_at(&now.into())
        {
            Ok(_) => Ok(Some(meta)),
            Err(e) => {
                debug!("ignoring non-timely consensus in database: {meta:?} {e}");
                Ok(None)
            }
        }
    }

    /// Loads all authority certificates from the database into a [`Vec<AuthCert>`].
    ///
    /// Performance wise, it is quite inefficient as it parses and verifies all
    /// certificates over again.  However, this should be fine as the N for
    /// directory authorities is usually very small.
    fn certs_already(
        &self,
        tx: &Transaction<'_>,
        now: Timestamp,
    ) -> Result<Vec<AuthCert>, DatabaseError> {
        let raw_certs = AuthCertMeta::query(tx)?
            .into_iter()
            .map(|meta| Ok::<_, DatabaseError>((meta, meta.data(tx)?)))
            .collect::<Result<Vec<_>, _>>()?;

        let mut certs_already = Vec::new();
        for (meta, raw) in raw_certs {
            // Only used for debugging.
            // TODO DIRMIRROR: Put this into span with tracing.
            let key_ids = AuthCertKeyIds {
                id_fingerprint: meta.kp_auth_id_rsa_sha1.0.into(),
                sk_fingerprint: meta.kp_auth_sign_rsa_sha1.0.into(),
            };

            let unverified = match parse2::parse_netdoc::<AuthCertUnverified>(&ParseInput::new(
                &raw,
                "<database>",
            )) {
                Ok(c) => c,
                Err(e) => {
                    // TODO DIRMIRROR: Perhaps we should remove it?
                    debug!("unparseable auth cert ({key_ids:?}) in database: {e}");
                    continue;
                }
            };

            let verified = match unverified.verify(self.authorities.v3idents()) {
                Ok(c) => c,
                Err(e) => {
                    debug!("ignoring invalid auth cert ({key_ids:?}): {e}");
                    continue;
                }
            };

            let timely = match self
                .tolerance
                .extend_tolerance(verified)
                .if_valid_at(&now.into())
            {
                Ok(c) => c,
                Err(e) => {
                    debug!("ignoring non-timely auth cert ({key_ids:?}): {e}");
                    continue;
                }
            };
            certs_already.push(timely);
        }
        Ok(certs_already)
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
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use std::collections::HashSet;

    use rusqlite::params;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tor_basic_utils::test_rng::testing_rng;

    use crate::{database::sql, testdata2};

    use super::*;

    type Plain = tor_netdoc::doc::netstatus::plain::NetworkStatusUnverified;
    type Md = tor_netdoc::doc::netstatus::md::NetworkStatusUnverified;

    /// Tests whether the load consensus state computes missing descriptors
    /// properly.
    ///
    /// For this, the test removes a present router descriptor from the storage
    /// to verify that it is detected as missing and added to the download
    /// queue.
    #[tokio::test]
    async fn state_load_consensus() {
        let pool = testdata2::test_db();
        let mut data = ConsensusBoundData::<Plain>::None;
        let engine = StaticEngine {
            authorities: testdata2::current_auth_cert_contacts(),
            tolerance: DirTolerance::default(),
            rt: PreferredRuntime::current().unwrap(),
            _phantom: Default::default(),
        };

        let time: Timestamp = testdata2::valid_system_time().into();
        let fresh_until: Timestamp = testdata2::current_consensus_ns()
            .0
            .preamble
            .lifetime
            .fresh_until
            .0
            .into();
        let valid_until: Timestamp = testdata2::current_consensus_ns()
            .0
            .preamble
            .lifetime
            .valid_until
            .0
            .into();
        // This is the middle of valid_until and fresh_until.
        let fresh_until_half = fresh_until + ((valid_until - fresh_until) / 2);

        // Remove a single router descriptor from our storage to see whether it
        // appears in the download queue as expected.
        let relay_to_remove = &testdata2::current_consensus_ns().0.routers[0];
        let relay_to_remove = db::Sha1::from(*relay_to_remove.doc_digest());
        pool.get()
            .unwrap()
            .execute(
                sql!("DELETE FROM router_descriptor WHERE unsigned_sha1 = ?1"),
                params![relay_to_remove],
            )
            .unwrap();

        engine
            .load_consensus(&pool, &mut data, time, &mut testing_rng())
            .unwrap();

        // El-cheapo assert_eq due to lack of PartialEq for tor-netdoc poc.
        match data {
            ConsensusBoundData::Verified { consensus, ttl, .. } => {
                // If everything worked properly, then the queue should only
                // contain the relay we removed, because that is missing now.
                db::read_tx(&pool, |tx| {
                    assert_eq!(
                        consensus.missing_servers(tx, None).unwrap(),
                        HashSet::from([relay_to_remove])
                    );
                    assert!(consensus.missing_extras(tx, None).unwrap().is_empty());
                    assert!(consensus.missing_micros(tx, None).unwrap().is_empty());
                })
                .unwrap();
                assert!(ttl >= fresh_until);
                assert!(ttl <= fresh_until_half);
            }
            _ => panic!("data is not verified"),
        }
    }

    /// Tests whether the fetch consensus state properly fetches a consensus
    /// and keeps it in memory as unverified.
    ///
    /// For this, we spawn a tokio task simulating a web server which responds
    /// with a consensus.
    #[tokio::test]
    async fn state_fetch_consensus() {
        let pool = testdata2::test_db();
        let mut data = ConsensusBoundData::<Plain>::None;
        let engine = StaticEngine {
            authorities: testdata2::current_auth_cert_contacts(),
            tolerance: DirTolerance::default(),
            rt: PreferredRuntime::current().unwrap(),
            _phantom: Default::default(),
        };
        let now = Timestamp::from(testdata2::invalid_system_time());

        let state = db::read_tx(&pool, |tx| engine.determine_state(tx, &data, now))
            .unwrap()
            .unwrap();
        assert_eq!(state, State::FetchConsensus);

        let server = TcpListener::bind("[::1]:0").await.unwrap();
        let saddr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = server.accept().await.unwrap();
            let mut buf = vec![0; 1024];
            let _ = stream.read(&mut buf).await.unwrap();

            let consensus = testdata2::current_consensus_ns().2;
            let resp = format!(
                "HTTP/1.0 200 OK\r\nContent-Encoding: identity\r\nContent-Length: {}\r\n\r\n{consensus}",
                consensus.len()
            );
            stream.write_all(resp.as_bytes()).await.unwrap();
        });

        engine
            .fetch_consensus(&mut data, &[saddr], now)
            .await
            .unwrap();
        match data {
            ConsensusBoundData::Unverified { raw, ttl, .. } => {
                assert_eq!(raw, testdata2::current_consensus_ns().2);
                assert_eq!(ttl, now + UNVERIFIED_TTL);
            }
            _ => panic!("data is not unverified"),
        }
    }

    /// Tests the download, verification, and insertion of authority certificates.
    ///
    /// For this, it starts by removing an existing one from the test database
    /// to see it getting re-downloaded, re-verified, and re-inserted again.
    #[tokio::test]
    async fn state_auth_certs() {
        let pool = testdata2::test_db();
        let mut data = ConsensusBoundData::<Plain>::Unverified {
            consensus: parse2::parse_netdoc(&ParseInput::new(
                testdata2::current_consensus_ns().2,
                "",
            ))
            .unwrap(),
            raw: testdata2::current_consensus_ns().2.to_owned(),
            ttl: Timestamp::from(testdata2::valid_system_time()) + UNVERIFIED_TTL,
        };
        let mut engine = StaticEngine {
            authorities: testdata2::current_auth_cert_contacts(),
            tolerance: DirTolerance::default(),
            rt: PreferredRuntime::current().unwrap(),
            _phantom: Default::default(),
        };

        // We want to download authority certificates; for this, remove
        // one of them from the database.
        pool.get()
            .unwrap()
            .execute(
                sql!(
                    "
                    DELETE FROM authority_key_certificate
                    WHERE :kp_auth_id_rsa_sha1 = ?1
                    "
                ),
                params![db::Sha1::from(
                    testdata2::current_auth_cert_ids()[0].to_bytes()
                )],
            )
            .unwrap();

        assert_eq!(
            db::read_tx(&pool, |tx| engine.determine_state(
                tx,
                &data,
                testdata2::valid_system_time().into()
            ))
            .unwrap()
            .unwrap(),
            State::AuthCerts
        );

        let server = TcpListener::bind("[::1]:0").await.unwrap();
        let saddr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0; 1024];
            let (mut stream, _) = server.accept().await.unwrap();
            let _ = stream.read(&mut buf).await.unwrap();

            let authcerts = testdata2::current_auth_certs()
                .into_iter()
                .map(|x| x.1)
                .collect::<String>();

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
                testdata2::valid_system_time().into(),
            )
            .await
            .unwrap();

        // Check whether we are done with all authcerts.
        assert_eq!(
            db::read_tx(&pool, |tx| engine.determine_state(
                tx,
                &data,
                testdata2::valid_system_time().into(),
            ))
            .unwrap()
            .unwrap(),
            State::StoreConsensus
        );
        // Check whether we now have all auth certs in the database.
        let certs = db::read_tx(&pool, |tx| {
            engine.certs_already(tx, testdata2::valid_system_time().into())
        })
        .unwrap()
        .unwrap();

        let got = certs
            .into_iter()
            .map(|c| c.dir_identity_key.to_rsa_identity())
            .collect::<HashSet<_>>();
        let expect = engine.authorities.v3idents().iter().copied().collect();
        assert_eq!(got, expect);

        // Check an edge case of not having enough trusted signers.
        engine.authorities = AuthorityContacts::builder().build().unwrap();
        let state = db::read_tx(&pool, |tx| {
            engine.determine_state(tx, &data, testdata2::valid_system_time().into())
        })
        .unwrap()
        .unwrap();
        assert_eq!(state, State::Hibernate);
    }

    /// Checks whether we can probably load and parse all certificates from
    /// the database.
    #[tokio::test]
    async fn certs_already() {
        let pool = testdata2::test_db();
        let engine = StaticEngine::<Plain> {
            authorities: testdata2::current_auth_cert_contacts(),
            tolerance: DirTolerance::default(),
            rt: PreferredRuntime::current().unwrap(),
            _phantom: Default::default(),
        };

        db::read_tx(&pool, |tx| {
            // With a correct system time, this should align with all authority
            // fingerprints we have.
            let certs_already = engine
                .certs_already(tx, testdata2::valid_system_time().into())
                .unwrap();
            assert_eq!(certs_already.len(), engine.authorities.v3idents().len());
            assert!(certs_already.iter().all(|c| {
                engine
                    .authorities
                    .v3idents()
                    .contains(&c.dir_identity_key.to_rsa_identity())
            }));

            // With an invalid system time, it should be empty.
            let certs_already = engine
                .certs_already(tx, testdata2::invalid_system_time().into())
                .unwrap();
            assert!(certs_already.is_empty());
        })
        .unwrap();
    }
}
