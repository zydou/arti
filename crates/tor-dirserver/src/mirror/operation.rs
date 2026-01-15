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

use std::time::Duration;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rand::Rng;
use rusqlite::{named_params, params, OptionalExtension, Transaction};
use strum::IntoEnumIterator;
use tor_basic_utils::RngExt;
use tor_dirclient::request::AuthCertRequest;
use tor_dircommon::{
    authority::AuthorityContacts,
    config::{DirTolerance, DownloadScheduleConfig},
};
use tor_error::internal;
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_netdoc::{
    doc::{
        authcert::{AuthCert, AuthCertKeyIds, AuthCertSigned},
        netstatus::ConsensusFlavor,
    },
    parse2::{self, NetdocSigned, ParseInput},
};
use tracing::warn;

use crate::{
    database::{self, sql, ContentEncoding, Timestamp},
    err::{DatabaseError, FatalError, NetdocRequestError},
    mirror::operation::download::ConsensusBoundDownloader,
};

mod download;

/// Obtains the most recent valid consensus from the database.
///
/// This function queries the database using a [`Transaction`] in order to have
/// a consistent view upon it.  It will return an [`Option`] containing various
/// consensus related timestamps plus the raw consensus itself (more on this
/// below).  In order to obtain a *valid* consensus, a [`Timestamp`] plus a
/// [`DirTolerance`] is supplied, which will be used for querying the datbaase.
///
/// # The [`Ok`] Return Value
///
/// In the [`Some`] case, the return value is composed of the following:
/// 1. The `valid-after` timestamp represented by a [`Timestamp`].
/// 2. The `fresh-until` timestamp represented by a [`Timestamp`].
/// 3. The `valid-until` timestamp represented by a [`Timestamp`].
/// 4. The raw consensus reprented by a [`String`].
///
/// The [`None`] case implies that no valid recent consensus has been found,
/// that is, no consensus at all or no consensus whose `valid-before` or
/// `valid-after` lies within the range composed by `now` and `tolerance`.
fn get_recent_consensus(
    tx: &Transaction,
    flavor: ConsensusFlavor,
    tolerance: &DirTolerance,
    now: Timestamp,
) -> Result<Option<(Timestamp, Timestamp, Timestamp, String)>, DatabaseError> {
    // Select the most recent flavored consensus document from the database.
    //
    // The `valid_after` and `valid_until` cells must be a member of the range:
    // `[valid_after - pre_valid_tolerance; valid_after + post_valid_tolerance]`
    // (inclusively).
    //
    // The query parameters being:
    // ?1: The consensus flavor as a String.
    // ?2: `now` as a Unix timestamp.
    let mut meta_stmt = tx.prepare_cached(sql!(
        "
        SELECT c.valid_after, c.fresh_until, c.valid_until, s.content
        FROM
          consensus AS c
          INNER JOIN store AS s ON s.sha256 = c.sha256
        WHERE
          flavor = ?1
          AND ?2 >= valid_after - ?3
          AND ?2 <= valid_until + ?4
        ORDER BY valid_after DESC
        LIMIT 1
        "
    ))?;

    // Actually execute the query; a None is totally valid and considered as
    // no consensus being present in the current database.
    let res = meta_stmt
        .query_one(
            params![
                flavor.name(),
                now,
                tolerance
                    .pre_valid_tolerance()
                    .as_secs()
                    .try_into()
                    .unwrap_or(i64::MAX),
                tolerance
                    .post_valid_tolerance()
                    .as_secs()
                    .try_into()
                    .unwrap_or(i64::MAX)
            ],
            |row| {
                Ok((
                    row.get::<_, Timestamp>(0)?,
                    row.get::<_, Timestamp>(1)?,
                    row.get::<_, Timestamp>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()?;

    let (valid_after, fresh_until, valid_until, consensus) = match res {
        Some(res) => res,
        None => return Ok(None),
    };

    let consensus =
        String::from_utf8(consensus).map_err(|e| internal!("utf-8 contraint violated? {e}"))?;

    Ok(Some((valid_after, fresh_until, valid_until, consensus)))
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
/// why the return type is not [`AuthCertSigned`].
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
          INNER JOIN store AS s ON s.sha256 = a.sha256
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
        let cert = parse2::parse_netdoc::<AuthCertSigned>(&ParseInput::new(&raw_cert, ""));
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
/// This function will then use the [`ConsensusBoundDownloader`] to download
/// the missing certificates from a directory authority.
async fn download_authority_certificates<'a, 'b, R: Rng>(
    missing: &[AuthCertKeyIds],
    downloader: &mut ConsensusBoundDownloader<'a, 'b>,
    rng: &mut R,
) -> Result<String, NetdocRequestError> {
    let mut requ = AuthCertRequest::new();
    missing.iter().for_each(|kp| requ.push(*kp));

    let resp = downloader
        .download(&requ, rng)
        .await
        .map_err(NetdocRequestError::Download)?;
    let resp = String::from_utf8(resp)?;

    Ok(resp)
}

/// Parses multiple raw directory authority certificates.
///
/// Returns the parsed [`AuthCertSigned`] alongside their raw plain-text
/// representation.
fn parse_authority_certificates<'a>(
    certs: &'a str,
) -> Result<Vec<(AuthCertSigned, &'a str)>, parse2::ParseError> {
    parse2::parse_netdoc_multiple_with_offsets::<AuthCertSigned>(&ParseInput::new(certs, ""))?
        .into_iter()
        // Creating the slice is fine, parse2 guarantees it is in-bounds.
        .map(|(cert, start, end)| Ok((cert, &certs[start..end])))
        .collect()
}

/// Verifies multiple raw directory authority certificates.
///
/// Returns the verified [`AuthCertSigned`] values as [`AuthCert`] values.
/// The [`str`] slice will remain unmodified, meaning that it will still include
/// the signature parts in plain-text.
/// This function is mostly used in conjunction with
/// [`parse_authority_certificates()`] in order to ensure its outputs were
/// correct.
fn verify_authority_certificates<'a>(
    certs: Vec<(AuthCertSigned, &'a str)>,
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
    // :sha256 - The SHA256 as found in the store table.
    // :id_rsa - The identity key fingerprint.
    // :sign_rsa - The signing key fingerprint.
    // :published - The published timestamp.
    // :expires - The expires timestamp.
    let mut stmt = tx.prepare_cached(sql!(
        "
        INSERT INTO authority_key_certificate
          (sha256, kp_auth_id_rsa_sha1, kp_auth_sign_rsa_sha1, dir_key_published, dir_key_expires)
        VALUES
          (:sha256, :id_rsa, :sign_rsa, :published, :expires)
        "
    ))?;

    // Compress and insert all certificates into the store within the context of
    // our (still pending) transaction.  Keep track of the uncompressed sha256
    // too.
    let certs = certs
        .iter()
        .map(|(cert, raw)| {
            // For now, we encode the authcerts in all encodings.
            // TODO: This is probably not a good idea, but it will also not be
            // the end of the world if we change this later -- at worst, clients
            // will simply get it in a different encoding they prefer less, but
            // that should not be super critical.
            let sha256 = database::store_insert(tx, raw.as_bytes(), ContentEncoding::iter())?;
            Ok::<_, DatabaseError>((sha256, cert))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Insert every certificate, after it has been inserted into the store, into
    // the authority certificates meta table.
    for (sha256, cert) in certs {
        stmt.execute(named_params! {
            ":sha256": sha256,
            ":id_rsa": cert.fingerprint.as_hex_upper(),
            ":sign_rsa": cert.dir_signing_key.to_rsa_identity().as_hex_upper(),
            ":published": Timestamp::from(cert.dir_key_published.0),
            ":expires": Timestamp::from(cert.dir_key_expires.0),
        })?;
    }

    Ok(())
}

/// Calculates the [`Duration`] to wait before querying the authorities again.
///
/// This function accepts a `fresh-until` and `valid-until`, both hopefully
/// obtained through the [`get_recent_consensus()`] function, and caculates a
/// [`Duration`] relative to `now`, describing the time to wait before querying
/// the authorities again.
///
/// If [`get_recent_consensus()`] returned [`None`], it is safe to skip a call
/// to this function and use [`Duration::ZERO`] instead.
///
/// # Specifications
///
/// * <https://spec.torproject.org/dir-spec/directory-cache-operation.html#download-ns-from-auth>
///
/// TODO DIRMIRROR: Consider not naming this timeout but something like
/// "download interval" or "poll interval".
fn calculate_sync_timeout<R: Rng>(
    fresh_until: Timestamp,
    valid_until: Timestamp,
    now: Timestamp,
    rng: &mut R,
) -> Duration {
    assert!(fresh_until < valid_until);

    let offset = rng
        .gen_range_checked(0..=((valid_until - fresh_until).as_secs() / 2))
        .expect("invalid range???");

    // fresh_until + offset - now
    fresh_until + Duration::from_secs(offset) - now
}

/// Runs forever in the current task, performing the core operation of a directory mirror.
///
/// This function runs forever in the current task, continously downloading
/// network documents from authorities and inserting them into the database,
/// while also performing garbage collection.
///
/// A core principle of this function is to be safe against power-losses, sudden
/// abortions, and such.  This means that re-starting this function will resume
/// seaminglessly from where it stopped.
///
/// # Algorithm
///
/// 1. Call [`get_recent_consensus()`] to obtain the most recent and non-expired
///    consensus from the database.
///     1. If the call returns [`Some`], goto (2).
///     2. If the call returns [`None`], goto (3).
/// 2. Spawn a task backed by [`tokio::time::timeout()`] whose purpose it is to
///    determine all missing network documents referred to by the current
///    consensus and scheduling downloads from the authorities in order to
///    obtain and insert them into the database.
///    TODO DIRMIRROR: Impose a timeout for each download attempt.
/// 3. Download a new consensus from the directory authorities and insert it into
///    the database.
/// 4. Perform a cycle of garbage collection.
/// 5. Goto (1).
///
/// # Specifications
///
/// * <https://spec.torproject.org/dir-spec/directory-cache-operation.html#download-desc-from-auth>
/// * <https://spec.torproject.org/dir-spec/client-operation.html#retrying-failed-downloads>
pub(super) async fn serve<R: Rng, F: Fn() -> Timestamp>(
    pool: Pool<SqliteConnectionManager>,
    flavor: ConsensusFlavor,
    _authorities: AuthorityContacts,
    _schedule: DownloadScheduleConfig,
    tolerance: DirTolerance,
    rng: &mut R,
    now_fn: F,
) -> Result<(), FatalError> {
    loop {
        let now = now_fn();

        // (1) Call get_recent_consensus() to obtain the most recent and non-expired
        // consensus from the database.
        // TODO: Use `Result::flatten` once MSRV is 1.89.0.
        let res = database::read_tx(&pool, {
            let tolerance = tolerance.clone();
            move |tx| get_recent_consensus(tx, flavor, &tolerance, now)
        });
        let res = match res {
            Ok(Ok(res)) => res,
            Err(e) | Ok(Err(e)) => {
                return Err(FatalError::ConsensusSelection(e));
            }
        };

        // (1.1) If the call returns Some, goto (2).
        if let Some((_valid_after, fresh_until, valid_until, _consensus)) = res {
            // (2) Run a closure backed by tokio::time::timeout() with a lifetime
            // returned by by calculate_sync_timeout, whose purpose it is to
            // determine all missing network documents reffered to by the current
            // consensus and scheduling downloads from the authorities in order
            // to obtain and insert them into the database.
            let sync_timeout = calculate_sync_timeout(fresh_until, valid_until, now, rng);
            tokio::time::timeout(sync_timeout, async {
                // TODO DIRMIRROR: Actually download descriptors.
                // Ensure a good timeout to protect against malicious
                // authorities transmitting data extra slow; a download should
                // probably not take `sync_timeout` but a few minutes instead.
                // This implies a nested timeout.  The `sync_timeout` for the
                // outer layer and a smaller timeout for each download, in order
                // to ensure that each download actually gets the same amount
                // of time to exist, instead of just the first ones having
                // the full-time, with subsequent ones having a smaller and
                // smaller time.
                let _ = std::future::pending::<()>().await;
            })
            .await
            .expect_err("std::future::pending returned?");
        }

        // (3) Download a new consensus from the directory authorities and insert
        // it into the database.
        //
        // At this stage we also have to ask ourselves what happens in the highly
        // unlikely but still possible case that a new consensus could not be
        // retrieved, due to connectivity-loss (actually likely) or the even
        // more unlikely case of the directory authorities all being down and/or
        // unable to compute a new consensus.
        //
        // The specification is fairly clean on that (see the link above).
        // Downloads are retried with a variation of the "decorrelated jitter"
        // algorithm; that is, determining a certain amount of time before trying
        // again from an authority we have not tried yet.
        //
        // TODO: Actually download from authorities.

        // (4) Perform a cycle of garbage collection.
        // TODO: Actually perform a cycle of garbage collection.
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
    use std::time::SystemTime;

    use crate::database;

    use super::*;
    use lazy_static::lazy_static;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tor_basic_utils::test_rng::testing_rng;
    use tor_dircommon::{authority::AuthorityContactsBuilder, config::DirToleranceBuilder};
    use tor_llcrypto::pk::rsa::RsaIdentity;
    use tor_rtcompat::PreferredRuntime;

    lazy_static! {
    /// Wed Jan 01 2020 00:00:00 GMT+0000
    static ref VALID_AFTER: Timestamp =
        (SystemTime::UNIX_EPOCH + Duration::from_secs(1577836800)).into();

    /// Wed Jan 01 2020 01:00:00 GMT+0000
    static ref FRESH_UNTIL: Timestamp =
        *VALID_AFTER + Duration::from_secs(60 * 60);

    /// Wed Jan 01 2020 02:00:00 GMT+0000
    static ref FRESH_UNTIL_HALF: Timestamp =
        *FRESH_UNTIL + Duration::from_secs(60 * 60);

    /// Wed Jan 01 2020 03:00:00 GMT+0000
    static ref VALID_UNTIL: Timestamp =
        *FRESH_UNTIL + Duration::from_secs(60 * 60 * 2);
    }

    const CONSENSUS_CONTENT: &str = "Lorem ipsum dolor sit amet.";
    const CONSENSUS_SHA256: &str =
        "DD14CBBF0E74909AAC7F248A85D190AFD8DA98265CEF95FC90DFDDABEA7C2E66";

    const CERT_CONTENT: &[u8] = include_bytes!("../../testdata/authcert-longclaw");
    const CERT_SHA256: &str = "8E16D249DF4E78E65FA8E0E863AC01A63995A8FB6F2B40526275BEB3E4AEABC9";

    fn create_dummy_db() -> Pool<SqliteConnectionManager> {
        let pool = database::open("").unwrap();
        database::rw_tx(&pool, |tx| {
            tx.execute(
                sql!("INSERT INTO store (sha256, content) VALUES (?1, ?2)"),
                params![CONSENSUS_SHA256, CONSENSUS_CONTENT.as_bytes()],
            )
            .unwrap();
            tx.execute(
                sql!("INSERT INTO store (sha256, content) VALUES (?1, ?2)"),
                params![CERT_SHA256, CERT_CONTENT],
            )
            .unwrap();

            tx.execute(
                sql!(
                    "
                    INSERT INTO consensus
                    (sha256, unsigned_sha3_256, flavor, valid_after, fresh_until, valid_until)
                    VALUES
                    (?1, ?2, ?3, ?4, ?5, ?6)
                    "
                ),
                params![
                    CONSENSUS_SHA256,
                    "0000000000000000000000000000000000000000000000000000000000000000", // not the correct hash
                    ConsensusFlavor::Plain.name(),
                    *VALID_AFTER,
                    *FRESH_UNTIL,
                    *VALID_UNTIL,
                ],
            )
            .unwrap();

            tx.execute(sql!(
                "
                INSERT INTO authority_key_certificate
                  (sha256, kp_auth_id_rsa_sha1, kp_auth_sign_rsa_sha1, dir_key_published, dir_key_expires)
                VALUES
                  (:sha256, :id_rsa, :sk_rsa, :published, :expires)
                "
                ),
                named_params! {
                ":sha256": CERT_SHA256,
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
    fn recent_consensus() {
        let pool = create_dummy_db();
        let no_tolerance = DirToleranceBuilder::default()
            .pre_valid_tolerance(Duration::ZERO)
            .post_valid_tolerance(Duration::ZERO)
            .build()
            .unwrap();
        let liberal_tolerance = DirToleranceBuilder::default()
            .pre_valid_tolerance(Duration::from_secs(60 * 60)) // 1h before
            .post_valid_tolerance(Duration::from_secs(60 * 60)) // 1h after
            .build()
            .unwrap();

        database::read_tx(&pool, move |tx| {
            // Get None by being way before valid-after.
            assert!(get_recent_consensus(
                tx,
                ConsensusFlavor::Plain,
                &no_tolerance,
                SystemTime::UNIX_EPOCH.into(),
            )
            .unwrap()
            .is_none());

            // Get None by being way behind valid-until.
            assert!(get_recent_consensus(
                tx,
                ConsensusFlavor::Plain,
                &no_tolerance,
                *VALID_UNTIL + Duration::from_secs(60 * 60 * 24 * 365),
            )
            .unwrap()
            .is_none());

            // Get None by being minimally before valid-after.
            assert!(get_recent_consensus(
                tx,
                ConsensusFlavor::Plain,
                &no_tolerance,
                *VALID_AFTER - Duration::from_secs(1),
            )
            .unwrap()
            .is_none());

            // Get None by being minimally behind valid-until.
            assert!(get_recent_consensus(
                tx,
                ConsensusFlavor::Plain,
                &no_tolerance,
                *VALID_UNTIL + Duration::from_secs(1),
            )
            .unwrap()
            .is_none());

            // Get a valid consensus by being in the interval.
            let res1 =
                get_recent_consensus(tx, ConsensusFlavor::Plain, &no_tolerance, *VALID_AFTER)
                    .unwrap()
                    .unwrap();
            let res2 =
                get_recent_consensus(tx, ConsensusFlavor::Plain, &no_tolerance, *VALID_UNTIL)
                    .unwrap()
                    .unwrap();
            let res3 = get_recent_consensus(
                tx,
                ConsensusFlavor::Plain,
                &no_tolerance,
                *VALID_AFTER + Duration::from_secs(60 * 30),
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                res1,
                (
                    *VALID_AFTER,
                    *FRESH_UNTIL,
                    *VALID_UNTIL,
                    CONSENSUS_CONTENT.to_string(),
                )
            );
            assert_eq!(res1, res2);
            assert_eq!(res2, res3);

            // Get a valid consensus using a liberal dir tolerance.
            let res1 = get_recent_consensus(
                tx,
                ConsensusFlavor::Plain,
                &liberal_tolerance,
                *VALID_AFTER - Duration::from_secs(60 * 30),
            )
            .unwrap()
            .unwrap();
            let res2 = get_recent_consensus(
                tx,
                ConsensusFlavor::Plain,
                &liberal_tolerance,
                *VALID_UNTIL + Duration::from_secs(60 * 30),
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                res1,
                (
                    *VALID_AFTER,
                    *FRESH_UNTIL,
                    *VALID_UNTIL,
                    CONSENSUS_CONTENT.to_string(),
                )
            );
            assert_eq!(res1, res2);
        })
        .unwrap();
    }

    #[test]
    fn sync_timeout() {
        // We repeat the tests a few thousand times to go over many random values.
        for _ in 0..10000 {
            let now = (SystemTime::UNIX_EPOCH + Duration::from_secs(42)).into();

            let dur = calculate_sync_timeout(*FRESH_UNTIL, *VALID_UNTIL, now, &mut testing_rng());
            assert!(dur >= *FRESH_UNTIL - now);
            assert!(dur <= *FRESH_UNTIL_HALF - now);
        }
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
                    WHERE sha256 = (SELECT sha256 FROM authority_key_certificate)
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
        let mut downloader = ConsensusBoundDownloader::new(authorities.downloads(), &rt);
        let certs_raw = download_authority_certificates(
            &[AuthCertKeyIds {
                id_fingerprint: RsaIdentity::from_hex("49015F787433103580E3B66A1707A00E60F2D15B")
                    .unwrap(),
                sk_fingerprint: RsaIdentity::from_hex("C5D153A6F0DA7CC22277D229DCBBF929D0589FE0")
                    .unwrap(),
            }],
            &mut downloader,
            &mut testing_rng(),
        )
        .await
        .unwrap();
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
                      store AS s ON a.sha256 = s.sha256
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
