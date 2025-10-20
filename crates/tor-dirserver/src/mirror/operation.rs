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

use std::time::{Duration, SystemTime};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rand::Rng;
use rusqlite::{params, OptionalExtension, Transaction};
use tor_basic_utils::RngExt;
use tor_dircommon::{
    authority::AuthorityContacts,
    config::{DirTolerance, DownloadScheduleConfig},
};
use tor_error::internal;
use tor_netdoc::doc::netstatus::ConsensusFlavor;
use tracing::warn;

use crate::{
    database::{self, sql, Sha256},
    err::{ConsensusSelectionError, DatabaseError},
};

/// Converts a [`SystemTime`] to a [`u64`] representing the seconds since the epoch.
///
/// Values before the epoch are not supported and will result in `0` being returned.
///
/// TODO: Should we instead just panic?  To be fair, I feel that this otherwise
/// might cause very undefined behavior.  On the other hand, `tor-cert` does
/// exactly the same.
fn st_to_unix(st: SystemTime) -> u64 {
    match st.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(unix) => unix.as_secs(),
        Err(_) => 0,
    }
}

/// Converts a Unix timestamp from a [`u64`] in seconds into a [`SystemTime`].
fn unix_to_st(unix: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(unix)
}

/// Obtains the most recent valid consensus from the database.
///
/// This function queries the database using a [`Transaction`] in order to have
/// a consistent view upon it.  It will return an [`Option`] containing various
/// consensus related timestamps plus the raw consensus itself (more on this
/// below).  In order to obtain a *valid* consensus, a [`SystemTime`] plus a
/// [`DirTolerance`] is supplied, which will be used for querying the database.
///
/// # The [`Ok`] Return Value
///
/// In the [`Some`] case, the return value is composed of the following:
/// 1. The `valid-after` timestamp represented by a [`SystemTime`].
/// 2. The `fresh-until` timestamp represented by a [`SystemTime`].
/// 3. The `valid-until` timestamp represented by a [`SystemTime`].
/// 4. The raw consensus reprented by a [`String`].
///
/// The [`None`] case implies that no valid recent consensus has been found,
/// that is, no consensus at all or no consensus whose `valid-before` or
/// `valid-after` lies within the range composed by `now` and `tolerance`.
fn get_recent_consensus(
    tx: &Transaction,
    flavor: ConsensusFlavor,
    tolerance: &DirTolerance,
    now: SystemTime,
) -> Result<Option<(SystemTime, SystemTime, SystemTime, String)>, ConsensusSelectionError> {
    // Select the most recent flavored consensus document from the database.
    //
    // The `valid_after` and `valid_until` cells must be a member of the range:
    // `[valid_after - pre_valid_tolerance; valid_after + post_valid_tolerance]`
    // (inclusively).
    //
    // The query parameters being:
    // ?1: The consensus flavor as a String.
    // ?2: `now` as a Unix timestamp.
    let mut meta_stmt = tx
        .prepare_cached(sql!(
            "
            SELECT valid_after, fresh_until, valid_until, sha256
            FROM consensus
              WHERE flavor = ?1
                AND ?2 >= valid_after - ?3
                AND ?2 <= valid_until + ?4
              ORDER BY valid_after DESC
              LIMIT 1
            "
        ))
        .map_err(DatabaseError::from)?;

    // Actually execute the query; a None is totally valid and considered as
    // no consensus being present in the current database.
    let meta: Option<(SystemTime, SystemTime, SystemTime, Sha256)> = meta_stmt
        .query_one(
            params![
                flavor.name(),
                st_to_unix(now),
                tolerance.pre_valid_tolerance().as_secs(),
                tolerance.post_valid_tolerance().as_secs()
            ],
            |row| {
                Ok((
                    // Convert u64 to SystemTime.
                    unix_to_st(row.get(0)?),
                    unix_to_st(row.get(1)?),
                    unix_to_st(row.get(2)?),
                    row.get(3)?,
                ))
            },
        )
        .optional()
        .map_err(DatabaseError::from)?;
    let (valid_after, fresh_until, valid_until, sha256) = match meta {
        Some(res) => res,
        None => return Ok(None),
    };

    // Query the sha256 obtained above from the content-addressable store table.
    //
    // Because the store table stores content as a BLOB, we also convert it to
    // a String securely, with errors composing a constraint violation.
    let mut content_stmt = tx
        .prepare_cached(sql!("SELECT content FROM store WHERE sha256 = ?1"))
        .map_err(DatabaseError::from)?;
    let consensus: Vec<u8> = content_stmt
        .query_one(params![sha256], |row| row.get(0))
        .map_err(DatabaseError::from)?;
    let consensus = String::from_utf8(consensus)
        .map_err(|e| DatabaseError::from(internal!("utf-8 contraint violated? {e}")))?;

    Ok(Some((valid_after, fresh_until, valid_until, consensus)))
}

/// Calculates the [`Duration`] to wait before querying the authorities again.
///
/// This function accepts a `fresh-until` and `valid-until`, both hopefully
/// obtained through the [`get_recent_consensus()`] function, and calculates
/// a [`Duration`] relative to `now` describing the time to wait before querying
/// the authorities again.  This function might also return [`Duration::ZERO`],
/// implying that a new consensus document should be acquired as soon as possible.
///
/// Note for interfacing applications: If you do not have a [`SystemTime`] because
/// you have no (valid) consensus at all, just use [`Duration::ZERO`] instead of
/// calling this function, which itself should only be used in the case that
/// [`get_recent_consensus()`] actually returned data.
///
/// # Specifications
///
/// * <https://spec.torproject.org/dir-spec/directory-cache-operation.html#download-ns-from-auth>
///
/// TODO DIRMIRROR: Consider not naming this timeout but something like
/// "download interval" or "poll interval".
fn calculate_sync_timeout<R: Rng>(
    fresh_until: SystemTime,
    valid_until: SystemTime,
    now: SystemTime,
    rng: &mut R,
) -> Duration {
    let fresh_until = st_to_unix(fresh_until);
    let valid_until = st_to_unix(valid_until);
    let now = st_to_unix(now);
    assert!(fresh_until < valid_until);

    let res = fresh_until
        + rng
            .gen_range_checked(0..=((valid_until - fresh_until) / 2))
            .expect("invalid rng range?");

    Duration::from_secs(res)
        .checked_sub(Duration::from_secs(now))
        .unwrap_or_default()
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
pub(super) async fn serve<R: Rng, F: Fn() -> SystemTime>(
    pool: Pool<SqliteConnectionManager>,
    flavor: ConsensusFlavor,
    _authorities: AuthorityContacts,
    _schedule: DownloadScheduleConfig,
    tolerance: DirTolerance,
    rng: &mut R,
    now_fn: F,
) -> Result<(), FatalError> {
    loop {
        // (1) Call get_recent_consensus() to obtain the most recent and non-expired
        // consensus from the database.
        // TODO: Use `Result::flatten` once MSRV is 1.89.0.
        let now = now_fn();
        let res = database::read_tx(&pool, {
            let tolerance = tolerance.clone();
            move |tx| get_recent_consensus(tx, flavor, &tolerance, now)
        })
        .map_err(ConsensusSelectionError::from);
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
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use crate::database;

    use super::*;
    use tor_basic_utils::test_rng::testing_rng;
    use tor_dircommon::config::DirToleranceBuilder;

    const VALID_AFTER: u64 = 1577836800; // Wed Jan 01 2020 00:00:00 GMT+0000
    const FRESH_UNTIL: u64 = VALID_AFTER + 60 * 60; // Wed Jan 01 2020 01:00:00 GMT+0000
    const FRESH_UNTIL_HALF: u64 = FRESH_UNTIL + 60 * 60; // Wed Jan 01 2020 02:00:00 GMT+0000
    const VALID_UNTIL: u64 = FRESH_UNTIL + 60 * 60 * 2; // Wed Jan 01 2020 03:00:00 GMT+0000

    const CONTENT: &str = "Lorem ipsum dolor sit amet.";
    const SHA256: &str = "DD14CBBF0E74909AAC7F248A85D190AFD8DA98265CEF95FC90DFDDABEA7C2E66";

    fn create_dummy_db() -> Pool<SqliteConnectionManager> {
        let pool = database::open("").unwrap();
        database::rw_tx(&pool, |tx| {
            tx.execute(
                sql!("INSERT INTO store (sha256, content) VALUES (?1, ?2)"),
                params![
                    "DD14CBBF0E74909AAC7F248A85D190AFD8DA98265CEF95FC90DFDDABEA7C2E66",
                    "Lorem ipsum dolor sit amet.".as_bytes()
                ],
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
                    "DD14CBBF0E74909AAC7F248A85D190AFD8DA98265CEF95FC90DFDDABEA7C2E66",
                    "0000000000000000000000000000000000000000000000000000000000000000", // not the correct hash
                    ConsensusFlavor::Plain.name(),
                    VALID_AFTER,
                    FRESH_UNTIL,
                    VALID_UNTIL,
                ],
            )
            .unwrap();
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
                SystemTime::UNIX_EPOCH,
            )
            .unwrap()
            .is_none());

            // Get None by being way behind valid-until.
            assert!(get_recent_consensus(
                tx,
                ConsensusFlavor::Plain,
                &no_tolerance,
                unix_to_st(VALID_UNTIL + 60 * 60 * 24 * 365),
            )
            .unwrap()
            .is_none());

            // Get None by being minimally before valid-after.
            assert!(get_recent_consensus(
                tx,
                ConsensusFlavor::Plain,
                &no_tolerance,
                unix_to_st(VALID_AFTER - 1),
            )
            .unwrap()
            .is_none());

            // Get None by being minimally behind valid-until.
            assert!(get_recent_consensus(
                tx,
                ConsensusFlavor::Plain,
                &no_tolerance,
                unix_to_st(VALID_UNTIL + 1),
            )
            .unwrap()
            .is_none());

            // Get a valid consensus by being in the interval.
            let res1 = get_recent_consensus(
                tx,
                ConsensusFlavor::Plain,
                &no_tolerance,
                unix_to_st(VALID_AFTER),
            )
            .unwrap()
            .unwrap();
            let res2 = get_recent_consensus(
                tx,
                ConsensusFlavor::Plain,
                &no_tolerance,
                unix_to_st(VALID_UNTIL),
            )
            .unwrap()
            .unwrap();
            let res3 = get_recent_consensus(
                tx,
                ConsensusFlavor::Plain,
                &no_tolerance,
                unix_to_st(VALID_AFTER + 60 * 30),
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                res1,
                (
                    unix_to_st(VALID_AFTER),
                    unix_to_st(FRESH_UNTIL),
                    unix_to_st(VALID_UNTIL),
                    CONTENT.to_string(),
                )
            );
            assert_eq!(res1, res2);
            assert_eq!(res2, res3);

            // Get a valid consensus using a liberal dir tolerance.
            let res1 = get_recent_consensus(
                tx,
                ConsensusFlavor::Plain,
                &liberal_tolerance,
                unix_to_st(VALID_AFTER - 60 * 30),
            )
            .unwrap()
            .unwrap();
            let res2 = get_recent_consensus(
                tx,
                ConsensusFlavor::Plain,
                &liberal_tolerance,
                unix_to_st(VALID_UNTIL + 60 * 30),
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                res1,
                (
                    unix_to_st(VALID_AFTER),
                    unix_to_st(FRESH_UNTIL),
                    unix_to_st(VALID_UNTIL),
                    CONTENT.to_string(),
                )
            );
            assert_eq!(res1, res2);
        })
        .unwrap();
    }

    #[test]
    fn sync_timeout() {
        // Get [`Duration::ZERO`] by being too late.
        assert_eq!(
            calculate_sync_timeout(
                unix_to_st(FRESH_UNTIL),
                unix_to_st(VALID_UNTIL),
                unix_to_st(VALID_UNTIL),
                &mut testing_rng(),
            ),
            Duration::ZERO
        );

        // We repeat the tests a few thousand times to go over many random values.
        for _ in 0..10000 {
            let now = st_to_unix(
                SystemTime::UNIX_EPOCH
                    .checked_add(Duration::from_secs(VALID_AFTER + 42))
                    .unwrap(),
            );

            let dur = calculate_sync_timeout(
                unix_to_st(FRESH_UNTIL),
                unix_to_st(VALID_UNTIL),
                unix_to_st(now),
                &mut testing_rng(),
            )
            .as_secs();
            assert!(dur >= FRESH_UNTIL - now && dur <= FRESH_UNTIL_HALF - now);
        }
    }
}
