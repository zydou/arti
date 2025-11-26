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
use rusqlite::{params, OptionalExtension, Transaction};
use tor_basic_utils::RngExt;
use tor_dircommon::{
    authority::AuthorityContacts,
    config::{DirTolerance, DownloadScheduleConfig},
};
use tor_error::internal;
use tor_netdoc::doc::netstatus::ConsensusFlavor;

use crate::{
    database::{self, sql, Timestamp},
    err::{DatabaseError, FatalError},
};

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
                tolerance.pre_valid_tolerance().as_secs(),
                tolerance.post_valid_tolerance().as_secs()
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
    use tor_basic_utils::test_rng::testing_rng;
    use tor_dircommon::config::DirToleranceBuilder;

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
                    *VALID_AFTER,
                    *FRESH_UNTIL,
                    *VALID_UNTIL,
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
                    CONTENT.to_string(),
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
}
