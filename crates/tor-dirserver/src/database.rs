//! Access to the database schema.
//!
//! This module is not intended to provide a high-level ORM, instead it serves
//! the purpose of initializing and upgrading the database, if necessary.
//!
//! # Synchronous or Asynchronous?
//!
//! The question on whether the database and access to it shall be synchronous
//! or asynchronous has been fairly long debate that eventually got settled
//! after realizing that an asynchronous approach does not work.  This comment
//! should serve as a reminder for future devs, wondering why we use certain
//! synchronous primitives in an otherwise asynchronous codebase.
//!
//! Early on, it was clear that we would need some sort of connection pool,
//! primarily for two reasons:
//! 1. Performing frequent open and close calls in every task would be costly.
//! 2. Sharing a single connection object with a Mutex would be a waste
//!
//! Because the application itself is primarily asynchronous, we decided to go
//! with an asynchronous connection pool as well, leading to the choose of
//! `deadpool` initially.
//!
//! However, soon thereafter, problems with `deadpool` became evident.  Those
//! problems mostly stemmed from the synchronous nature of SQLite itself.  In our
//! case, this problem was initially triggered by figuring out a way to solve
//! `SQLITE_BUSY` handling.  In the end, we decided to settle upon the following
//! approach: Set `PRAGMA busy_timeout` to a certain value and create write
//! transactions with `BEGIN EXCLUSIVE`.  This way, SQLite would try to obtain
//! a write transaction for `busy_timeout` milliseconds by blocking the current
//! thread.  Due to this blocking, async no longer made any sense and was in
//! fact quite counter-productive because those potential sleep could screw a
//! lot of things up, which became very evident while trying to test this.
//!
//! Besides, throughout refactoring the code base, we realized that, even while
//! still using `deadpool`, the actual "asynchronous" calls interfacing with the
//! database became smaller and smaller.  In the end, the asynchronous code just
//! involved parts of obtaining a connection and creating a transaction,
//! eventually resulting in a calling a synchronous function taking the
//! transaction handle to perform the lion's share of the operation.

use std::{num::NonZero, path::Path};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Transaction, TransactionBehavior};

use crate::err::DatabaseError;

/// Representation of a Sha256 hash in hexadecimal (upper-case)
// TODO: Make this a real type that actually enforces the constraints.
pub(crate) type Sha256 = String;

/// A no-op macro just returning the supplied.
///
/// The purpose of this macro is to semantically mark [`str`] literals to be
/// SQL statement.
///
/// Keep in mind that the compiler will not notice if you forget this macro.
/// Unfortunately, you have to ensure it yourself.
macro_rules! sql {
    ($s:literal) => {
        $s
    };
}

pub(crate) use sql;

/// Version 1 of the database schema.
///
/// TODO DIRMIRROR: Should we rename arti_dirmirror_schema_version to say
/// dirserver or something more generic?
const V1_SCHEMA: &str = sql!(
    "
-- Meta table to store the current schema version.
CREATE TABLE arti_dirmirror_schema_version(
    version TEXT NOT NULL -- currently, always `1`
) STRICT;

-- Stores consensuses.
--
-- http://<hostname>/tor/status-vote/current/consensus-<FLAVOR>
-- http://<hostname>/tor/status-vote/current/consensus-<FLAVOR>/<F1>+<F2>+<F3>
-- http://<hostname>/tor/status-vote/current/consensus-<FLAVOR>/diff/<HASH>/<FPRLIST>
CREATE TABLE consensus(
    rowid               INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256              TEXT NOT NULL UNIQUE,
    -- Required for consensus diffs.
    -- https://spec.torproject.org/dir-spec/directory-cache-operation.html#diff-format
    unsigned_sha3_256   TEXT NOT NULL UNIQUE,
    flavor              TEXT NOT NULL,
    valid_after         INTEGER NOT NULL,
    fresh_until         INTEGER NOT NULL,
    valid_until         INTEGER NOT NULL,
    FOREIGN KEY(sha256) REFERENCES store(sha256),
    CHECK(GLOB('*[^0-9A-F]*', unsigned_sha3_256) == 0),
    CHECK(LENGTH(unsigned_sha3_256) == 64),
    CHECK(flavor IN ('ns', 'md')),
    CHECK(valid_after >= 0),
    CHECK(fresh_until >= 0),
    CHECK(valid_until >= 0),
    CHECK(valid_after < fresh_until),
    CHECK(fresh_until < valid_until)
) STRICT;

-- Stores consensus diffs.
--
-- http://<hostname>/tor/status-vote/current/consensus-<FLAVOR>/diff/<HASH>/<FPRLIST>
CREATE TABLE consensus_diff(
    rowid                   INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256                  TEXT NOT NULL UNIQUE,
    old_consensus_rowid     INTEGER NOT NULL,
    new_consensus_rowid     INTEGER NOT NULL,
    FOREIGN KEY(sha256) REFERENCES store(sha256),
    FOREIGN KEY(old_consensus_rowid) REFERENCES consensus(rowid),
    FOREIGN KEY(new_consensus_rowid) REFERENCES consensus(rowid)
) STRICT;

-- Stores the router descriptors.
--
-- http://<hostname>/tor/server/fp/<F>
-- http://<hostname>/tor/server/d/<D>
-- http://<hostname>/tor/server/authority
-- http://<hostname>/tor/server/all
CREATE TABLE router_descriptor(
    rowid                   INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256                  TEXT NOT NULL UNIQUE,
    sha1                    TEXT NOT NULL UNIQUE,
    kp_relay_id_rsa_sha1    TEXT NOT NULL,
    flavor                  TEXT NOT NULL,
    router_extra_info_rowid  INTEGER,
    FOREIGN KEY(sha256) REFERENCES store(sha256),
    FOREIGN KEY(router_extra_info_rowid) REFERENCES router_extra_info(rowid),
    CHECK(GLOB('*[^0-9A-F]*', sha1) == 0),
    CHECK(GLOB('*[^0-9A-F]*', kp_relay_id_rsa_sha1) == 0),
    CHECK(LENGTH(sha1) == 40),
    CHECK(LENGTH(kp_relay_id_rsa_sha1) == 40),
    CHECK(flavor IN ('ns', 'md'))
) STRICT;

-- Stores extra-info documents.
--
-- http://<hostname>/tor/extra/d/<D>
-- http://<hostname>/tor/extra/fp/<FP>
-- http://<hostname>/tor/extra/all
-- http://<hostname>/tor/extra/authority
CREATE TABLE router_extra_info(
    rowid                   INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256                  TEXT NOT NULL UNIQUE,
    sha1                    TEXT NOT NULL UNIQUE,
    kp_relay_id_rsa_sha1    TEXT NOT NULL,
    FOREIGN KEY(sha256) REFERENCES store(sha256),
    CHECK(GLOB('*[^0-9A-F]*', sha1) == 0),
    CHECK(GLOB('*[^0-9A-F]*', kp_relay_id_rsa_sha1) == 0),
    CHECK(LENGTH(sha1) == 40),
    CHECK(LENGTH(kp_relay_id_rsa_sha1) == 40)
) STRICT;

-- Directory authority key certificates.
--
-- This information is derived from the consensus documents.
--
-- http://<hostname>/tor/keys/all
-- http://<hostname>/tor/keys/authority
-- http://<hostname>/tor/keys/fp/<F>
-- http://<hostname>/tor/keys/sk/<F>-<S>
CREATE TABLE authority_key_certificate(
    rowid                   INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256                  TEXT NOT NULL UNIQUE,
    kp_auth_id_rsa_sha1     TEXT NOT NULL,
    kp_auth_sign_rsa_sha1   TEXT NOT NULL,
    dir_key_expires         INTEGER NOT NULL,
    FOREIGN KEY(sha256) REFERENCES store(sha256),
    CHECK(GLOB('*[^0-9A-F]*', kp_auth_id_rsa_sha1) == 0),
    CHECK(GLOB('*[^0-9A-F]*', kp_auth_sign_rsa_sha1) == 0),
    CHECK(LENGTH(kp_auth_id_rsa_sha1) == 40),
    CHECK(LENGTH(kp_auth_sign_rsa_sha1) == 40),
    CHECK(dir_key_expires >= 0)

) STRICT;

-- Content addressable storage, storing all contents.
CREATE TABLE store(
    rowid   INTEGER PRIMARY KEY AUTOINCREMENT, -- hex uppercase
    sha256  TEXT NOT NULL UNIQUE,
    content BLOB NOT NULL,
    CHECK(GLOB('*[^0-9A-F]*', sha256) == 0),
    CHECK(LENGTH(sha256) == 64)
) STRICT;

-- Stores compressed network documents.
CREATE TABLE compressed_document(
    rowid               INTEGER PRIMARY KEY AUTOINCREMENT,
    algorithm           TEXT NOT NULL,
    identity_sha256     TEXT NOT NULL,
    compressed_sha256   TEXT NOT NULL,
    FOREIGN KEY(identity_sha256) REFERENCES store(sha256),
    FOREIGN KEY(compressed_sha256) REFERENCES store(sha256),
    UNIQUE(algorithm, identity_sha256)
) STRICT;

-- Stores the N:M cardinality of which router descriptors are contained in which
-- consensuses.
CREATE TABLE consensus_router_descriptor_member(
    consensus_rowid         INTEGER,
    router_descriptor_rowid INTEGER,
    PRIMARY KEY(consensus_rowid, router_descriptor_rowid),
    FOREIGN KEY(consensus_rowid) REFERENCES consensus(rowid),
    FOREIGN KEY(router_descriptor_rowid) REFERENCES router_descriptor(rowid)
) STRICT;

-- Stores which authority key signed which consensuses.
--
-- Required to implement the consensus retrieval by authority fingerprints as
-- well as the garbage collection of authority key certificates.
--
-- http://<hostname>/tor/status-vote/current/consensus-<FLAVOR>/<F1>+<F2>+<F3>
CREATE TABLE consensus_authority_voter(
    consensus_rowid INTEGER,
    authority_rowid INTEGER,
    PRIMARY KEY(consensus_rowid, authority_rowid),
    FOREIGN KEY(consensus_rowid) REFERENCES consensus(rowid),
    FOREIGN KEY(authority_rowid) REFERENCES authority_key_certificate(rowid)
) STRICT;

INSERT INTO arti_dirmirror_schema_version VALUES ('1');
"
);

/// Global options set in every connection.
const GLOBAL_OPTIONS: &str = sql!(
    "
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=1000;
"
);

/// Opens a database from disk, creating a [`Pool`] for it.
///
/// This function should be the entry point for all things requiring a database
/// handle, as this function prepares all necessary steps required for operating
/// on the database correctly, such as:
/// * Schema initialization.
/// * Schema upgrade.
/// * Setting connection specific settings.
///
/// # `SQLITE_BUSY` Caveat
///
/// There is a problem with the handling of `SQLITE_BUSY` when opening an
/// SQLite database.  In WAL, opening a database might acquire an exclusive lock
/// for a very short amount of time, in order to perform clean-up from previous
/// connections alongside other tasks for maintaining database integrity?  This
/// means, that opening multiple SQLite databases simultanously will result in
/// a busy error regardless of a busy handler, as setting a busy handler will
/// require an existing connection, something we are unable to obtain in the
/// first place.
///
/// In order to mitigate this issue, the recommended way in the SQLite community
/// is to simply ensure that database connections are opened sequentially,
/// by urging calling applications to just use a single [`Pool`] instance.
///
/// Testing this is hard unfortunately.
pub(crate) fn open<P: AsRef<Path>>(
    path: P,
) -> Result<Pool<SqliteConnectionManager>, DatabaseError> {
    let num_cores = std::thread::available_parallelism()
        .unwrap_or(NonZero::new(8).expect("8 == 0?"))
        .get() as u32;

    let manager = r2d2_sqlite::SqliteConnectionManager::file(&path);
    let pool = Pool::builder().max_size(num_cores).build(manager)?;

    rw_tx(&pool, |tx| {
        // Prepare the database, doing the following steps:
        // 1. Checking the database schema.
        // 2. Upgrading (in future) or initializing the database schema (if empty).

        let has_arti_dirmirror_schema_version = match tx.query_one(
            sql!(
                "
                SELECT name
                FROM sqlite_master
                  WHERE type = 'table'
                    AND name = 'arti_dirmirror_schema_version'
                "
            ),
            params![],
            |_| Ok(()),
        ) {
            Ok(()) => true,
            Err(rusqlite::Error::QueryReturnedNoRows) => false,
            Err(e) => return Err(DatabaseError::LowLevel(e)),
        };

        if has_arti_dirmirror_schema_version {
            let version = tx.query_one(
                sql!("SELECT version FROM arti_dirmirror_schema_version WHERE rowid = 1"),
                params![],
                |row| row.get::<_, String>(0),
            )?;

            match version.as_ref() {
                "1" => {}
                unknown => {
                    return Err(DatabaseError::IncompatibleSchema {
                        version: unknown.into(),
                    })
                }
            }
        } else {
            tx.execute_batch(V1_SCHEMA)?;
        }

        Ok::<_, DatabaseError>(())
    })??;

    Ok(pool)
}

/// Executes a closure `op` with a given read-only [`Transaction`].
///
/// The [`Transaction`] always gets rolled back the moment `op` returns.
///
/// The [`Transaction`] gets initialized with the global pragma options set.
///
/// **The closure shall not perform write operations!**
/// Not only do they get rolled back anyways, but upgrading the [`Transaction`]
/// from a read to a write transaction will lead to other simultanous write upgrades
/// to fail.  Unfortunately, there is no real programatic way to ensure this.
pub(crate) fn read_tx<U, F>(pool: &Pool<SqliteConnectionManager>, op: F) -> Result<U, DatabaseError>
where
    F: FnOnce(&Transaction<'_>) -> U,
{
    let mut conn = pool.get()?;
    conn.execute_batch(GLOBAL_OPTIONS)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let res = op(&tx);
    tx.rollback()?;
    Ok(res)
}

/// Executes a closure `op` with a given read-write [`Transaction`].
///
/// The [`Transaction`] always gets committed the moment `op` returns.
///
/// The [`Transaction`] gets initialized with the global pragma options set.
///
/// The [`Transaction`] gets created with [`TransactionBehavior::Immediate`],
/// meaning it will immediately exist as a write connection, retrying in the
/// case of a [`rusqlite::ErrorCode::DatabaseBusy`] until it failed after 1s.
pub(crate) fn rw_tx<U, F>(pool: &Pool<SqliteConnectionManager>, op: F) -> Result<U, DatabaseError>
where
    F: FnOnce(&Transaction<'_>) -> U,
{
    let mut conn = pool.get()?;
    conn.execute_batch(GLOBAL_OPTIONS)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Exclusive)?;
    let res = op(&tx);
    tx.commit()?;
    Ok(res)
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
    use std::{
        sync::{Arc, Once},
        time::Duration,
    };

    use rusqlite::Connection;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn open() {
        let db_dir = tempdir().unwrap();
        let db_path = db_dir.path().join("db");

        super::open(&db_path).unwrap();
        let conn = Connection::open(&db_path).unwrap();

        // Check if the version was initialized properly.
        let version = conn
            .query_one(
                "SELECT version FROM arti_dirmirror_schema_version WHERE rowid = 1",
                params![],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        assert_eq!(version, "1");

        // Set the version to something unknown.
        conn.execute(
            "UPDATE arti_dirmirror_schema_version SET version = 42",
            params![],
        )
        .unwrap();
        drop(conn);

        assert_eq!(
            super::open(&db_path).unwrap_err().to_string(),
            "incompatible schema version: 42"
        );
    }

    #[test]
    fn read_tx() {
        let db_dir = tempdir().unwrap();
        let db_path = db_dir.path().join("db");

        let pool = super::open(&db_path).unwrap();

        // Do a write transaction despite forbidden.
        super::read_tx(&pool, |tx| {
            tx.execute_batch("DELETE FROM arti_dirmirror_schema_version")
                .unwrap();
            let e = tx
                .query_one(
                    sql!("SELECT version FROM arti_dirmirror_schema_version"),
                    params![],
                    |row| row.get::<_, String>(0),
                )
                .unwrap_err();
            assert_eq!(e, rusqlite::Error::QueryReturnedNoRows);
        })
        .unwrap();

        // Normal check.
        let version: String = super::read_tx(&pool, |tx| {
            tx.query_one(
                sql!("SELECT version FROM arti_dirmirror_schema_version"),
                params![],
                |row| row.get(0),
            )
            .unwrap()
        })
        .unwrap();
        assert_eq!(version, "1");
    }

    #[test]
    fn rw_tx() {
        let db_dir = tempdir().unwrap();
        let db_path = db_dir.path().join("db");

        let pool = super::open(&db_path).unwrap();

        // Do a write transaction.
        super::rw_tx(&pool, |tx| {
            tx.execute_batch("DELETE FROM arti_dirmirror_schema_version")
                .unwrap();
        })
        .unwrap();

        // Check that it was deleted.
        super::read_tx(&pool, |tx| {
            let e = tx
                .query_one(
                    sql!("SELECT version FROM arti_dirmirror_schema_version"),
                    params![],
                    |row| row.get::<_, String>(0),
                )
                .unwrap_err();
            assert_eq!(e, rusqlite::Error::QueryReturnedNoRows);
        })
        .unwrap();
    }

    #[test]
    fn rw_tx_busy_timeout_working() {
        let db_dir = tempdir().unwrap();
        let db_path = db_dir.path().join("db");
        let writer_acquired = Arc::new(Once::new());
        let pool = super::open(db_path).unwrap();

        let t1 = std::thread::spawn({
            let pool = pool.clone();
            let writer_acquired = writer_acquired.clone();
            move || {
                super::rw_tx(&pool, move |_tx| {
                    println!("t1 acquired write lock");
                    writer_acquired.call_once(|| ());
                    std::thread::sleep(Duration::from_millis(500));
                    println!("t2 released write lock");
                })
            }
        });

        let t2 = std::thread::spawn(move || {
            println!("t2 waits for t1 to acquire write lock");
            writer_acquired.wait();
            println!("t2 realized that t1 has acquired write lock");

            super::rw_tx(&pool, move |_tx| {
                println!("t2 acquired write lock");
                std::thread::sleep(Duration::from_millis(500));
                println!("t2 released write lock");
            })
        });

        t1.join().unwrap().unwrap();
        t2.join().unwrap().unwrap();
    }

    #[test]
    fn rw_tx_busy_timeout_busy() {
        let db_dir = tempdir().unwrap();
        let db_path = db_dir.path().join("db");
        let writer_acquired = Arc::new(Once::new());
        let pool = super::open(db_path).unwrap();

        let t1 = std::thread::spawn({
            let pool = pool.clone();
            let writer_acquired = writer_acquired.clone();
            move || {
                super::rw_tx(&pool, move |_tx| {
                    println!("t1 acquired write lock");
                    writer_acquired.call_once(|| ());
                    std::thread::sleep(Duration::from_millis(1500));
                    println!("t2 released write lock");
                })
            }
        });

        let t2 = std::thread::spawn(move || {
            println!("t2 waits for t1 to acquire write lock");
            writer_acquired.wait();
            println!("t2 realized that t1 has acquired write lock");

            super::rw_tx(&pool, |_tx| unreachable!())
        });

        t1.join().unwrap().unwrap();
        assert_eq!(
            t2.join().unwrap().unwrap_err().to_string(),
            "low-level rusqlite error: database is locked"
        );
    }
}
