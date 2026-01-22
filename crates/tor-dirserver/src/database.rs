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

// TODO DIRMIRROR: This could benefit from methods by wrapping the pool into a
// custom type.

use std::{
    fmt::Display,
    io::{Cursor, Write},
    num::NonZero,
    ops::{Add, Sub},
    path::Path,
    time::{Duration, SystemTime},
};

use flate2::write::{DeflateEncoder, GzEncoder};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{
    named_params, params,
    types::{FromSql, FromSqlError, FromSqlResult, ToSqlOutput, ValueRef},
    ToSql, Transaction, TransactionBehavior,
};
use saturating_time::SaturatingTime;
use sha2::Digest;
use tor_error::into_internal;

use crate::err::DatabaseError;

/// The identifier for documents in the content-addressable cache.
///
/// Right now, this is a Sha256 hash, but this may change in future.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub(crate) struct DocumentId([u8; 32]);

impl DocumentId {
    /// Computes the [`DocumentId`] from arbitrary data.
    pub(crate) fn digest(data: &[u8]) -> Self {
        Self(sha2::Sha256::digest(data).into())
    }
}

impl Display for DocumentId {
    /// Formats the [`DocumentId`] in uppercase hexadecimal.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode_upper(self.0))
    }
}

impl FromSql for DocumentId {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        // We read the document id as a hexadecimal string from the database.
        // Afterwards, we convert it to binary data, which should succeed due
        // to database check constraints.  Finally, we verify the length to see
        // whether it actually constitutes a valid SHA256 checksum.
        let data: [u8; 32] = value
            .as_str()
            .map(hex::decode)?
            .map_err(|e| {
                FromSqlError::Other(Box::new(tor_error::internal!(
                    "non hex data in database? {e}"
                )))
            })?
            .try_into()
            .map_err(|_| {
                FromSqlError::Other(Box::new(tor_error::internal!(
                    "document id with invalid length in database?"
                )))
            })?;

        Ok(Self(data))
    }
}

impl ToSql for DocumentId {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        // Because Self is only constructed with FromSql and digest data, it is
        // safe to assume to be valid.  Even if not, database constraints will
        // catch us from inserting invalid data.
        Ok(ToSqlOutput::from(self.to_string()))
    }
}

impl PartialEq<&str> for DocumentId {
    fn eq(&self, other: &&str) -> bool {
        self.to_string() == other.to_uppercase()
    }
}

#[cfg(test)]
impl From<[u8; 32]> for DocumentId {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

/// The supported content encodings.
#[derive(Debug, Clone, Copy, PartialEq, strum::EnumString, strum::Display, strum::EnumIter)]
#[strum(serialize_all = "kebab-case", ascii_case_insensitive)]
pub(crate) enum ContentEncoding {
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

/// A wrapper around [`SystemTime`] with convenient features.
///
/// Please use this type throughout the crate internally, instead of
/// [`SystemTime`].
///
/// # Conversion
///
/// This type can be safely converted from and into a [`SystemTime`], because
/// it is just a wrapper type.
///
/// # Saturating Artihmetic
///
/// This type implements [`Add`] and [`Sub`] for [`Duration`] and [`Timestamp`]
/// ([`Sub`] only) using saturating artihmetic from the [`saturating_time`]
/// crate.  It means that addition and subtraction can be safely performed
/// without the potential risk of an unexpected panic, instead wrapping to
/// a local maximum/minimum or [`Duration::ZERO`] depending on the type.
///
/// Note that we don't provide a saturating version of [`Duration`], so addition
/// or substraction of two [`Duration`]s still needs care to avoid panics.
///
/// # SQLite Interaction
///
/// This type implements [`FromSql`] and [`ToSql`], making it convenient to
/// integrate into SQL statements, as the database schema represents timestamps
/// internally using a non-negative [`i64`] storing the seconds since the epoch.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub(crate) struct Timestamp(SystemTime);

impl From<SystemTime> for Timestamp {
    fn from(value: SystemTime) -> Self {
        Self(value)
    }
}

impl From<Timestamp> for SystemTime {
    fn from(value: Timestamp) -> Self {
        value.0
    }
}

impl Add<Duration> for Timestamp {
    type Output = Self;

    /// Performs a saturating addition wrapping to [`SystemTime::max_value()`].
    fn add(self, rhs: Duration) -> Self::Output {
        Self(self.0.saturating_add(rhs))
    }
}

impl Sub<Duration> for Timestamp {
    type Output = Self;

    /// Performs a saturating subtraction wrapping to [`SystemTime::min_value()`].
    fn sub(self, rhs: Duration) -> Self::Output {
        Self(self.0.saturating_sub(rhs))
    }
}

impl Sub<Timestamp> for Timestamp {
    type Output = Duration;

    /// Performs a saturating duration_since wrapping to [`Duration::ZERO`].
    fn sub(self, rhs: Timestamp) -> Self::Output {
        self.0.saturating_duration_since(rhs.0)
    }
}

impl FromSql for Timestamp {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let mut res = SystemTime::UNIX_EPOCH;
        res = res.saturating_add(Duration::from_secs(value.as_i64()?.try_into().unwrap_or(0)));
        Ok(Self(res))
    }
}

impl ToSql for Timestamp {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(
            self.0
                .saturating_duration_since(SystemTime::UNIX_EPOCH)
                .as_secs()
                .try_into()
                .unwrap_or(i64::MAX),
        ))
    }
}

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
const V1_SCHEMA: &str = sql!(
    "
-- Meta table to store the current schema version.
CREATE TABLE arti_dirserver_schema_version(
    version TEXT NOT NULL -- currently, always `1`
) STRICT;

-- Stores consensuses.
--
-- http://<hostname>/tor/status-vote/current/consensus-<FLAVOR>
-- http://<hostname>/tor/status-vote/current/consensus-<FLAVOR>/<F1>+<F2>+<F3>
-- http://<hostname>/tor/status-vote/current/consensus-<FLAVOR>/diff/<HASH>/<FPRLIST>
CREATE TABLE consensus(
    rowid               INTEGER PRIMARY KEY AUTOINCREMENT,
    docid               TEXT NOT NULL UNIQUE,
    -- Required for consensus diffs.
    -- https://spec.torproject.org/dir-spec/directory-cache-operation.html#diff-format
    unsigned_sha3_256   TEXT NOT NULL UNIQUE,
    flavor              TEXT NOT NULL,
    valid_after         INTEGER NOT NULL,
    fresh_until         INTEGER NOT NULL,
    valid_until         INTEGER NOT NULL,
    FOREIGN KEY(docid) REFERENCES store(docid),
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
    docid                   TEXT NOT NULL UNIQUE,
    old_consensus_rowid     INTEGER NOT NULL,
    new_consensus_rowid     INTEGER NOT NULL,
    FOREIGN KEY(docid) REFERENCES store(docid),
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
    docid                   TEXT NOT NULL UNIQUE,
    sha1                    TEXT NOT NULL UNIQUE,
    sha2                    TEXT NOT NULL UNIQUE,
    kp_relay_id_rsa_sha1    TEXT NOT NULL,
    flavor                  TEXT NOT NULL,
    router_extra_info_rowid  INTEGER,
    FOREIGN KEY(docid) REFERENCES store(docid),
    FOREIGN KEY(router_extra_info_rowid) REFERENCES router_extra_info(rowid),
    CHECK(GLOB('*[^0-9A-F]*', sha1) == 0),
    CHECK(GLOB('*[^0-9A-F]*', kp_relay_id_rsa_sha1) == 0),
    CHECK(LENGTH(sha1) == 40),
    CHECK(docid == sha2),
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
    docid                   TEXT NOT NULL UNIQUE,
    sha1                    TEXT NOT NULL UNIQUE,
    kp_relay_id_rsa_sha1    TEXT NOT NULL,
    FOREIGN KEY(docid) REFERENCES store(docid),
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
    docid                   TEXT NOT NULL UNIQUE,
    kp_auth_id_rsa_sha1     TEXT NOT NULL,
    kp_auth_sign_rsa_sha1   TEXT NOT NULL,
    dir_key_published       INTEGER NOT NULL,
    dir_key_expires         INTEGER NOT NULL,
    FOREIGN KEY(docid) REFERENCES store(docid),
    CHECK(GLOB('*[^0-9A-F]*', kp_auth_id_rsa_sha1) == 0),
    CHECK(GLOB('*[^0-9A-F]*', kp_auth_sign_rsa_sha1) == 0),
    CHECK(LENGTH(kp_auth_id_rsa_sha1) == 40),
    CHECK(LENGTH(kp_auth_sign_rsa_sha1) == 40),
    CHECK(dir_key_published >= 0),
    CHECK(dir_key_expires >= 0),
    CHECK(dir_key_published < dir_key_expires)

) STRICT;

-- Content addressable storage, storing all contents.
CREATE TABLE store(
    rowid   INTEGER PRIMARY KEY AUTOINCREMENT, -- hex uppercase
    docid   TEXT NOT NULL UNIQUE,
    content BLOB NOT NULL,
    CHECK(GLOB('*[^0-9A-F]*', docid) == 0),
    CHECK(LENGTH(docid) == 64)
) STRICT;

-- Stores compressed network documents.
CREATE TABLE compressed_document(
    rowid               INTEGER PRIMARY KEY AUTOINCREMENT,
    algorithm           TEXT NOT NULL,
    identity_docid      TEXT NOT NULL,
    compressed_docid   TEXT NOT NULL,
    FOREIGN KEY(identity_docid) REFERENCES store(docid),
    FOREIGN KEY(compressed_docid) REFERENCES store(docid),
    UNIQUE(algorithm, identity_docid)
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

INSERT INTO arti_dirserver_schema_version VALUES ('1');
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

        let has_arti_dirserver_schema_version = match tx.query_one(
            sql!(
                "
                SELECT name
                FROM sqlite_master
                  WHERE type = 'table'
                    AND name = 'arti_dirserver_schema_version'
                "
            ),
            params![],
            |_| Ok(()),
        ) {
            Ok(()) => true,
            Err(rusqlite::Error::QueryReturnedNoRows) => false,
            Err(e) => return Err(DatabaseError::LowLevel(e)),
        };

        if has_arti_dirserver_schema_version {
            let version = tx.query_one(
                sql!("SELECT version FROM arti_dirserver_schema_version WHERE rowid = 1"),
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

/// Inserts `data` into store while also compressing it with given encodings.
///
/// Returns the [`DocumentId`] of `data`.
///
/// This function inserts `data` into store and also compresses it into all
/// given compression formats.
///
/// Duplicates get re-encoded and replaced in the database, including
/// [`ContentEncoding::Identity`].
pub(crate) fn store_insert<I: Iterator<Item = ContentEncoding>>(
    tx: &Transaction,
    data: &[u8],
    encodings: I,
) -> Result<DocumentId, DatabaseError> {
    // The statement to insert some data into the store.
    //
    // Parameters:
    // :docid - The docid.
    // :content - The binary data.
    let mut store_stmt = tx.prepare_cached(sql!(
        "
        INSERT OR REPLACE INTO store (docid, content)
        VALUES
        (:docid, :content)
        "
    ))?;

    // The statement to insert a compressed document into the metatable.
    //
    // Parameters:
    // :algorithm - The name of the encoding algorithm.
    // :identity_docid - The docid of the plain-text document in the store.
    // :compressed_docid - The docid of the encoded document in the store.
    let mut compressed_stmt = tx.prepare_cached(sql!(
        "
        INSERT OR REPLACE INTO compressed_document (algorithm, identity_docid, compressed_docid)
        VALUES
        (:algorithm, :identity_docid, :compressed_docid)
        "
    ))?;

    // Insert the plain document into the store.
    let identity_docid = DocumentId::digest(data);
    store_stmt.execute(named_params! {
        ":docid": identity_docid,
        ":content": data
    })?;

    // Compress it into all formats and insert it into store and compressed.
    for encoding in encodings {
        if encoding == ContentEncoding::Identity {
            // Ignore identity because we inserted that above.
            continue;
        }

        // We map a compression error to a bug because there is no good reason
        // on why it should fail, given that we compress from memory data to
        // memory data.  Probably because it uses the std::io::Writer interface
        // which itself demands use of std::io::Result.
        let compressed = compress(data, encoding).map_err(into_internal!("{encoding} failed?"))?;
        let compressed_docid = DocumentId::digest(&compressed);
        store_stmt.execute(named_params! {
            ":docid": compressed_docid,
            ":content": compressed,
        })?;
        compressed_stmt.execute(named_params! {
            ":algorithm": encoding.to_string(),
            ":identity_docid": identity_docid,
            ":compressed_docid": compressed_docid,
        })?;
    }

    Ok(identity_docid)
}

/// Compresses `data` into a specified [`ContentEncoding`].
///
/// Returns a [`Vec`] containing the encoded data.
fn compress(data: &[u8], encoding: ContentEncoding) -> Result<Vec<u8>, std::io::Error> {
    match encoding {
        ContentEncoding::Identity => Ok(data.to_vec()),
        ContentEncoding::Deflate => {
            let mut w = DeflateEncoder::new(Vec::new(), Default::default());
            w.write_all(data)?;
            w.finish()
        }
        ContentEncoding::Gzip => {
            let mut w = GzEncoder::new(Vec::new(), Default::default());
            w.write_all(data)?;
            w.finish()
        }
        ContentEncoding::XZstd => zstd::encode_all(data, Default::default()),
        ContentEncoding::XTorLzma => {
            let mut res = Vec::new();
            lzma_rs::lzma_compress(&mut Cursor::new(data), &mut res)?;
            Ok(res)
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
    use std::{
        collections::HashSet,
        io::Read,
        sync::{Arc, Once},
    };

    use flate2::read::{DeflateDecoder, GzDecoder};
    use rusqlite::Connection;
    use strum::IntoEnumIterator;
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
                "SELECT version FROM arti_dirserver_schema_version WHERE rowid = 1",
                params![],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        assert_eq!(version, "1");

        // Set the version to something unknown.
        conn.execute(
            "UPDATE arti_dirserver_schema_version SET version = 42",
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
            tx.execute_batch("DELETE FROM arti_dirserver_schema_version")
                .unwrap();
            let e = tx
                .query_one(
                    sql!("SELECT version FROM arti_dirserver_schema_version"),
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
                sql!("SELECT version FROM arti_dirserver_schema_version"),
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
            tx.execute_batch("DELETE FROM arti_dirserver_schema_version")
                .unwrap();
        })
        .unwrap();

        // Check that it was deleted.
        super::read_tx(&pool, |tx| {
            let e = tx
                .query_one(
                    sql!("SELECT version FROM arti_dirserver_schema_version"),
                    params![],
                    |row| row.get::<_, String>(0),
                )
                .unwrap_err();
            assert_eq!(e, rusqlite::Error::QueryReturnedNoRows);
        })
        .unwrap();
    }

    /// Tests whether our SQLite busy error handling works in normal situations.
    ///
    /// A normal situations means a situation where a lock is never held for
    /// more than 1000ms.  In our case, we will work with two threads.
    /// t1 will acquire an exclusive lock and inform t2 about it.  t2 waits
    /// until t1 has acquired this lock and then immediately informs t1, that
    /// it will now wait for a lock too.  Now, t1 will immediately terminate,
    /// thereby releasing the lock and leading t2 to eventually acquire it.
    #[test]
    fn rw_tx_busy_timeout_working() {
        let db_dir = tempdir().unwrap();
        let db_path = db_dir.path().join("db");
        let pool = super::open(db_path).unwrap();

        // t2 will wait on this before it starts doing stuff.
        let t1_acquired_lock = Arc::new(Once::new());
        // t1 will wait on this in order to terminate properly.
        let t2_is_waiting = Arc::new(Once::new());

        let t1 = std::thread::spawn({
            let pool = pool.clone();
            let t1_acquired_lock = t1_acquired_lock.clone();
            let t2_is_waiting = t2_is_waiting.clone();
            move || {
                super::rw_tx(&pool, move |_tx| {
                    // Inform t2 we have write lock.
                    t1_acquired_lock.call_once(|| ());
                    println!("t1 acquired write lock");

                    // Wait for t2 to start waiting.
                    t2_is_waiting.wait();
                })
                .unwrap();
                println!("t2 released write lock");
            }
        });

        println!("t2 waits for t1 to acquire write lock");
        t1_acquired_lock.wait();
        t2_is_waiting.call_once(|| ());
        super::rw_tx(&pool, |_| ()).unwrap();
        println!("t2 acquired and released write lock");
        t1.join().unwrap();
    }

    /// Tests whether our SQLite busy error handlings fails as expected.
    ///
    /// We configure SQLite to fail after 1000ms.  This test works with two
    /// threads.  t1 will acquire an exclusive lock on the database and will
    /// inform t2 about it, which itself will wait until t1 has acquired the
    /// lock.  t2 will then immediately try to also obtain an exclusive lock,
    /// which should fail after about 1000ms.  After the failure, t2 informs
    /// t1 that it has failed, causing t1 to terminate.
    #[test]
    fn rw_tx_busy_timeout_busy() {
        let db_dir = tempdir().unwrap();
        let db_path = db_dir.path().join("db");
        let pool = super::open(db_path).unwrap();

        // t2 will wait on this before it starts doing stuff.
        let t1_acquired_lock = Arc::new(Once::new());
        // t1 will wait on this in order to terminate properly.
        let t2_gave_up = Arc::new(Once::new());

        let t1 = std::thread::spawn({
            let pool = pool.clone();
            let t1_acquired_lock = t1_acquired_lock.clone();
            let t2_gave_up = t2_gave_up.clone();

            move || {
                super::rw_tx(&pool, move |_tx| {
                    // Inform t2 we have the write lock.
                    t1_acquired_lock.call_once(|| ());
                    println!("t1 acquired write lock");
                    // Wait for t2 to give up before we release (how mean from us).
                    t2_gave_up.wait();
                })
                .unwrap();
                println!("t1 released write lock");
            }
        });

        println!("t2 waits for t1 to acquire write lock");
        t1_acquired_lock.wait();
        let e = super::rw_tx(&pool, |_| ()).unwrap_err();
        assert_eq!(
            e.to_string(),
            "low-level rusqlite error: database is locked"
        );
        println!("t2 gave up on acquiring write lock");
        t2_gave_up.call_once(|| ());
        t1.join().unwrap();
    }

    #[test]
    fn store_insert() {
        let db_dir = tempdir().unwrap();
        let db_path = db_dir.path().join("db");

        super::open(&db_path).unwrap();
        let mut conn = Connection::open(&db_path).unwrap();
        let tx = conn.transaction().unwrap();

        let docid = super::store_insert(&tx, "foobar".as_bytes(), ContentEncoding::iter()).unwrap();
        assert_eq!(
            docid,
            "C3AB8FF13720E8AD9047DD39466B3C8974E592C2FA383D4A3960714CAEF0C4F2"
        );

        let res = tx
            .query_one(
                sql!(
                    "
                    SELECT content
                    FROM store
                    WHERE docid = 'C3AB8FF13720E8AD9047DD39466B3C8974E592C2FA383D4A3960714CAEF0C4F2'
                    "
                ),
                params![],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .unwrap();
        assert_eq!(res, "foobar".as_bytes());

        let mut stmt = tx.prepare_cached(sql!(
            "
            SELECT algorithm
            FROM compressed_document
            WHERE identity_docid = 'C3AB8FF13720E8AD9047DD39466B3C8974E592C2FA383D4A3960714CAEF0C4F2'
            "
        )).unwrap();

        let algorithms = stmt
            .query_map(params![], |row| row.get::<_, String>(0))
            .unwrap();

        let algorithms = algorithms.map(|x| x.unwrap()).collect::<HashSet<_>>();
        assert_eq!(
            algorithms,
            HashSet::from([
                "deflate".to_string(),
                "gzip".to_string(),
                "x-zstd".to_string(),
                "x-tor-lzma".to_string()
            ])
        );

        // Now insert the same thing a second time again and see whether the
        // ON CONFLICT magic works.
        let docid_second =
            super::store_insert(&tx, "foobar".as_bytes(), ContentEncoding::iter()).unwrap();
        assert_eq!(docid, docid_second);

        // Remove a few compressed entries and get them again.
        let n = tx
            .execute(
                sql!(
                    "
                    DELETE FROM
                    compressed_document
                    WHERE algorithm IN ('deflate', 'x-zstd')
                    "
                ),
                params![],
            )
            .unwrap();
        assert_eq!(n, 2);

        let docid_third =
            super::store_insert(&tx, "foobar".as_bytes(), ContentEncoding::iter()).unwrap();
        assert_eq!(docid, docid_third);
        let algorithms = stmt
            .query_map(params![], |row| row.get::<_, String>(0))
            .unwrap();
        let algorithms = algorithms.map(|x| x.unwrap()).collect::<HashSet<_>>();
        assert_eq!(
            algorithms,
            HashSet::from([
                "deflate".to_string(),
                "gzip".to_string(),
                "x-zstd".to_string(),
                "x-tor-lzma".to_string()
            ])
        );
    }

    #[test]
    fn compress() {
        /// Asserts that `res` contains `encoding`.
        fn contains(encoding: ContentEncoding, res: &[(ContentEncoding, Vec<u8>)]) {
            assert!(res.iter().any(|x| x.0 == encoding));
        }

        const INPUT: &[u8] = "foobar".as_bytes();

        // Check whether everything was encoded.
        let res = ContentEncoding::iter()
            .map(|encoding| (encoding, super::compress(INPUT, encoding).unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(res.len(), 5);
        contains(ContentEncoding::Identity, &res);
        contains(ContentEncoding::Deflate, &res);
        contains(ContentEncoding::Gzip, &res);
        contains(ContentEncoding::XTorLzma, &res);
        contains(ContentEncoding::XZstd, &res);

        // Check if we can decode it.
        for (encoding, compressed) in res {
            let mut decompressed = Vec::new();

            match encoding {
                ContentEncoding::Identity => decompressed = compressed,
                ContentEncoding::Deflate => {
                    DeflateDecoder::new(Cursor::new(compressed))
                        .read_to_end(&mut decompressed)
                        .unwrap();
                }
                ContentEncoding::Gzip => {
                    GzDecoder::new(Cursor::new(compressed))
                        .read_to_end(&mut decompressed)
                        .unwrap();
                }
                ContentEncoding::XTorLzma => {
                    lzma_rs::lzma_decompress(&mut Cursor::new(compressed), &mut decompressed)
                        .unwrap();
                }
                ContentEncoding::XZstd => {
                    decompressed = zstd::decode_all(Cursor::new(compressed)).unwrap();
                }
            }

            assert_eq!(decompressed, INPUT);
        }
    }
}
