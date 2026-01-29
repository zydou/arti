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

use digest::Digest;
use flate2::write::{DeflateEncoder, GzEncoder};
use getset::CopyGetters;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rand::Rng;
use rusqlite::{
    named_params, params,
    types::{FromSql, FromSqlError, FromSqlResult, ToSqlOutput, ValueRef},
    OptionalExtension, ToSql, Transaction, TransactionBehavior,
};
use saturating_time::SaturatingTime;
use tor_basic_utils::RngExt;
use tor_dircommon::config::DirTolerance;
use tor_error::into_internal;
use tor_netdoc::doc::{authcert::AuthCertKeyIds, netstatus::ConsensusFlavor};

use crate::err::DatabaseError;

/// Version 1 of the database schema.
///
/// TODO DIRMIRROR: Before the release, figure out where to use rowid and where
/// to use docid.
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
    unsigned_sha1           TEXT NOT NULL UNIQUE,
    unsigned_sha2           TEXT NOT NULL UNIQUE,
    kp_relay_id_rsa_sha1    TEXT NOT NULL,
    flavor                  TEXT NOT NULL,
    router_extra_info_sha1  TEXT,
    FOREIGN KEY(docid) REFERENCES store(docid),
    CHECK(GLOB('*[^0-9A-F]*', unsigned_sha1) == 0),
    CHECK(GLOB('*[^0-9A-F]*', unsigned_sha2) == 0),
    CHECK(GLOB('*[^0-9A-F]*', kp_relay_id_rsa_sha1) == 0),
    CHECK(GLOB('*[^0-9A-F]*', router_extra_info_sha1) == 0),
    CHECK(LENGTH(unsigned_sha1) == 40),
    CHECK(LENGTH(unsigned_sha2) == 64),
    CHECK(LENGTH(kp_relay_id_rsa_sha1) == 40),
    CHECK(LENGTH(router_extra_info_sha1) == 40),
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
    consensus_docid         TEXT NOT NULL,
    unsigned_sha1           TEXT NOT NULL,
    unsigned_sha2           TEXT NOT NULL,
    PRIMARY KEY(consensus_docid, unsigned_sha1, unsigned_sha2),
    FOREIGN KEY(consensus_docid) REFERENCES consensus(docid),
    CHECK(GLOB('*[^0-9A-F]*', unsigned_sha1) == 0),
    CHECK(GLOB('*[^0-9A-F]*', unsigned_sha2) == 0),
    CHECK(LENGTH(unsigned_sha1) == 40),
    CHECK(LENGTH(unsigned_sha2) == 64)
) STRICT;

-- Stores which authority key signed which consensuses.
--
-- Required to implement the consensus retrieval by authority fingerprints as
-- well as the garbage collection of authority key certificates.
--
-- http://<hostname>/tor/status-vote/current/consensus-<FLAVOR>/<F1>+<F2>+<F3>
CREATE TABLE consensus_authority_voter(
    consensus_docid TEXT,
    authority_docid TEXT,
    PRIMARY KEY(consensus_docid, authority_docid),
    FOREIGN KEY(consensus_docid) REFERENCES consensus(docid),
    FOREIGN KEY(authority_docid) REFERENCES authority_key_certificate(docid)
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

/// Convience macro for implementing a hash type in a rusqlite compatible fashion.
macro_rules! impl_hash_wrapper {
    ($name:ident, $algo:ty, $size:literal) => {
        /// Database wrapper type for [`$algo`].
        #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
        pub(crate) struct $name([u8; $size]);

        impl $name {
            /// Computes the [`$name`] from arbitrary data.
            pub(crate) fn digest(data: &[u8]) -> Self {
                Self(<$algo>::digest(data).into())
            }
        }

        impl Display for $name {
            /// Formats the [`$name`] in uppercase hexadecimal.
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", hex::encode_upper(self.0))
            }
        }

        impl FromSql for $name {
            fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
                // We read the hash as a hexadecimal string from the database.
                // Convert it to binary data and check length afterwards.
                let data: [u8; $size] = value
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
                            "$name with invalid length in database?"
                        )))
                    })?;

                Ok(Self(data))
            }
        }

        impl ToSql for $name {
            fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
                // Because Self is only constructed with FromSql and digest
                // data, it is safe to assume it is valid.
                Ok(ToSqlOutput::from(self.to_string()))
            }
        }

        impl PartialEq<&str> for $name {
            fn eq(&self, other: &&str) -> bool {
                self.to_string() == other.to_uppercase()
            }
        }

        #[cfg(test)]
        impl From<[u8; $size]> for $name {
            fn from(value: [u8; $size]) -> Self {
                Self(value)
            }
        }
    };
}

impl_hash_wrapper!(Sha1, sha1::Sha1, 20);
impl_hash_wrapper!(Sha256, sha2::Sha256, 32);
impl_hash_wrapper!(Sha3_256, sha3::Sha3_256, 32);

/// The identifier for documents in the content-addressable cache.
///
/// Right now, this is a [`Sha256`] hash, but this may change in future.
pub(crate) type DocumentId = Sha256;

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

/// Representation of consensus metadata from the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CopyGetters)]
#[get_copy = "pub(crate)"]
pub(crate) struct ConsensusMeta {
    /// The document id uniquely identifying the consensus.
    docid: DocumentId,

    /// The SHA3 of the unsigned part of the consensus.
    unsigned_sha3_256: Sha3_256,

    /// The flavor of the consensus.
    flavor: ConsensusFlavor,

    /// The time after which this consensus is valid.
    valid_after: Timestamp,

    /// The time after which this consensus stops being fresh.
    fresh_until: Timestamp,

    /// The time after which this consensus stops being valid.
    valid_until: Timestamp,
}

impl ConsensusMeta {
    /// Obtains the most recent valid consensus from the database.
    ///
    /// This function queries the database using a [`Transaction`] in order to
    /// have a consistent view upon it.  It will return an [`Option`] containing
    /// a [`Consensus`].  In order to obtain a *valid* consensus, a [`Timestamp`]
    /// plus a [`DirTolerance`] are supplied, which will be used for querying
    /// the database in a time-constrained fashion.
    ///
    /// The [`None`] case implies that no valid consensus has been found, that
    /// is, no consensus at all or no consensus whose `valid-before` or
    /// `valid-after` lies within the range composed by `now` and `tolerance`.
    pub(crate) fn query_recent(
        tx: &Transaction,
        flavor: ConsensusFlavor,
        tolerance: &DirTolerance,
        now: Timestamp,
    ) -> Result<Option<Self>, DatabaseError> {
        // Select the most recent flavored consensus document from the database.
        //
        // The `valid_after` and `valid_until` cells must be a member of the range:
        // `[valid_after - pre_valid_tolerance; valid_after + post_valid_tolerance]`
        // (inclusively).
        let mut meta_stmt = tx.prepare_cached(sql!(
            "
            SELECT docid, unsigned_sha3_256, valid_after, fresh_until, valid_until
            FROM consensus
            WHERE
              flavor = :flavor
              AND :now >= valid_after - :pre_valid
              AND :now <= valid_until + :post_valid
            ORDER BY valid_after DESC
            LIMIT 1
            "
        ))?;

        // Actually execute the query; a None is totally valid and considered as
        // no consensus being present in the current database.
        let res = meta_stmt.query_one(named_params! {
            ":flavor": flavor.name(),
            ":now": now,
            ":pre_valid": tolerance.pre_valid_tolerance().as_secs().try_into().unwrap_or(i64::MAX),
            ":post_valid": tolerance.post_valid_tolerance().as_secs().try_into().unwrap_or(i64::MAX),
        }, |row| {
            Ok(Self {
                docid: row.get(0)?,
                unsigned_sha3_256: row.get(1)?,
                flavor,
                valid_after: row.get(2)?,
                fresh_until: row.get(3)?,
                valid_until: row.get(4)?,
            })
        }).optional()?;

        Ok(res)
    }

    /// Queries the raw data of a [`ConsensusMeta`].
    pub(crate) fn data(&self, tx: &Transaction<'_>) -> Result<String, DatabaseError> {
        let mut stmt = tx.prepare_cached(sql!(
            "
            SELECT content
            FROM store
            WHERE docid = :docid
            "
        ))?;

        let raw = stmt.query_one(named_params! {":docid": self.docid}, |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        let raw = String::from_utf8(raw).map_err(into_internal!("utf-8 constraint violated?"))?;
        Ok(raw)
    }

    /// Calculates the [`Timestamp`] at which the authorities will be queried again.
    ///
    /// # Specifications
    ///
    /// * <https://spec.torproject.org/dir-spec/directory-cache-operation.html#download-ns-from-auth>
    pub(crate) fn lifetime<R: Rng>(&self, rng: &mut R) -> Timestamp {
        assert!(self.fresh_until < self.valid_until);

        let offset = rng
            .gen_range_checked(0..=((self.valid_until - self.fresh_until).as_secs() / 2))
            .expect("invalid range?");

        self.fresh_until + Duration::from_secs(offset)
    }
}

/// Representation of authority certificate metadata from the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CopyGetters)]
#[get_copy = "pub(crate)"]
pub(crate) struct AuthCertMeta {
    /// The document id uniquely identifying the consensus.
    docid: DocumentId,

    /// The SHA-1 fingerprint of the identity key.
    kp_auth_id_rsa_sha1: Sha1,

    /// The SHA-1 fingerprint of the signign key.
    kp_auth_sign_rsa_sha1: Sha1,

    /// The timestamp after which this certificate will be valid.
    dir_key_published: Timestamp,

    /// The timestamp until this certificate will be valid.
    dir_key_expires: Timestamp,
}

impl AuthCertMeta {
    /// Obtain the most recently published and valid certificate for each authority.
    ///
    /// Returns the found [`AuthCertMeta`] items as well as the missing
    /// [`AuthCertKeyIds`].
    ///
    /// # Performance
    ///
    /// This function has a performance between `O(n * log n)` and `O(n^2)`
    /// because it performs `signatories.len()` database queries, with each
    /// database query potentially taking something between `O(log n)` to
    /// `O(n)` to execute.  However, given that this respective value is
    /// oftentimes fairly small, it should not be much of a big concern.
    pub(crate) fn query_recent(
        tx: &Transaction,
        signatories: &[AuthCertKeyIds],
        tolerance: &DirTolerance,
        now: Timestamp,
    ) -> Result<(Vec<Self>, Vec<AuthCertKeyIds>), DatabaseError> {
        // For every key pair in `signatories`, get the most recent valid cert.
        //
        // This query selects the most recent timestamp valid certificate from
        // the database for a single given key pair.  It means that this query
        // has to be executed as many times as there are entires in
        // `signatories`.
        //
        // Unfortunately, there is no neater way to do this, because the
        // alternative would involve using a nested set which SQLite does not
        // support, even with the carray extension.  An alternative might be to
        // precompute that string and then insert it here using `format!` but
        // that feels hacky, error- and injection-prone.
        //
        // Parameters:
        // :id_rsa: The RSA identity key fingerprint in uppercase hexadecimal.
        // :sk_rsa: The RSA signing key fingerprint in uppercase hexadecimal.
        // :now: The current system timestamp.
        // :pre_tolerance: The tolerance for not-yet-valid certificates.
        // :post_tolerance: The tolerance for expired certificates.
        let mut stmt = tx.prepare_cached(sql!(
            "
            SELECT docid, kp_auth_id_rsa_sha1, kp_auth_sign_rsa_sha1,
              dir_key_published, dir_key_expires
            FROM authority_key_certificate
            WHERE
              (:id_rsa, :sk_rsa) = (kp_auth_id_rsa_sha1, kp_auth_sign_rsa_sha1)
              AND :now >= dir_key_published - :pre_tolerance
              AND :now <= dir_key_expires + :post_tolerance
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
            let res = stmt
            .query_one(
                named_params! {
                    ":id_rsa": kp.id_fingerprint.as_hex_upper(),
                    ":sk_rsa": kp.sk_fingerprint.as_hex_upper(),
                    ":now": now,
                    ":pre_tolerance": tolerance.pre_valid_tolerance().as_secs().try_into().unwrap_or(i64::MAX),
                    ":post_tolerance": tolerance.post_valid_tolerance().as_secs().try_into().unwrap_or(i64::MAX),
                },
                |row| Ok(Self {
                    docid: row.get(0)?,
                    kp_auth_id_rsa_sha1: row.get(1)?,
                    kp_auth_sign_rsa_sha1: row.get(2)?,
                    dir_key_published: row.get(3)?,
                    dir_key_expires: row.get(4)?,
                })
            )
            .optional()?;

            match res {
                Some(cert) => found.push(cert),
                None => missing.push(*kp),
            }
        }

        Ok((found, missing))
    }

    /// Queries the raw data of an [`AuthCertMeta`].
    pub(crate) fn data(&self, tx: &Transaction<'_>) -> Result<String, DatabaseError> {
        let mut stmt = tx.prepare_cached(sql!(
            "
            SELECT content
            FROM store
            WHERE docid = :docid
            "
        ))?;

        let raw = stmt.query_one(named_params! {":docid": self.docid}, |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        let raw = String::from_utf8(raw).map_err(into_internal!("utf-8 constraint violated?"))?;
        Ok(raw)
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
    use lazy_static::lazy_static;
    use rusqlite::Connection;
    use strum::IntoEnumIterator;
    use tempfile::tempdir;
    use tor_basic_utils::test_rng::testing_rng;
    use tor_dircommon::config::DirToleranceBuilder;
    use tor_llcrypto::pk::rsa::RsaIdentity;

    use super::*;

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
    const CERT_CONTENT: &[u8] = include_bytes!("../testdata/authcert-longclaw");

    lazy_static! {
        static ref CONSENSUS_DOCID: DocumentId = DocumentId::digest(CONSENSUS_CONTENT.as_bytes());
        static ref CERT_DOCID: DocumentId = DocumentId::digest(CERT_CONTENT);
    }

    fn create_dummy_db() -> Pool<SqliteConnectionManager> {
        let pool = open("").unwrap();
        rw_tx(&pool, |tx| {
            tx.execute(
                sql!("INSERT INTO store (docid, content) VALUES (?1, ?2)"),
                params![*CONSENSUS_DOCID, CONSENSUS_CONTENT.as_bytes()],
            )
            .unwrap();

            tx.execute(
                sql!("INSERT INTO store (docid, content) VALUES (?1, ?2)"),
                params![*CERT_DOCID, CERT_CONTENT],
            )
            .unwrap();

            tx.execute(
                sql!(
                    "
                    INSERT INTO consensus
                    (docid, unsigned_sha3_256, flavor, valid_after, fresh_until, valid_until)
                    VALUES
                    (?1, ?2, ?3, ?4, ?5, ?6)
                    "
                ),
                params![
                    *CONSENSUS_DOCID,
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
    fn open_test() {
        let db_dir = tempdir().unwrap();
        let db_path = db_dir.path().join("db");

        open(&db_path).unwrap();
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
            open(&db_path).unwrap_err().to_string(),
            "incompatible schema version: 42"
        );
    }

    #[test]
    fn read_tx_test() {
        let db_dir = tempdir().unwrap();
        let db_path = db_dir.path().join("db");

        let pool = open(&db_path).unwrap();

        // Do a write transaction despite forbidden.
        read_tx(&pool, |tx| {
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
        let version: String = read_tx(&pool, |tx| {
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
    fn rw_tx_test() {
        let db_dir = tempdir().unwrap();
        let db_path = db_dir.path().join("db");

        let pool = open(&db_path).unwrap();

        // Do a write transaction.
        rw_tx(&pool, |tx| {
            tx.execute_batch("DELETE FROM arti_dirserver_schema_version")
                .unwrap();
        })
        .unwrap();

        // Check that it was deleted.
        read_tx(&pool, |tx| {
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
        let pool = open(db_path).unwrap();

        // t2 will wait on this before it starts doing stuff.
        let t1_acquired_lock = Arc::new(Once::new());
        // t1 will wait on this in order to terminate properly.
        let t2_is_waiting = Arc::new(Once::new());

        let t1 = std::thread::spawn({
            let pool = pool.clone();
            let t1_acquired_lock = t1_acquired_lock.clone();
            let t2_is_waiting = t2_is_waiting.clone();
            move || {
                rw_tx(&pool, move |_tx| {
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
        rw_tx(&pool, |_| ()).unwrap();
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
        let pool = open(db_path).unwrap();

        // t2 will wait on this before it starts doing stuff.
        let t1_acquired_lock = Arc::new(Once::new());
        // t1 will wait on this in order to terminate properly.
        let t2_gave_up = Arc::new(Once::new());

        let t1 = std::thread::spawn({
            let pool = pool.clone();
            let t1_acquired_lock = t1_acquired_lock.clone();
            let t2_gave_up = t2_gave_up.clone();

            move || {
                rw_tx(&pool, move |_tx| {
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
        let e = rw_tx(&pool, |_| ()).unwrap_err();
        assert_eq!(
            e.to_string(),
            "low-level rusqlite error: database is locked"
        );
        println!("t2 gave up on acquiring write lock");
        t2_gave_up.call_once(|| ());
        t1.join().unwrap();
    }

    #[test]
    fn store_insert_test() {
        let db_dir = tempdir().unwrap();
        let db_path = db_dir.path().join("db");

        open(&db_path).unwrap();
        let mut conn = Connection::open(&db_path).unwrap();
        let tx = conn.transaction().unwrap();

        let docid = store_insert(&tx, "foobar".as_bytes(), ContentEncoding::iter()).unwrap();
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
        let docid_second = store_insert(&tx, "foobar".as_bytes(), ContentEncoding::iter()).unwrap();
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

        let docid_third = store_insert(&tx, "foobar".as_bytes(), ContentEncoding::iter()).unwrap();
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
    fn compress_test() {
        /// Asserts that `res` contains `encoding`.
        fn contains(encoding: ContentEncoding, res: &[(ContentEncoding, Vec<u8>)]) {
            assert!(res.iter().any(|x| x.0 == encoding));
        }

        const INPUT: &[u8] = "foobar".as_bytes();

        // Check whether everything was encoded.
        let res = ContentEncoding::iter()
            .map(|encoding| (encoding, compress(INPUT, encoding).unwrap()))
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

        read_tx(&pool, move |tx| {
            // Get None by being way before valid-after.
            assert!(ConsensusMeta::query_recent(
                tx,
                ConsensusFlavor::Plain,
                &no_tolerance,
                SystemTime::UNIX_EPOCH.into(),
            )
            .unwrap()
            .is_none());

            // Get None by being way behind valid-until.
            assert!(ConsensusMeta::query_recent(
                tx,
                ConsensusFlavor::Plain,
                &no_tolerance,
                *VALID_UNTIL + Duration::from_secs(60 * 60 * 24 * 365),
            )
            .unwrap()
            .is_none());

            // Get None by being minimally before valid-after.
            assert!(ConsensusMeta::query_recent(
                tx,
                ConsensusFlavor::Plain,
                &no_tolerance,
                *VALID_AFTER - Duration::from_secs(1),
            )
            .unwrap()
            .is_none());

            // Get None by being minimally behind valid-until.
            assert!(ConsensusMeta::query_recent(
                tx,
                ConsensusFlavor::Plain,
                &no_tolerance,
                *VALID_UNTIL + Duration::from_secs(1),
            )
            .unwrap()
            .is_none());

            // Get a valid consensus by being in the interval.
            let res1 = ConsensusMeta::query_recent(
                tx,
                ConsensusFlavor::Plain,
                &no_tolerance,
                *VALID_AFTER,
            )
            .unwrap()
            .unwrap();
            let res2 = ConsensusMeta::query_recent(
                tx,
                ConsensusFlavor::Plain,
                &no_tolerance,
                *VALID_UNTIL,
            )
            .unwrap()
            .unwrap();
            let res3 = ConsensusMeta::query_recent(
                tx,
                ConsensusFlavor::Plain,
                &no_tolerance,
                *VALID_AFTER + Duration::from_secs(60 * 30),
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                res1,
                ConsensusMeta {
                    docid: *CONSENSUS_DOCID,
                    unsigned_sha3_256: Sha3_256::from([0; 32]),
                    flavor: ConsensusFlavor::Plain,
                    valid_after: *VALID_AFTER,
                    fresh_until: *FRESH_UNTIL,
                    valid_until: *VALID_UNTIL,
                }
            );
            assert_eq!(res1, res2);
            assert_eq!(res2, res3);

            // Get a valid consensus using a liberal dir tolerance.
            let res1 = ConsensusMeta::query_recent(
                tx,
                ConsensusFlavor::Plain,
                &liberal_tolerance,
                *VALID_AFTER - Duration::from_secs(60 * 30),
            )
            .unwrap()
            .unwrap();
            let res2 = ConsensusMeta::query_recent(
                tx,
                ConsensusFlavor::Plain,
                &liberal_tolerance,
                *VALID_UNTIL + Duration::from_secs(60 * 30),
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                res1,
                ConsensusMeta {
                    docid: *CONSENSUS_DOCID,
                    unsigned_sha3_256: Sha3_256::from([0; 32]),
                    flavor: ConsensusFlavor::Plain,
                    valid_after: *VALID_AFTER,
                    fresh_until: *FRESH_UNTIL,
                    valid_until: *VALID_UNTIL,
                }
            );
            assert_eq!(res1, res2);
        })
        .unwrap();
    }

    #[test]
    fn sync_timeout() {
        // We repeat the tests a few thousand times to go over many random values.
        let cons = ConsensusMeta {
            docid: *CONSENSUS_DOCID,
            unsigned_sha3_256: Sha3_256::from([0; 32]),
            flavor: ConsensusFlavor::Plain,
            valid_after: *VALID_AFTER,
            fresh_until: *FRESH_UNTIL,
            valid_until: *VALID_UNTIL,
        };
        for _ in 0..10000 {
            let when = cons.lifetime(&mut testing_rng());
            assert!(when >= *FRESH_UNTIL);
            assert!(when <= *FRESH_UNTIL_HALF);
        }
    }

    #[test]
    fn get_auth_cert() {
        let pool = create_dummy_db();

        // Empty.
        let (found, missing) = read_tx(&pool, |tx| {
            AuthCertMeta::query_recent(
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
        let (found, missing) = read_tx(&pool, |tx| {
            AuthCertMeta::query_recent(
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
        assert_eq!(
            found,
            vec![AuthCertMeta {
                docid: DocumentId::digest(CERT_CONTENT),
                kp_auth_id_rsa_sha1: Sha1::from([
                    73, 1, 95, 120, 116, 51, 16, 53, 128, 227, 182, 106, 23, 7, 160, 14, 96, 242,
                    209, 91
                ]),
                kp_auth_sign_rsa_sha1: Sha1::from([
                    197, 209, 83, 166, 240, 218, 124, 194, 34, 119, 210, 41, 220, 187, 249, 41,
                    208, 88, 159, 224
                ]),
                dir_key_published: (SystemTime::UNIX_EPOCH + Duration::from_secs(1764543578))
                    .into(),
                dir_key_expires: (SystemTime::UNIX_EPOCH + Duration::from_secs(1772492378)).into()
            }]
        );
        assert_eq!(
            missing,
            vec![
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
                AuthCertKeyIds {
                    id_fingerprint: RsaIdentity::from_hex(
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                    )
                    .unwrap(),
                    sk_fingerprint: RsaIdentity::from_hex(
                        "0000000000000000000000000000000000000000",
                    )
                    .unwrap(),
                }
            ]
        );
    }
}
