//! Access to the database schema.
//!
//! This module is not inteded to provide a high-level ORM, instead it serves
//! the purpose of initializing and upgrading the database, if necessary.

use std::path::PathBuf;

use deadpool::managed::{Pool, PoolError};
use deadpool_sqlite::{Config, Manager};
use rusqlite::params;
use tor_error::internal;

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
PRAGMA journal_mode=WAL;

BEGIN TRANSACTION;

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
    CHECK(LENGTH(kp_auth_sign_rsa_sha1) == 40)

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

COMMIT;
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
pub(crate) async fn open<P: Into<PathBuf>>(path: P) -> Result<Pool<Manager>, DatabaseError> {
    let pool = Config::new(path)
        .create_pool(deadpool::Runtime::Tokio1)
        .map_err(|e| internal!("pool creation failed?: {e}"))?;

    // Prepare the database, doing the following steps:
    // 1. Setting `foreign_keys=ON`.
    // 2. Checking the database schema.
    // 3. Upgrading (in future) or initializing the database schema (if empty).
    pool.get()
        .await
        .map_err(|e| match e {
            PoolError::Backend(e) => DatabaseError::LowLevel(e),
            PoolError::Closed => DatabaseError::Pool(PoolError::Closed),
            PoolError::NoRuntimeSpecified => DatabaseError::Pool(PoolError::NoRuntimeSpecified),
            PoolError::PostCreateHook(e) => {
                DatabaseError::Bug(internal!("post create hook error? {e}"))
            }
            PoolError::Timeout(e) => DatabaseError::Pool(PoolError::Timeout(e)),
        })?
        .interact(|conn| {
            // Set global pragmas.
            conn.execute("PRAGMA foreign_keys=ON", params![])?;

            let has_arti_dirmirror_schema_version = match conn.query_one(
                "
                    SELECT name
                    FROM sqlite_master
                    WHERE type = 'table' AND name = 'arti_dirmirror_schema_version'
                ",
                params![],
                |_| Ok(()),
            ) {
                Ok(()) => true,
                Err(rusqlite::Error::QueryReturnedNoRows) => false,
                Err(e) => return Err(DatabaseError::LowLevel(e)),
            };

            if has_arti_dirmirror_schema_version {
                let version = conn.query_one(
                    "SELECT version FROM arti_dirmirror_schema_version WHERE rowid = 1",
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
                conn.execute_batch(V1_SCHEMA)?;
            }

            Ok::<_, DatabaseError>(())
        })
        .await
        .map_err(|e| internal!("pool interaction failed?: {e}"))??;

    Ok(pool)
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
    use rusqlite::Connection;
    use tempfile::tempdir;

    use super::*;

    #[tokio::test]
    async fn open() {
        let db_dir = tempdir().unwrap();
        let db_path = db_dir.path().join("db");

        super::open(&db_path).await.unwrap();
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
            super::open(&db_path).await.unwrap_err().to_string(),
            "incompatible schema version: 42"
        );
    }
}
