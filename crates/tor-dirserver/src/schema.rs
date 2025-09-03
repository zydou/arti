//! Access to the database schema.
//!
//! This module is not inteded to provide a high-level ORM, instead it serves
//! the purpose of initializing and upgrading the database, if necessary.

use rusqlite::Connection;

use crate::err::DatabaseError;

/// Representation of a Sha256 hash in hexadecimal (upper-case)
// TODO: Make this a real type that actually enforces the constraints.
pub(crate) type Sha256 = String;

/// Version 1 of the database schema.
const V1_SCHEMA: &str = "
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
";

/// Prepares a database for operation that is, initializing and upgrading it
/// if neccessary.
///
/// This function also enables the `PRAGMA foreign_keys=ON` because it is,
/// unfortuantely, connection specific.
pub(crate) fn prepare_db(conn: &mut Connection) -> Result<(), DatabaseError> {
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;

    let schema_version = init_db(conn)?;
    match schema_version.as_str() {
        "1" => Ok(()),
        _ => Err(DatabaseError::IncompatibleSchema(schema_version)),
    }
}

/// Initializes the database schema if the database is not already initialized.
///
/// Always returns database schema version.
fn init_db(conn: &mut Connection) -> Result<String, DatabaseError> {
    // TODO DIRMIRROR: The error handling here is quite poor.
    let version: Option<String> = conn
        .query_one(
            "SELECT version FROM arti_dirmirror_schema_version WHERE rowid = 1",
            [],
            |row| row.get(0),
        )
        .ok();

    if let Some(v) = version {
        Ok(v)
    } else {
        // Initialize the database schema.
        conn.execute_batch(V1_SCHEMA)?;
        Ok(String::from("1"))
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
    use super::*;

    use deadpool_sqlite::Config;

    #[tokio::test]
    async fn schema() {
        // Create the database connection.
        let pool = Config::new("")
            .create_pool(deadpool::Runtime::Tokio1)
            .unwrap();

        // Initialize the database.
        pool.get()
            .await
            .unwrap()
            .interact(prepare_db)
            .await
            .unwrap()
            .unwrap();

        // Initialize the database again (no-op).
        pool.get()
            .await
            .unwrap()
            .interact(prepare_db)
            .await
            .unwrap()
            .unwrap();

        // Initialize it again to get the schema version.
        let schema_version = pool
            .get()
            .await
            .unwrap()
            .interact(init_db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(schema_version, "1");

        // Modify the schema version to trigger an error.
        pool.get()
            .await
            .unwrap()
            .interact(|conn| {
                conn.execute_batch("UPDATE arti_dirmirror_schema_version SET version = 42;")
            })
            .await
            .unwrap()
            .unwrap();

        // Initialize again and get an error.
        let err = pool
            .get()
            .await
            .unwrap()
            .interact(prepare_db)
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(err.to_string(), "unrecognized schema version: 42");
    }
}
