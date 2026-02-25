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
    CHECK(flavor IN ('ns', 'microdesc')),
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
    extra_unsigned_sha1     TEXT,
    FOREIGN KEY(docid) REFERENCES store(docid),
    CHECK(GLOB('*[^0-9A-F]*', unsigned_sha1) == 0),
    CHECK(GLOB('*[^0-9A-F]*', unsigned_sha2) == 0),
    CHECK(GLOB('*[^0-9A-F]*', kp_relay_id_rsa_sha1) == 0),
    CHECK(GLOB('*[^0-9A-F]*', extra_unsigned_sha1) == 0),
    CHECK(LENGTH(unsigned_sha1) == 40),
    CHECK(LENGTH(unsigned_sha2) == 64),
    CHECK(LENGTH(kp_relay_id_rsa_sha1) == 40),
    CHECK(LENGTH(extra_unsigned_sha1) == 40)
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
    unsigned_sha1           TEXT NOT NULL UNIQUE,
    kp_relay_id_rsa_sha1    TEXT NOT NULL,
    FOREIGN KEY(docid) REFERENCES store(docid),
    CHECK(GLOB('*[^0-9A-F]*', unsigned_sha1) == 0),
    CHECK(GLOB('*[^0-9A-F]*', kp_relay_id_rsa_sha1) == 0),
    CHECK(LENGTH(unsigned_sha1) == 40),
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
