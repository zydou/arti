//! Net document storage backed by sqlite3.
//!
//! We store most objects in sqlite tables, except for very large ones,
//! which we store as "blob" files in a separate directory.

use super::ExpirationConfig;
use crate::docmeta::{AuthCertMeta, ConsensusMeta};
use crate::err::ReadOnlyStorageError;
use crate::storage::{InputString, Store};
use crate::{Error, Result};

use fs_mistrust::CheckedDir;
use tor_basic_utils::PathExt as _;
use tor_error::warn_report;
use tor_netdoc::doc::authcert::AuthCertKeyIds;
use tor_netdoc::doc::microdesc::MdDigest;
use tor_netdoc::doc::netstatus::{ConsensusFlavor, Lifetime};
#[cfg(feature = "routerdesc")]
use tor_netdoc::doc::routerdesc::RdDigest;

#[cfg(feature = "bridge-client")]
pub(crate) use {crate::storage::CachedBridgeDescriptor, tor_guardmgr::bridge::BridgeConfig};

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use rusqlite::{params, OpenFlags, OptionalExtension, Transaction};
use time::OffsetDateTime;
use tracing::{trace, warn};

/// Local directory cache using a Sqlite3 connection.
pub(crate) struct SqliteStore {
    /// Connection to the sqlite3 database.
    conn: rusqlite::Connection,
    /// Location for the sqlite3 database; used to reopen it.
    sql_path: Option<PathBuf>,
    /// Location to store blob files.
    blob_dir: CheckedDir,
    /// Lockfile to prevent concurrent write attempts from different
    /// processes.
    ///
    /// If this is None we aren't using a lockfile.  Watch out!
    ///
    /// (sqlite supports that with connection locking, but we want to
    /// be a little more coarse-grained here)
    lockfile: Option<fslock::LockFile>,
}

impl SqliteStore {
    /// Construct or open a new SqliteStore at some location on disk.
    /// The provided location must be a directory, or a possible
    /// location for a directory: the directory will be created if
    /// necessary.
    ///
    /// If readonly is true, the result will be a read-only store.
    /// Otherwise, when readonly is false, the result may be
    /// read-only or read-write, depending on whether we can acquire
    /// the lock.
    ///
    /// # Limitations:
    ///
    /// The file locking that we use to ensure that only one dirmgr is
    /// writing to a given storage directory at a time is currently
    /// _per process_. Therefore, you might get unexpected results if
    /// two SqliteStores are created in the same process with the
    /// path.
    pub(crate) fn from_path_and_mistrust<P: AsRef<Path>>(
        path: P,
        mistrust: &fs_mistrust::Mistrust,
        mut readonly: bool,
    ) -> Result<Self> {
        let path = path.as_ref();
        let sqlpath = path.join("dir.sqlite3");
        let blobpath = path.join("dir_blobs/");
        let lockpath = path.join("dir.lock");

        let verifier = mistrust.verifier().permit_readable().check_content();

        let blob_dir = if readonly {
            verifier.secure_dir(blobpath)?
        } else {
            verifier.make_secure_dir(blobpath)?
        };

        // Check permissions on the sqlite and lock files; don't require them to
        // exist.
        for p in [&lockpath, &sqlpath] {
            match mistrust
                .verifier()
                .permit_readable()
                .require_file()
                .check(p)
            {
                Ok(()) | Err(fs_mistrust::Error::NotFound(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }

        let mut lockfile = fslock::LockFile::open(&lockpath).map_err(Error::from_lockfile)?;
        if !readonly && !lockfile.try_lock().map_err(Error::from_lockfile)? {
            readonly = true; // we couldn't get the lock!
        };
        let flags = if readonly {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        } else {
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
        };
        let conn = rusqlite::Connection::open_with_flags(&sqlpath, flags)?;
        let mut store = SqliteStore::from_conn_internal(conn, blob_dir, readonly)?;
        store.sql_path = Some(sqlpath);
        store.lockfile = Some(lockfile);
        Ok(store)
    }

    /// Construct a new SqliteStore from a database connection and a location
    /// for blob files.
    ///
    /// Used for testing with a memory-backed database.
    ///
    /// Note: `blob_dir` must not be used for anything other than storing the blobs associated with
    /// this database, since we will freely remove unreferenced files from this directory.
    #[cfg(test)]
    fn from_conn(conn: rusqlite::Connection, blob_dir: CheckedDir) -> Result<Self> {
        Self::from_conn_internal(conn, blob_dir, false)
    }

    /// Construct a new SqliteStore from a database connection and a location
    /// for blob files.
    ///
    /// The `readonly` argument specifies whether the database connection should be read-only.
    fn from_conn_internal(
        conn: rusqlite::Connection,
        blob_dir: CheckedDir,
        readonly: bool,
    ) -> Result<Self> {
        // sqlite (as of Jun 2024) does not enforce foreign keys automatically unless you set this
        // pragma on the connection.
        conn.pragma_update(None, "foreign_keys", "ON")?;

        let mut result = SqliteStore {
            conn,
            blob_dir,
            lockfile: None,
            sql_path: None,
        };

        result.check_schema(readonly)?;

        Ok(result)
    }

    /// Check whether this database has a schema format we can read, and
    /// install or upgrade the schema if necessary.
    fn check_schema(&mut self, readonly: bool) -> Result<()> {
        let tx = self.conn.transaction()?;
        let db_n_tables: u32 = tx.query_row(
            "SELECT COUNT(name) FROM sqlite_master
             WHERE type='table'
             AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )?;
        let db_exists = db_n_tables > 0;

        // Update the schema from current_vsn to the latest (does not commit)
        let update_schema = |tx: &rusqlite::Transaction, current_vsn| {
            for (from_vsn, update) in UPDATE_SCHEMA.iter().enumerate() {
                let from_vsn = u32::try_from(from_vsn).expect("schema version >2^32");
                let new_vsn = from_vsn + 1;
                if current_vsn < new_vsn {
                    tx.execute_batch(update)?;
                    tx.execute(UPDATE_SCHEMA_VERSION, params![new_vsn, new_vsn])?;
                }
            }
            Ok::<_, Error>(())
        };

        if !db_exists {
            if !readonly {
                tx.execute_batch(INSTALL_V0_SCHEMA)?;
                update_schema(&tx, 0)?;
                tx.commit()?;
            } else {
                // The other process should have created the database!
                return Err(Error::ReadOnlyStorage(ReadOnlyStorageError::NoDatabase));
            }
            return Ok(());
        }

        let (version, readable_by): (u32, u32) = tx.query_row(
            "SELECT version, readable_by FROM TorSchemaMeta
             WHERE name = 'TorDirStorage'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;

        if version < SCHEMA_VERSION {
            if !readonly {
                update_schema(&tx, version)?;
                tx.commit()?;
            } else {
                return Err(Error::ReadOnlyStorage(
                    ReadOnlyStorageError::IncompatibleSchema {
                        schema: version,
                        supported: SCHEMA_VERSION,
                    },
                ));
            }

            return Ok(());
        } else if readable_by > SCHEMA_VERSION {
            return Err(Error::UnrecognizedSchema {
                schema: readable_by,
                supported: SCHEMA_VERSION,
            });
        }

        // rolls back the transaction, but nothing was done.
        Ok(())
    }

    /// Read a blob from disk, mapping it if possible.
    ///
    /// Return `Ok(None)` if the file for the blob was not found on disk;
    /// returns an error in other cases.
    fn read_blob(&self, path: &str) -> Result<Option<InputString>> {
        let file = match self.blob_dir.open(path, OpenOptions::new().read(true)) {
            Ok(file) => file,
            Err(fs_mistrust::Error::NotFound(_)) => {
                warn!(
                    "{:?} was listed in the database, but its corresponding file had been deleted",
                    path
                );
                self.conn
                    .execute(DELETE_EXTDOC_BY_FILENAME, params![path])?;
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        };

        InputString::load(file)
            .map_err(|err| Error::CacheFile {
                action: "loading",
                fname: PathBuf::from(path),
                error: Arc::new(err),
            })
            .map(Some)
    }

    /// Write a file to disk as a blob, and record it in the ExtDocs table.
    ///
    /// Return a SavedBlobHandle that describes where the blob is, and which
    /// can be used either to commit the blob or delete it.
    fn save_blob_internal(
        &mut self,
        contents: &[u8],
        doctype: &str,
        dtype: &str,
        digest: &[u8],
        expires: OffsetDateTime,
    ) -> Result<SavedBlobHandle<'_>> {
        let digest = hex::encode(digest);
        let digeststr = format!("{}-{}", dtype, digest);
        let fname = format!("{}_{}", doctype, digeststr);

        let full_path = self.blob_dir.join(&fname)?;
        let unlinker = Unlinker::new(&full_path);
        self.blob_dir
            .write_and_replace(&fname, contents)
            .map_err(|e| match e {
                fs_mistrust::Error::Io { err, .. } => Error::CacheFile {
                    action: "saving",
                    fname: full_path,
                    error: err,
                },
                err => err.into(),
            })?;

        let tx = self.conn.unchecked_transaction()?;
        tx.execute(INSERT_EXTDOC, params![digeststr, expires, dtype, fname])?;

        Ok(SavedBlobHandle {
            tx,
            fname,
            digeststr,
            unlinker,
        })
    }

    /// Save a blob to disk and commit it.
    #[cfg(test)]
    fn save_blob(
        &mut self,
        contents: &[u8],
        doctype: &str,
        dtype: &str,
        digest: &[u8],
        expires: OffsetDateTime,
    ) -> Result<String> {
        let h = self.save_blob_internal(contents, doctype, dtype, digest, expires)?;
        let SavedBlobHandle {
            tx,
            digeststr,
            fname,
            unlinker,
        } = h;
        let _ = digeststr;
        tx.commit()?;
        unlinker.forget();
        Ok(fname)
    }

    /// Return the valid-after time for the latest non non-pending consensus,
    #[cfg(test)]
    // We should revise the tests to use latest_consensus_meta instead.
    fn latest_consensus_time(&self, flavor: ConsensusFlavor) -> Result<Option<OffsetDateTime>> {
        Ok(self
            .latest_consensus_meta(flavor)?
            .map(|m| m.lifetime().valid_after().into()))
    }

    /// Remove the blob with name `fname`, but do not give an error on failure.
    fn remove_blob_or_warn<P: AsRef<Path>>(&self, fname: P) {
        let fname = fname.as_ref();
        if let Err(e) = self.blob_dir.remove_file(fname) {
            warn_report!(e, "Unable to remove {}", fname.display_lossy());
        }
    }

    /// Delete any blob files that are old enough, and not mentioned in the ExtDocs table.
    ///
    /// There shouldn't actually be any, but we don't want to let our cache grow infinitely
    /// if we have a bug.
    fn remove_unreferenced_blobs(
        &self,
        now: OffsetDateTime,
        expiration: &ExpirationConfig,
    ) -> Result<()> {
        // Now, look for any unreferenced blobs that are a bit old.
        for ent in self.blob_dir.read_directory(".")?.flatten() {
            let md_error = |io_error| Error::CacheFile {
                action: "getting metadata",
                fname: ent.file_name().into(),
                error: Arc::new(io_error),
            };
            if ent
                .metadata()
                .map_err(md_error)?
                .modified()
                .map_err(md_error)?
                + expiration.consensuses
                >= now
            {
                // this file is sufficiently recent that we should not remove it, just to be cautious.
                continue;
            }
            let filename = match ent.file_name().into_string() {
                Ok(s) => s,
                Err(os_str) => {
                    // This filename wasn't utf-8.  We will never create one of these.
                    warn!(
                        "Removing bizarre file '{}' from blob store.",
                        os_str.to_string_lossy()
                    );
                    self.remove_blob_or_warn(ent.file_name());
                    continue;
                }
            };
            let found: (u32,) =
                self.conn
                    .query_row(COUNT_EXTDOC_BY_PATH, params![&filename], |row| {
                        row.try_into()
                    })?;
            if found == (0,) {
                warn!("Removing unreferenced file '{}' from blob store", &filename);
                self.remove_blob_or_warn(ent.file_name());
            }
        }

        Ok(())
    }
}

impl Store for SqliteStore {
    fn is_readonly(&self) -> bool {
        match &self.lockfile {
            Some(f) => !f.owns_lock(),
            None => false,
        }
    }
    fn upgrade_to_readwrite(&mut self) -> Result<bool> {
        if self.is_readonly() && self.sql_path.is_some() {
            let lf = self
                .lockfile
                .as_mut()
                .expect("No lockfile open; cannot upgrade to read-write storage");
            if !lf.try_lock().map_err(Error::from_lockfile)? {
                // Somebody else has the lock.
                return Ok(false);
            }
            // Unwrap should be safe due to parent `.is_some()` check
            #[allow(clippy::unwrap_used)]
            match rusqlite::Connection::open(self.sql_path.as_ref().unwrap()) {
                Ok(conn) => {
                    self.conn = conn;
                }
                Err(e) => {
                    let _ignore = lf.unlock();
                    return Err(e.into());
                }
            }
        }
        Ok(true)
    }
    fn expire_all(&mut self, expiration: &ExpirationConfig) -> Result<()> {
        let tx = self.conn.transaction()?;
        // This works around a false positive; see
        //   https://github.com/rust-lang/rust-clippy/issues/8114
        #[allow(clippy::let_and_return)]
        let expired_blobs: Vec<String> = {
            let mut stmt = tx.prepare(FIND_EXPIRED_EXTDOCS)?;
            let names = stmt
                .query_map([], |row| row.get::<_, String>(0))?
                .filter_map(std::result::Result::ok)
                .collect();
            names
        };

        let now = OffsetDateTime::now_utc();
        tx.execute(DROP_OLD_EXTDOCS, [])?;

        // In theory bad system clocks might generate table rows with times far in the future.
        // However, for data which is cached here which comes from the network consensus,
        // we rely on the fact that no consensus from the future exists, so this can't happen.
        tx.execute(DROP_OLD_MICRODESCS, [now - expiration.microdescs])?;
        tx.execute(DROP_OLD_AUTHCERTS, [now - expiration.authcerts])?;
        tx.execute(DROP_OLD_CONSENSUSES, [now - expiration.consensuses])?;
        tx.execute(DROP_OLD_ROUTERDESCS, [now - expiration.router_descs])?;

        // Bridge descriptors come from bridges and bridges might send crazy times,
        // so we need to discard any that look like they are from the future,
        // since otherwise wrong far-future timestamps might live in our DB indefinitely.
        #[cfg(feature = "bridge-client")]
        tx.execute(DROP_OLD_BRIDGEDESCS, [now, now])?;

        tx.commit()?;
        for name in expired_blobs {
            let fname = self.blob_dir.join(name);
            if let Ok(fname) = fname {
                let _ignore = std::fs::remove_file(fname);
            }
        }

        self.remove_unreferenced_blobs(now, expiration)?;

        Ok(())
    }

    fn latest_consensus(
        &self,
        flavor: ConsensusFlavor,
        pending: Option<bool>,
    ) -> Result<Option<InputString>> {
        trace!(?flavor, ?pending, "Loading latest consensus from cache");
        let rv: Option<(OffsetDateTime, OffsetDateTime, String)> = match pending {
            None => self
                .conn
                .query_row(FIND_CONSENSUS, params![flavor.name()], |row| row.try_into())
                .optional()?,
            Some(pending_val) => self
                .conn
                .query_row(
                    FIND_CONSENSUS_P,
                    params![pending_val, flavor.name()],
                    |row| row.try_into(),
                )
                .optional()?,
        };

        if let Some((_va, _vu, filename)) = rv {
            // TODO: If the cache is corrupt (because this blob is missing), and the cache has not yet
            // been cleaned, this may fail to find the latest consensus that we actually have.
            self.read_blob(&filename)
        } else {
            Ok(None)
        }
    }
    fn latest_consensus_meta(&self, flavor: ConsensusFlavor) -> Result<Option<ConsensusMeta>> {
        let mut stmt = self.conn.prepare(FIND_LATEST_CONSENSUS_META)?;
        let mut rows = stmt.query(params![flavor.name()])?;
        if let Some(row) = rows.next()? {
            Ok(Some(cmeta_from_row(row)?))
        } else {
            Ok(None)
        }
    }
    #[cfg(test)]
    fn consensus_by_meta(&self, cmeta: &ConsensusMeta) -> Result<InputString> {
        if let Some((text, _)) =
            self.consensus_by_sha3_digest_of_signed_part(cmeta.sha3_256_of_signed())?
        {
            Ok(text)
        } else {
            Err(Error::CacheCorruption(
                "couldn't find a consensus we thought we had.",
            ))
        }
    }
    fn consensus_by_sha3_digest_of_signed_part(
        &self,
        d: &[u8; 32],
    ) -> Result<Option<(InputString, ConsensusMeta)>> {
        let digest = hex::encode(d);
        let mut stmt = self
            .conn
            .prepare(FIND_CONSENSUS_AND_META_BY_DIGEST_OF_SIGNED)?;
        let mut rows = stmt.query(params![digest])?;
        if let Some(row) = rows.next()? {
            let meta = cmeta_from_row(row)?;
            let fname: String = row.get(5)?;
            if let Some(text) = self.read_blob(&fname)? {
                return Ok(Some((text, meta)));
            }
        }
        Ok(None)
    }
    fn store_consensus(
        &mut self,
        cmeta: &ConsensusMeta,
        flavor: ConsensusFlavor,
        pending: bool,
        contents: &str,
    ) -> Result<()> {
        let lifetime = cmeta.lifetime();
        let sha3_of_signed = cmeta.sha3_256_of_signed();
        let sha3_of_whole = cmeta.sha3_256_of_whole();
        let valid_after: OffsetDateTime = lifetime.valid_after().into();
        let fresh_until: OffsetDateTime = lifetime.fresh_until().into();
        let valid_until: OffsetDateTime = lifetime.valid_until().into();

        /// How long to keep a consensus around after it has expired
        const CONSENSUS_LIFETIME: time::Duration = time::Duration::days(4);

        // After a few days have passed, a consensus is no good for
        // anything at all, not even diffs.
        let expires = valid_until + CONSENSUS_LIFETIME;

        let doctype = format!("con_{}", flavor.name());

        let h = self.save_blob_internal(
            contents.as_bytes(),
            &doctype,
            "sha3-256",
            &sha3_of_whole[..],
            expires,
        )?;
        h.tx.execute(
            INSERT_CONSENSUS,
            params![
                valid_after,
                fresh_until,
                valid_until,
                flavor.name(),
                pending,
                hex::encode(sha3_of_signed),
                h.digeststr
            ],
        )?;
        h.tx.commit()?;
        h.unlinker.forget();
        Ok(())
    }
    fn mark_consensus_usable(&mut self, cmeta: &ConsensusMeta) -> Result<()> {
        let d = hex::encode(cmeta.sha3_256_of_whole());
        let digest = format!("sha3-256-{}", d);

        let tx = self.conn.transaction()?;
        let n = tx.execute(MARK_CONSENSUS_NON_PENDING, params![digest])?;
        trace!("Marked {} consensuses usable", n);
        tx.commit()?;

        Ok(())
    }
    fn delete_consensus(&mut self, cmeta: &ConsensusMeta) -> Result<()> {
        let d = hex::encode(cmeta.sha3_256_of_whole());
        let digest = format!("sha3-256-{}", d);

        // TODO: We should probably remove the blob as well, but for now
        // this is enough.
        let tx = self.conn.transaction()?;
        tx.execute(REMOVE_CONSENSUS, params![digest])?;
        tx.commit()?;

        Ok(())
    }

    fn authcerts(&self, certs: &[AuthCertKeyIds]) -> Result<HashMap<AuthCertKeyIds, String>> {
        let mut result = HashMap::new();
        // TODO(nickm): Do I need to get a transaction here for performance?
        let mut stmt = self.conn.prepare(FIND_AUTHCERT)?;

        for ids in certs {
            let id_digest = hex::encode(ids.id_fingerprint.as_bytes());
            let sk_digest = hex::encode(ids.sk_fingerprint.as_bytes());
            if let Some(contents) = stmt
                .query_row(params![id_digest, sk_digest], |row| row.get::<_, String>(0))
                .optional()?
            {
                result.insert(*ids, contents);
            }
        }

        Ok(result)
    }
    fn store_authcerts(&mut self, certs: &[(AuthCertMeta, &str)]) -> Result<()> {
        let tx = self.conn.transaction()?;
        let mut stmt = tx.prepare(INSERT_AUTHCERT)?;
        for (meta, content) in certs {
            let ids = meta.key_ids();
            let id_digest = hex::encode(ids.id_fingerprint.as_bytes());
            let sk_digest = hex::encode(ids.sk_fingerprint.as_bytes());
            let published: OffsetDateTime = meta.published().into();
            let expires: OffsetDateTime = meta.expires().into();
            stmt.execute(params![id_digest, sk_digest, published, expires, content])?;
        }
        stmt.finalize()?;
        tx.commit()?;
        Ok(())
    }

    fn microdescs(&self, digests: &[MdDigest]) -> Result<HashMap<MdDigest, String>> {
        let mut result = HashMap::new();
        let mut stmt = self.conn.prepare(FIND_MD)?;

        // TODO(nickm): Should I speed this up with a transaction, or
        // does it not matter for queries?
        for md_digest in digests {
            let h_digest = hex::encode(md_digest);
            if let Some(contents) = stmt
                .query_row(params![h_digest], |row| row.get::<_, String>(0))
                .optional()?
            {
                result.insert(*md_digest, contents);
            }
        }

        Ok(result)
    }
    fn store_microdescs(&mut self, digests: &[(&str, &MdDigest)], when: SystemTime) -> Result<()> {
        let when: OffsetDateTime = when.into();

        let tx = self.conn.transaction()?;
        let mut stmt = tx.prepare(INSERT_MD)?;

        for (content, md_digest) in digests {
            let h_digest = hex::encode(md_digest);
            stmt.execute(params![h_digest, when, content])?;
        }
        stmt.finalize()?;
        tx.commit()?;
        Ok(())
    }
    fn update_microdescs_listed(&mut self, digests: &[MdDigest], when: SystemTime) -> Result<()> {
        let tx = self.conn.transaction()?;
        let mut stmt = tx.prepare(UPDATE_MD_LISTED)?;
        let when: OffsetDateTime = when.into();

        for md_digest in digests {
            let h_digest = hex::encode(md_digest);
            stmt.execute(params![when, h_digest])?;
        }

        stmt.finalize()?;
        tx.commit()?;
        Ok(())
    }

    #[cfg(feature = "routerdesc")]
    fn routerdescs(&self, digests: &[RdDigest]) -> Result<HashMap<RdDigest, String>> {
        let mut result = HashMap::new();
        let mut stmt = self.conn.prepare(FIND_RD)?;

        // TODO(nickm): Should I speed this up with a transaction, or
        // does it not matter for queries?
        for rd_digest in digests {
            let h_digest = hex::encode(rd_digest);
            if let Some(contents) = stmt
                .query_row(params![h_digest], |row| row.get::<_, String>(0))
                .optional()?
            {
                result.insert(*rd_digest, contents);
            }
        }

        Ok(result)
    }
    #[cfg(feature = "routerdesc")]
    fn store_routerdescs(&mut self, digests: &[(&str, SystemTime, &RdDigest)]) -> Result<()> {
        let tx = self.conn.transaction()?;
        let mut stmt = tx.prepare(INSERT_RD)?;

        for (content, when, rd_digest) in digests {
            let when: OffsetDateTime = (*when).into();
            let h_digest = hex::encode(rd_digest);
            stmt.execute(params![h_digest, when, content])?;
        }
        stmt.finalize()?;
        tx.commit()?;
        Ok(())
    }

    #[cfg(feature = "bridge-client")]
    fn lookup_bridgedesc(&self, bridge: &BridgeConfig) -> Result<Option<CachedBridgeDescriptor>> {
        let bridge_line = bridge.to_string();
        Ok(self
            .conn
            .query_row(FIND_BRIDGEDESC, params![bridge_line], |row| {
                let (fetched, document): (OffsetDateTime, _) = row.try_into()?;
                let fetched = fetched.into();
                Ok(CachedBridgeDescriptor { fetched, document })
            })
            .optional()?)
    }

    #[cfg(feature = "bridge-client")]
    fn store_bridgedesc(
        &mut self,
        bridge: &BridgeConfig,
        entry: CachedBridgeDescriptor,
        until: SystemTime,
    ) -> Result<()> {
        if self.is_readonly() {
            // Hopefully whoever *does* have the lock will update the cache.
            // Otherwise it will contain a stale entry forever
            // (which we'll ignore, but waste effort on).
            return Ok(());
        }
        let bridge_line = bridge.to_string();
        let row = params![
            bridge_line,
            OffsetDateTime::from(entry.fetched),
            OffsetDateTime::from(until),
            entry.document,
        ];
        self.conn.execute(INSERT_BRIDGEDESC, row)?;
        Ok(())
    }

    #[cfg(feature = "bridge-client")]
    fn delete_bridgedesc(&mut self, bridge: &BridgeConfig) -> Result<()> {
        if self.is_readonly() {
            // This is called when we find corrupted or stale cache entries,
            // to stop us wasting time on them next time.
            // Hopefully whoever *does* have the lock will do this.
            return Ok(());
        }
        let bridge_line = bridge.to_string();
        self.conn.execute(DELETE_BRIDGEDESC, params![bridge_line])?;
        Ok(())
    }
}

/// Handle to a blob that we have saved to disk but not yet committed to
/// the database.
struct SavedBlobHandle<'a> {
    /// Transaction we're using to add the blob to the ExtDocs table.
    tx: Transaction<'a>,
    /// Filename for the file, with respect to the blob directory.
    #[allow(unused)]
    fname: String,
    /// Declared digest string for this blob. Of the format
    /// "digesttype-hexstr".
    digeststr: String,
    /// An 'unlinker' for the blob file.
    unlinker: Unlinker,
}

/// Handle to a file which we might have to delete.
///
/// When this handle is dropped, the file gets deleted, unless you have
/// first called [`Unlinker::forget`].
struct Unlinker {
    /// The location of the file to remove, or None if we shouldn't
    /// remove it.
    p: Option<PathBuf>,
}
impl Unlinker {
    /// Make a new Unlinker for a given filename.
    fn new<P: AsRef<Path>>(p: P) -> Self {
        Unlinker {
            p: Some(p.as_ref().to_path_buf()),
        }
    }
    /// Forget about this unlinker, so that the corresponding file won't
    /// get dropped.
    fn forget(mut self) {
        self.p = None;
    }
}
impl Drop for Unlinker {
    fn drop(&mut self) {
        if let Some(p) = self.p.take() {
            let _ignore_err = std::fs::remove_file(p);
        }
    }
}

/// Convert a hexadecimal sha3-256 digest from the database into an array.
fn digest_from_hex(s: &str) -> Result<[u8; 32]> {
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(s, &mut bytes[..]).map_err(Error::BadHexInCache)?;
    Ok(bytes)
}

/// Convert a hexadecimal sha3-256 "digest string" as used in the
/// digest column from the database into an array.
fn digest_from_dstr(s: &str) -> Result<[u8; 32]> {
    if let Some(stripped) = s.strip_prefix("sha3-256-") {
        digest_from_hex(stripped)
    } else {
        Err(Error::CacheCorruption("Invalid digest in database"))
    }
}

/// Create a ConsensusMeta from a `Row` returned by one of
/// `FIND_LATEST_CONSENSUS_META` or `FIND_CONSENSUS_AND_META_BY_DIGEST`.
fn cmeta_from_row(row: &rusqlite::Row<'_>) -> Result<ConsensusMeta> {
    let va: OffsetDateTime = row.get(0)?;
    let fu: OffsetDateTime = row.get(1)?;
    let vu: OffsetDateTime = row.get(2)?;
    let d_signed: String = row.get(3)?;
    let d_all: String = row.get(4)?;
    let lifetime = Lifetime::new(va.into(), fu.into(), vu.into())
        .map_err(|_| Error::CacheCorruption("inconsistent lifetime in database"))?;
    Ok(ConsensusMeta::new(
        lifetime,
        digest_from_hex(&d_signed)?,
        digest_from_dstr(&d_all)?,
    ))
}

/// Set up the tables for the arti cache schema in a sqlite database.
const INSTALL_V0_SCHEMA: &str = "
  -- Helps us version the schema.  The schema here corresponds to a
  -- version number called 'version', and it should be readable by
  -- anybody who is compliant with versions of at least 'readable_by'.
  CREATE TABLE TorSchemaMeta (
     name TEXT NOT NULL PRIMARY KEY,
     version INTEGER NOT NULL,
     readable_by INTEGER NOT NULL
  );

  INSERT INTO TorSchemaMeta (name, version, readable_by) VALUES ( 'TorDirStorage', 0, 0 );

  -- Keeps track of external blobs on disk.
  CREATE TABLE ExtDocs (
    -- Records a digest of the file contents, in the form 'dtype-hexstr'
    digest TEXT PRIMARY KEY NOT NULL,
    -- When was this file created?
    created DATE NOT NULL,
    -- After what time will this file definitely be useless?
    expires DATE NOT NULL,
    -- What is the type of this file? Currently supported are 'con:<flavor>'.
    type TEXT NOT NULL,
    -- Filename for this file within our blob directory.
    filename TEXT NOT NULL
  );

  -- All the microdescriptors we know about.
  CREATE TABLE Microdescs (
    sha256_digest TEXT PRIMARY KEY NOT NULL,
    last_listed DATE NOT NULL,
    contents BLOB NOT NULL
  );

  -- All the authority certificates we know.
  CREATE TABLE Authcerts (
    id_digest TEXT NOT NULL,
    sk_digest TEXT NOT NULL,
    published DATE NOT NULL,
    expires DATE NOT NULL,
    contents BLOB NOT NULL,
    PRIMARY KEY (id_digest, sk_digest)
  );

  -- All the consensuses we're storing.
  CREATE TABLE Consensuses (
    valid_after DATE NOT NULL,
    fresh_until DATE NOT NULL,
    valid_until DATE NOT NULL,
    flavor TEXT NOT NULL,
    pending BOOLEAN NOT NULL,
    sha3_of_signed_part TEXT NOT NULL,
    digest TEXT NOT NULL,
    FOREIGN KEY (digest) REFERENCES ExtDocs (digest) ON DELETE CASCADE
  );
  CREATE INDEX Consensuses_vu on CONSENSUSES(valid_until);

";

/// Update the database schema, from each version to the next
const UPDATE_SCHEMA: &[&str] = &["
  -- Update the database schema from version 0 to version 1.
  CREATE TABLE RouterDescs (
    sha1_digest TEXT PRIMARY KEY NOT NULL,
    published DATE NOT NULL,
    contents BLOB NOT NULL
  );
","
  -- Update the database schema from version 1 to version 2.
  -- We create this table even if the bridge-client feature is disabled, but then don't touch it at all.
  CREATE TABLE BridgeDescs (
    bridge_line TEXT PRIMARY KEY NOT NULL,
    fetched DATE NOT NULL,
    until DATE NOT NULL,
    contents BLOB NOT NULL
  );
"];

/// Update the database schema version tracking, from each version to the next
const UPDATE_SCHEMA_VERSION: &str = "
  UPDATE TorSchemaMeta SET version=? WHERE version<?;
";

/// Version number used for this version of the arti cache schema.
const SCHEMA_VERSION: u32 = UPDATE_SCHEMA.len() as u32;

/// Query: find the latest-expiring microdesc consensus with a given
/// pending status.
const FIND_CONSENSUS_P: &str = "
  SELECT valid_after, valid_until, filename
  FROM Consensuses
  INNER JOIN ExtDocs ON ExtDocs.digest = Consensuses.digest
  WHERE pending = ? AND flavor = ?
  ORDER BY valid_until DESC
  LIMIT 1;
";

/// Query: find the latest-expiring microdesc consensus, regardless of
/// pending status.
const FIND_CONSENSUS: &str = "
  SELECT valid_after, valid_until, filename
  FROM Consensuses
  INNER JOIN ExtDocs ON ExtDocs.digest = Consensuses.digest
  WHERE flavor = ?
  ORDER BY valid_until DESC
  LIMIT 1;
";

/// Query: Find the valid-after time for the latest-expiring
/// non-pending consensus of a given flavor.
const FIND_LATEST_CONSENSUS_META: &str = "
  SELECT valid_after, fresh_until, valid_until, sha3_of_signed_part, digest
  FROM Consensuses
  WHERE pending = 0 AND flavor = ?
  ORDER BY valid_until DESC
  LIMIT 1;
";

/// Look up a consensus by its digest-of-signed-part string.
const FIND_CONSENSUS_AND_META_BY_DIGEST_OF_SIGNED: &str = "
  SELECT valid_after, fresh_until, valid_until, sha3_of_signed_part, Consensuses.digest, filename
  FROM Consensuses
  INNER JOIN ExtDocs on ExtDocs.digest = Consensuses.digest
  WHERE Consensuses.sha3_of_signed_part = ?
  LIMIT 1;
";

/// Query: Update the consensus whose digest field is 'digest' to call it
/// no longer pending.
const MARK_CONSENSUS_NON_PENDING: &str = "
  UPDATE Consensuses
  SET pending = 0
  WHERE digest = ?;
";

/// Query: Remove the consensus with a given digest field.
#[allow(dead_code)]
const REMOVE_CONSENSUS: &str = "
  DELETE FROM Consensuses
  WHERE digest = ?;
";

/// Query: Find the authority certificate with given key digests.
const FIND_AUTHCERT: &str = "
  SELECT contents FROM AuthCerts WHERE id_digest = ? AND sk_digest = ?;
";

/// Query: find the microdescriptor with a given hex-encoded sha256 digest
const FIND_MD: &str = "
  SELECT contents
  FROM Microdescs
  WHERE sha256_digest = ?
";

/// Query: find the router descriptors with a given hex-encoded sha1 digest
#[cfg(feature = "routerdesc")]
const FIND_RD: &str = "
  SELECT contents
  FROM RouterDescs
  WHERE sha1_digest = ?
";

/// Query: find every ExtDocs member that has expired.
const FIND_EXPIRED_EXTDOCS: &str = "
  SELECT filename FROM ExtDocs where expires < datetime('now');
";

/// Query: find whether an ExtDoc is listed.
const COUNT_EXTDOC_BY_PATH: &str = "
  SELECT COUNT(*) FROM ExtDocs WHERE filename = ?;
";

/// Query: Add a new entry to ExtDocs.
const INSERT_EXTDOC: &str = "
  INSERT OR REPLACE INTO ExtDocs ( digest, created, expires, type, filename )
  VALUES ( ?, datetime('now'), ?, ?, ? );
";

/// Query: Add a new consensus.
const INSERT_CONSENSUS: &str = "
  INSERT OR REPLACE INTO Consensuses
    ( valid_after, fresh_until, valid_until, flavor, pending, sha3_of_signed_part, digest )
  VALUES ( ?, ?, ?, ?, ?, ?, ? );
";

/// Query: Add a new AuthCert
const INSERT_AUTHCERT: &str = "
  INSERT OR REPLACE INTO Authcerts
    ( id_digest, sk_digest, published, expires, contents)
  VALUES ( ?, ?, ?, ?, ? );
";

/// Query: Add a new microdescriptor
const INSERT_MD: &str = "
  INSERT OR REPLACE INTO Microdescs ( sha256_digest, last_listed, contents )
  VALUES ( ?, ?, ? );
";

/// Query: Add a new router descriptor
#[allow(unused)]
#[cfg(feature = "routerdesc")]
const INSERT_RD: &str = "
  INSERT OR REPLACE INTO RouterDescs ( sha1_digest, published, contents )
  VALUES ( ?, ?, ? );
";

/// Query: Change the time when a given microdescriptor was last listed.
const UPDATE_MD_LISTED: &str = "
  UPDATE Microdescs
  SET last_listed = max(last_listed, ?)
  WHERE sha256_digest = ?;
";

/// Query: Find a cached bridge descriptor
#[cfg(feature = "bridge-client")]
const FIND_BRIDGEDESC: &str = "SELECT fetched, contents FROM BridgeDescs WHERE bridge_line = ?;";
/// Query: Record a cached bridge descriptor
#[cfg(feature = "bridge-client")]
const INSERT_BRIDGEDESC: &str = "
  INSERT OR REPLACE INTO BridgeDescs ( bridge_line, fetched, until, contents )
  VALUES ( ?, ?, ?, ? );
";
/// Query: Remove a cached bridge descriptor
#[cfg(feature = "bridge-client")]
#[allow(dead_code)]
const DELETE_BRIDGEDESC: &str = "DELETE FROM BridgeDescs WHERE bridge_line = ?;";

/// Query: Discard every expired extdoc.
///
/// External documents aren't exposed through [`Store`].
const DROP_OLD_EXTDOCS: &str = "DELETE FROM ExtDocs WHERE expires < datetime('now');";

/// Query: Discard an extdoc with a given path.
const DELETE_EXTDOC_BY_FILENAME: &str = "DELETE FROM ExtDocs WHERE filename = ?;";

/// Query: Discard every router descriptor that hasn't been listed for 3
/// months.
// TODO: Choose a more realistic time.
const DROP_OLD_ROUTERDESCS: &str = "DELETE FROM RouterDescs WHERE published < ?;";
/// Query: Discard every microdescriptor that hasn't been listed for 3 months.
// TODO: Choose a more realistic time.
const DROP_OLD_MICRODESCS: &str = "DELETE FROM Microdescs WHERE last_listed < ?;";
/// Query: Discard every expired authority certificate.
const DROP_OLD_AUTHCERTS: &str = "DELETE FROM Authcerts WHERE expires < ?;";
/// Query: Discard every consensus that's been expired for at least
/// two days.
const DROP_OLD_CONSENSUSES: &str = "DELETE FROM Consensuses WHERE valid_until < ?;";
/// Query: Discard every bridge descriptor that is too old, or from the future.  (Both ?=now.)
#[cfg(feature = "bridge-client")]
const DROP_OLD_BRIDGEDESCS: &str = "DELETE FROM BridgeDescs WHERE ? > until OR fetched > ?;";

#[cfg(test)]
pub(crate) mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::storage::EXPIRATION_DEFAULTS;
    use hex_literal::hex;
    use tempfile::{tempdir, TempDir};
    use time::ext::NumericalDuration;

    pub(crate) fn new_empty() -> Result<(TempDir, SqliteStore)> {
        let tmp_dir = tempdir().unwrap();
        let sql_path = tmp_dir.path().join("db.sql");
        let conn = rusqlite::Connection::open(sql_path)?;
        let blob_path = tmp_dir.path().join("blobs");
        let blob_dir = fs_mistrust::Mistrust::builder()
            .dangerously_trust_everyone()
            .build()
            .unwrap()
            .verifier()
            .make_secure_dir(blob_path)
            .unwrap();
        let store = SqliteStore::from_conn(conn, blob_dir)?;

        Ok((tmp_dir, store))
    }

    #[test]
    fn init() -> Result<()> {
        let tmp_dir = tempdir().unwrap();
        let blob_dir = fs_mistrust::Mistrust::builder()
            .dangerously_trust_everyone()
            .build()
            .unwrap()
            .verifier()
            .secure_dir(&tmp_dir)
            .unwrap();
        let sql_path = tmp_dir.path().join("db.sql");
        // Initial setup: everything should work.
        {
            let conn = rusqlite::Connection::open(&sql_path)?;
            let _store = SqliteStore::from_conn(conn, blob_dir.clone())?;
        }
        // Second setup: shouldn't need to upgrade.
        {
            let conn = rusqlite::Connection::open(&sql_path)?;
            let _store = SqliteStore::from_conn(conn, blob_dir.clone())?;
        }
        // Third setup: shouldn't need to upgrade.
        {
            let conn = rusqlite::Connection::open(&sql_path)?;
            conn.execute_batch("UPDATE TorSchemaMeta SET version = 9002;")?;
            let _store = SqliteStore::from_conn(conn, blob_dir.clone())?;
        }
        // Fourth: this says we can't read it, so we'll get an error.
        {
            let conn = rusqlite::Connection::open(&sql_path)?;
            conn.execute_batch("UPDATE TorSchemaMeta SET readable_by = 9001;")?;
            let val = SqliteStore::from_conn(conn, blob_dir);
            assert!(val.is_err());
        }
        Ok(())
    }

    #[test]
    fn bad_blob_fname() -> Result<()> {
        let (_tmp_dir, store) = new_empty()?;

        assert!(store.blob_dir.join("abcd").is_ok());
        assert!(store.blob_dir.join("abcd..").is_ok());
        assert!(store.blob_dir.join("..abcd..").is_ok());
        assert!(store.blob_dir.join(".abcd").is_ok());

        assert!(store.blob_dir.join("..").is_err());
        assert!(store.blob_dir.join("../abcd").is_err());
        assert!(store.blob_dir.join("/abcd").is_err());

        Ok(())
    }

    #[test]
    fn blobs() -> Result<()> {
        let (_tmp_dir, mut store) = new_empty()?;

        let now = OffsetDateTime::now_utc();
        let one_week = 1.weeks();

        let fname1 = store.save_blob(
            b"Hello world",
            "greeting",
            "sha1",
            &hex!("7b502c3a1f48c8609ae212cdfb639dee39673f5e"),
            now + one_week,
        )?;

        let fname2 = store.save_blob(
            b"Goodbye, dear friends",
            "greeting",
            "sha1",
            &hex!("2149c2a7dbf5be2bb36fb3c5080d0fb14cb3355c"),
            now - one_week,
        )?;

        assert_eq!(
            fname1,
            "greeting_sha1-7b502c3a1f48c8609ae212cdfb639dee39673f5e"
        );
        assert_eq!(
            &std::fs::read(store.blob_dir.join(&fname1)?).unwrap()[..],
            b"Hello world"
        );
        assert_eq!(
            &std::fs::read(store.blob_dir.join(&fname2)?).unwrap()[..],
            b"Goodbye, dear friends"
        );

        let n: u32 = store
            .conn
            .query_row("SELECT COUNT(filename) FROM ExtDocs", [], |row| row.get(0))?;
        assert_eq!(n, 2);

        let blob = store.read_blob(&fname2)?.unwrap();
        assert_eq!(blob.as_str().unwrap(), "Goodbye, dear friends");

        // Now expire: the second file should go away.
        store.expire_all(&EXPIRATION_DEFAULTS)?;
        assert_eq!(
            &std::fs::read(store.blob_dir.join(&fname1)?).unwrap()[..],
            b"Hello world"
        );
        assert!(std::fs::read(store.blob_dir.join(&fname2)?).is_err());
        let n: u32 = store
            .conn
            .query_row("SELECT COUNT(filename) FROM ExtDocs", [], |row| row.get(0))?;
        assert_eq!(n, 1);

        Ok(())
    }

    #[test]
    fn consensus() -> Result<()> {
        use tor_netdoc::doc::netstatus;

        let (_tmp_dir, mut store) = new_empty()?;
        let now = OffsetDateTime::now_utc();
        let one_hour = 1.hours();

        assert_eq!(
            store.latest_consensus_time(ConsensusFlavor::Microdesc)?,
            None
        );

        let cmeta = ConsensusMeta::new(
            netstatus::Lifetime::new(
                now.into(),
                (now + one_hour).into(),
                SystemTime::from(now + one_hour * 2),
            )
            .unwrap(),
            [0xAB; 32],
            [0xBC; 32],
        );

        store.store_consensus(
            &cmeta,
            ConsensusFlavor::Microdesc,
            true,
            "Pretend this is a consensus",
        )?;

        {
            assert_eq!(
                store.latest_consensus_time(ConsensusFlavor::Microdesc)?,
                None
            );
            let consensus = store
                .latest_consensus(ConsensusFlavor::Microdesc, None)?
                .unwrap();
            assert_eq!(consensus.as_str()?, "Pretend this is a consensus");
            let consensus = store.latest_consensus(ConsensusFlavor::Microdesc, Some(false))?;
            assert!(consensus.is_none());
        }

        store.mark_consensus_usable(&cmeta)?;

        {
            assert_eq!(
                store.latest_consensus_time(ConsensusFlavor::Microdesc)?,
                now.into()
            );
            let consensus = store
                .latest_consensus(ConsensusFlavor::Microdesc, None)?
                .unwrap();
            assert_eq!(consensus.as_str()?, "Pretend this is a consensus");
            let consensus = store
                .latest_consensus(ConsensusFlavor::Microdesc, Some(false))?
                .unwrap();
            assert_eq!(consensus.as_str()?, "Pretend this is a consensus");
        }

        {
            let consensus_text = store.consensus_by_meta(&cmeta)?;
            assert_eq!(consensus_text.as_str()?, "Pretend this is a consensus");

            let (is, _cmeta2) = store
                .consensus_by_sha3_digest_of_signed_part(&[0xAB; 32])?
                .unwrap();
            assert_eq!(is.as_str()?, "Pretend this is a consensus");

            let cmeta3 = ConsensusMeta::new(
                netstatus::Lifetime::new(
                    now.into(),
                    (now + one_hour).into(),
                    SystemTime::from(now + one_hour * 2),
                )
                .unwrap(),
                [0x99; 32],
                [0x99; 32],
            );
            assert!(store.consensus_by_meta(&cmeta3).is_err());

            assert!(store
                .consensus_by_sha3_digest_of_signed_part(&[0x99; 32])?
                .is_none());
        }

        {
            assert!(store
                .consensus_by_sha3_digest_of_signed_part(&[0xAB; 32])?
                .is_some());
            store.delete_consensus(&cmeta)?;
            assert!(store
                .consensus_by_sha3_digest_of_signed_part(&[0xAB; 32])?
                .is_none());
        }

        Ok(())
    }

    #[test]
    fn authcerts() -> Result<()> {
        let (_tmp_dir, mut store) = new_empty()?;
        let now = OffsetDateTime::now_utc();
        let one_hour = 1.hours();

        let keyids = AuthCertKeyIds {
            id_fingerprint: [3; 20].into(),
            sk_fingerprint: [4; 20].into(),
        };
        let keyids2 = AuthCertKeyIds {
            id_fingerprint: [4; 20].into(),
            sk_fingerprint: [3; 20].into(),
        };

        let m1 = AuthCertMeta::new(keyids, now.into(), SystemTime::from(now + one_hour * 24));

        store.store_authcerts(&[(m1, "Pretend this is a cert")])?;

        let certs = store.authcerts(&[keyids, keyids2])?;
        assert_eq!(certs.len(), 1);
        assert_eq!(certs.get(&keyids).unwrap(), "Pretend this is a cert");

        Ok(())
    }

    #[test]
    fn microdescs() -> Result<()> {
        let (_tmp_dir, mut store) = new_empty()?;

        let now = OffsetDateTime::now_utc();
        let one_day = 1.days();

        let d1 = [5_u8; 32];
        let d2 = [7; 32];
        let d3 = [42; 32];
        let d4 = [99; 32];

        let long_ago: OffsetDateTime = now - one_day * 100;
        store.store_microdescs(
            &[
                ("Fake micro 1", &d1),
                ("Fake micro 2", &d2),
                ("Fake micro 3", &d3),
            ],
            long_ago.into(),
        )?;

        store.update_microdescs_listed(&[d2], now.into())?;

        let mds = store.microdescs(&[d2, d3, d4])?;
        assert_eq!(mds.len(), 2);
        assert_eq!(mds.get(&d1), None);
        assert_eq!(mds.get(&d2).unwrap(), "Fake micro 2");
        assert_eq!(mds.get(&d3).unwrap(), "Fake micro 3");
        assert_eq!(mds.get(&d4), None);

        // Now we'll expire.  that should drop everything but d2.
        store.expire_all(&EXPIRATION_DEFAULTS)?;
        let mds = store.microdescs(&[d2, d3, d4])?;
        assert_eq!(mds.len(), 1);
        assert_eq!(mds.get(&d2).unwrap(), "Fake micro 2");

        Ok(())
    }

    #[test]
    #[cfg(feature = "routerdesc")]
    fn routerdescs() -> Result<()> {
        let (_tmp_dir, mut store) = new_empty()?;

        let now = OffsetDateTime::now_utc();
        let one_day = 1.days();
        let long_ago: OffsetDateTime = now - one_day * 100;
        let recently = now - one_day;

        let d1 = [5_u8; 20];
        let d2 = [7; 20];
        let d3 = [42; 20];
        let d4 = [99; 20];

        store.store_routerdescs(&[
            ("Fake routerdesc 1", long_ago.into(), &d1),
            ("Fake routerdesc 2", recently.into(), &d2),
            ("Fake routerdesc 3", long_ago.into(), &d3),
        ])?;

        let rds = store.routerdescs(&[d2, d3, d4])?;
        assert_eq!(rds.len(), 2);
        assert_eq!(rds.get(&d1), None);
        assert_eq!(rds.get(&d2).unwrap(), "Fake routerdesc 2");
        assert_eq!(rds.get(&d3).unwrap(), "Fake routerdesc 3");
        assert_eq!(rds.get(&d4), None);

        // Now we'll expire.  that should drop everything but d2.
        store.expire_all(&EXPIRATION_DEFAULTS)?;
        let rds = store.routerdescs(&[d2, d3, d4])?;
        assert_eq!(rds.len(), 1);
        assert_eq!(rds.get(&d2).unwrap(), "Fake routerdesc 2");

        Ok(())
    }

    #[test]
    fn from_path_rw() -> Result<()> {
        let tmp = tempdir().unwrap();
        let mistrust = fs_mistrust::Mistrust::new_dangerously_trust_everyone();

        // Nothing there: can't open read-only
        let r = SqliteStore::from_path_and_mistrust(tmp.path(), &mistrust, true);
        assert!(r.is_err());
        assert!(!tmp.path().join("dir_blobs").try_exists().unwrap());

        // Opening it read-write will crate the files
        {
            let mut store = SqliteStore::from_path_and_mistrust(tmp.path(), &mistrust, false)?;
            assert!(tmp.path().join("dir_blobs").is_dir());
            assert!(store.lockfile.is_some());
            assert!(!store.is_readonly());
            assert!(store.upgrade_to_readwrite()?); // no-op.
        }

        // At this point, we can successfully make a read-only connection.
        {
            let mut store2 = SqliteStore::from_path_and_mistrust(tmp.path(), &mistrust, true)?;
            assert!(store2.is_readonly());

            // Nobody else is locking this, so we can upgrade.
            assert!(store2.upgrade_to_readwrite()?); // no-op.
            assert!(!store2.is_readonly());
        }
        Ok(())
    }

    #[test]
    fn orphaned_blobs() -> Result<()> {
        let (_tmp_dir, mut store) = new_empty()?;
        /*
        for ent in store.blob_dir.read_directory(".")?.flatten() {
            println!("{:?}", ent);
        }
        */
        assert_eq!(store.blob_dir.read_directory(".")?.count(), 0);

        let now = OffsetDateTime::now_utc();
        let one_week = 1.weeks();
        let _fname_good = store.save_blob(
            b"Goodbye, dear friends",
            "greeting",
            "sha1",
            &hex!("2149c2a7dbf5be2bb36fb3c5080d0fb14cb3355c"),
            now + one_week,
        )?;
        assert_eq!(store.blob_dir.read_directory(".")?.count(), 1);

        // Now, create a two orphaned blobs: one with a recent timestamp, and one with an older
        // timestamp.
        store
            .blob_dir
            .write_and_replace("fairly_new", b"new contents will stay")?;
        store
            .blob_dir
            .write_and_replace("fairly_old", b"old contents will be removed")?;
        filetime::set_file_mtime(
            store.blob_dir.join("fairly_old")?,
            SystemTime::from(now - one_week).into(),
        )
        .expect("Can't adjust mtime");

        assert_eq!(store.blob_dir.read_directory(".")?.count(), 3);

        store.remove_unreferenced_blobs(now, &EXPIRATION_DEFAULTS)?;
        assert_eq!(store.blob_dir.read_directory(".")?.count(), 2);

        Ok(())
    }
}
