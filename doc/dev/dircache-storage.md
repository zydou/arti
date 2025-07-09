# Dircache Storage

This document tries to explain the storage model on how the dircache stores
data internally.

## Requirements

1. Be fault resilient (e.g. power-loss/sudden crashes *MUST NOT* result in data loss)
2. Be fast with lookups by various keys (e.g. fingerprint, digest, ...)
3. Have everything in one place
4. Avoid redundant copies of (frequently used) data

## SQLite as the fundamental primitive

*SQLite* has been chosen as the primitive data storage back-end, because it
offers a neat read performance and acceptable write performance, although the
latter one is more critical for dirauths rather than dircaches due to the
frequently uploaded descriptors and data; besides it satisfies the first two
requirements trivially and the latter two if we add certain constraints outlined
below.

## Future extension towards a dirauth

A dircache forms the basis of a dirauth.  The current plan is to design the
dircache as an independent component of which the dirauth related code is merely
an extension.  Due to this design decision, all dirauth related data structures
*SHOULD* have their own tables.

## Caching as a middle layer

As outlined above, we want to avoid having the same data multiple times in
memory.  Let's say we serve the same request a thousand times in parallel,
then we do not want to store the same data 10,000 times in memory but rather
only once.

The goal of the cache *IS NOT* to reduce the number of disk reads for frequently
requested data.  We rely on SQLite internals and the operating system's buffer
cache to handle this well-enough for us.  Besides, in times of solid state
drives, disk access is in the microseconds and no longer a bottle neck as it
once used to be.

The cache is implemented by a
```rust
type CacheData = Arc<[u8]>;
type Cache = RwLock<HashMap<Sha256, CacheData>>;
```

## Compression

## Structure of the database

The database schema consists of two types of tables:
* Document tables
	* Represent actual documents that are served by the dircache
	* Those documents are: consensuses, consensus diffs, authority information,
	  router descriptors, and extra-info documents
* Helper tables
	* Tables that contain additional information about documents we serve
	* For example: compressed data, authority votes on consensuses, ...

A *document table* has a few mandatory columns, whereas *helper tables* are too
domain specific to impose any restrictions on them.

A *document table* *MUST* the following columns:
* `rowid`
	* Serves as the primary key
* `content`
	* The actual raw content of the document
	* *MUST* be valid UTF-8 under all circumstandes
* `content_sha256`
	* Uniquely identifies and addresses the data by `content`

Besides, every document table *MUST* have an index on `content_sha256` as well
as any other key by which clients may query it. (Such as the fingerprint for
router descriptors).

All hash values are stored in upper-case hexadecimal.

The actual SQL schema is outlined below:
```sql
PRAGMA foreign_keys = ON;
PRAGMA journal_mode=WAL;

-- Meta table to store the current schema version.
CREATE TABLE arti_dircache_schema_version(
	version	TEXT NOT NULL -- currently, always `1`
) STRICT;

-- Stores consensuses.
--
-- http://<hostname>/tor/status-vote/current/consensus-<FLAVOR>
-- http://<hostname>/tor/status-vote/current/consensus-<FLAVOR>/<F1>+<F2>+<F3>
-- http://<hostname>/tor/status-vote/current/consensus-<FLAVOR>/diff/<HASH>/<FPRLIST>
CREATE TABLE consensus(
	rowid				INTEGER PRIMARY KEY AUTOINCREMENT,
	content				TEXT NOT NULL,
	content_sha256		TEXT NOT NULL UNIQUE,
	unsigned_sha3_256	TEXT NOT NULL UNIQUE,
	flavor				TEXT NOT NULL,
	valid_after			INTEGER NOT NULL,
	fresh_until			INTEGER NOT NULL,
	valid_until			INTEGER NOT NULL,
	CHECK(LENGTH(content_sha256) == 64),
	CHECK(LENGTH(unsigned_sha3_256) == 64),
	CHECK(flavor IN ('ns', 'md'))
) STRICT;

-- Stores consensus diffs.
--
-- http://<hostname>/tor/status-vote/current/consensus-<FLAVOR>/diff/<HASH>/<FPRLIST>
CREATE TABLE consensus_diff(
	rowid				INTEGER PRIMARY KEY AUTOINCREMENT,
	content				TEXT NOT NULL,
	content_sha256		TEXT NOT NULL UNIQUE,
	old_consensus_rowid	INTEGER NOT NULL,
	new_consensus_rowid	INTEGER NOT NULL,
	FOREIGN KEY(old_consensus_rowid) REFERENCES consensus(rowid),
	FOREIGN KEY(new_consensus_rowid) REFERENCES consensus(rowid),
	CHECK(LENGTH(content_sha256) == 64)
) STRICT;

-- Stores the router descriptors.
--
-- http://<hostname>/tor/server/fp/<F>
-- http://<hostname>/tor/server/d/<D>
-- http://<hostname>/tor/server/authority
-- http://<hostname>/tor/server/all
CREATE TABLE router_descriptor(
	rowid					INTEGER PRIMARY KEY AUTOINCREMENT,
	content					TEXT NOT NULL,
	content_sha256			TEXT NOT NULL UNIQUE,
	content_sha1			TEXT NOT NULL UNIQUE,
	kp_relay_id_rsa_sha1	TEXT NOT NULL,
	flavor					TEXT NOT NULL,
	router_extra_info_rowid	INTEGER,
	FOREIGN KEY(router_extra_info_rowid) REFERENCES router_extra_info(rowid),
	CHECK(LENGTH(content_sha256) == 64),
	CHECK(LENGTH(content_sha1) == 40),
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
	rowid					INTEGER PRIMARY KEY AUTOINCREMENT,
	content					TEXT NOT NULL,
	content_sha256			TEXT NOT NULL UNIQUE,
	content_sha1			TEXT NOT NULL UNIQUE,
	kp_relay_id_rsa_sha1	TEXT NOT NULL,
	CHECK(LENGTH(content_sha256) == 64),
	CHECK(LENGTH(content_sha1) == 40),
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
	rowid					INTEGER PRIMARY KEY AUTOINCREMENT,
	content					TEXT NOT NULL,
	content_sha256			TEXT NOT NULL UNIQUE,
	kp_auth_id_rsa_sha1		TEXT NOT NULL,
	kp_auth_sign_rsa_sha1	TEXT NOT NULL,
	dir_key_expires			INTEGER NOT NULL,
	CHECK(LENGTH(content_sha256) == 64),
	CHECK(LENGTH(kp_auth_id_rsa_sha1) == 40),
	CHECK(LENGTH(kp_auth_sign_rsa_sha1) == 40)

) STRICT;

-- Stores compressed network documents.
--
-- Garbage collection works by scanning all `content_sha256` columns in the
-- relevant tables and then deleting all rows in `compressed_document` whose
-- `identity_sha256` is not in the set retrieved prior.
CREATE TABLE compressed_document(
	rowid				INTEGER PRIMARY KEY AUTOINCREMENT,
	algorithm			TEXT NOT NULL,
	identity_sha256		TEXT NOT NULL,
	compressed_sha256	TEXT NOT NULL,
	compressed			BLOB NOT NULL,
	CHECK(LENGTH(identity_sha256) == 64),
	CHECK(LENGTH(compressed_sha256) == 64),
	UNIQUE(algorithm, identity_sha256)
) STRICT;

-- Stores the N:M cardinality of which router descriptors are contained in which
-- consensuses.
CREATE TABLE consensus_router_descriptor_member(
	consensus_rowid			INTEGER,
	router_descriptor_rowid INTEGER,
	PRIMARY KEY(consensus_rowid, router_descriptor_rowid),
	FOREIGN KEY(consensus_rowid) REFERENCES consensus(rowid),
	FOREIGN KEY(router_descriptor_rowid) REFERENCES router_descriptor(rowid)
) STRICT;

-- Stores which authority key signed which consensuses.

-- Required to implement the consensus retrieval by authority fingerprints as
-- well as the garbage collection of authority key certificates.
--
-- http://<hostname>/tor/status-vote/current/consensus-<FLAVOR>/<F1>+<F2>+<F3>
CREATE TABLE consensus_authority_voter(
	consensus_rowid	INTEGER,
	authority_rowid	INTEGER,
	PRIMARY KEY(consensus_rowid, authority_rowid),
	FOREIGN KEY(consensus_rowid) REFERENCES consensus(rowid),
	FOREIGN KEY(authority_rowid) REFERENCES authority_key_certificate(rowid)
) STRICT;
```

## General operations

The following outlines some pseudo code for common operations.

### Insertion of a new consensus

This one explains how we insert a new consensus into the dircache.
It works similarly for `consensus-md`.

1. Download the consensus from an authority
2. Parse and validate it accordingly to the specification
3. Figure out the missing router descriptors and extra-info documents
4. Compute consensus diffs
5. Compute compressions
6. Insert everything in one transaction into the database and update the
   `last_seen` fields.
7. Asnchronously download missing router descriptors and extra-info documents
   from the directory authorities and modify the database as it goes along.

### Request of an arbitrary document

The following models in pseudo code on how a network document is queried and
served:
1. Search for the appropriate document and store `content_sha256`
2. Check whether the `content_sha256` is in the cache
	* If so, clone the `Arc`
	* If not, query `content` with `WHERE content_sha256 = ?` and insert it into
	  the cache
3. Transmit the data to the client
4. Check whether the reference counter is `1` (Controversial, see "Cleaning the cache")
	* If so, remove `content_sha256` entirely from the cache, as we are the last
	  active server of the resource.
	* If not, do nothing except.
	* For improving the development experience, it is probably best to implement
	  that in a `Drop` trait.

TODO: Do this for compression, I doubt it will be much different though ...

Below is some Rust-like pseudo code demonstrating it.
It follows a locking hierarchy where none of the locks (db and cache) may be
held simultaneously.
```rust
// (1)
let sha256 = db.transaction().query("SELECT content_sha256 FROM table WHERE column_name = column_value");

let content = if let Some(content) = cache.read().get(sha256).map(Arc::clone) {
	// We have to use `get` here if we want to use temporary locks.
	content
} else {
	// Read from db and insert into cache.
	// `db` and `cache` are not hold simultaneously but only for each operation.
	let content = Arc::new(db.transaction().query(format!("SELECT content FROM table WHERE content_sha256 = {sha256}")));
	// We have to use entry here in order to avoid duplicate cache writes in the
	// case of a parallel cache miss.
	cache.write().entry(sha256).or_insert(Arc::clone(&content));
	content
};
```

### Example `SELECT` queries

* Query a consensus:
	```sql
	SELECT content_sha256
	FROM consensus
	WHERE flavor = 'ns'
	ORDER BY valid_after DESC
	LIMIT 1;
	```
* Query a consensus diff from a given hash `HHH` to the newest consensus:
	```sql
	SELECT content_sha256
	FROM consensus_diff
	WHERE old_consensus_rowid = (
		SELECT rowid
		FROM consensus
		WHERE flavor = 'ns' AND content_sha3_256 = 'HHH'
	) AND new_consensus_rowid = (
		SELECT rowid
		FROM consensus
		WHERE flavor = 'ns'
		ORDER BY valid_after DESC
		LIMIT 1
	);
	```
* Obtain the key certificate of a certain authority:
	```sql
	SELECT content_sha256
	FROM authority_key_certificate
	WHERE kp_auth_id_rsa_sha1 = 'HHH'
	ORDER BY dir_key_expires DESC
	LIMIT 1;
	```
* Obtain a specific router's descriptor:
	```sql
	SELECT content_sha256
	FROM router_descriptor AS rd
	INNER JOIN consensus_router_descriptor_member AS crdm
	ON rd.rowid = crdm.router_descriptor_rowid
	INNER JOIN consensus AS c
	ON crdm.consensus_rowid = c.rowid
	WHERE rd.kp_relay_id_rsa_sha1 = 'HHH'
	AND rd.flavor = 'ns'
	ORDER BY c.valid_after DESC
	LIMIT 1;
	```
* Obtain extra-info:
	```sql
	SELECT content_sha256
	FROM router_extra_info
	WHERE rowid = (
		SELECT content_sha256
		FROM router_descriptor AS rd
		INNER JOIN consensus_router_descriptor_member AS crdm
		ON rd.rowid = crdm.router_descriptor_rowid
		INNER JOIN consensus AS c
		ON crdm.consensus_rowid = c.rowid
		WHERE rd.kp_relay_id_rsa_sha1 = 'HHH'
		AND rd.flavor = 'ns'
		ORDER BY c.valid_after DESC
		LIMIT 1;
	);
	```

### Garbage Collection

Over time, the dircache will collect some garbage.  This is intentional,
as various documents are not deleted the moment they are no longer listed in
a consensus.

```sql
BEGIN TRANSACTION;

-- GC the consensus.
-- Store the rowids of all consensuses older than seven days.
SELECT rowid FROM consensus WHERE valid_after <= (UNIXEPOCH() - 604800);
DELETE FROM consensus_router_descriptor_member WHERE consensus_rowid IN (???);
DELETE FROM consensus_authority_voter WHERE consensus_rowid IN (???);
DELETE FROM consensus_diff WHERE old_consensus_rowid IN (???) OR new_consensus_rowid IN (???);
DELETE FROM consensus WHERE rowid IN (???);

-- GC the router descriptors.
-- Store the rowids of all router descriptors not listed in a consensus.
-- TODO: We need an additional column when we are going to add dirauth stuff.
SELECT rowid FROM router_descriptor WHERE rowid NOT IN (
	SELECT router_descriptor_rowid FROM consensus_router_descriptor_member
);
DELETE FROM router_descriptor WHERE rowid IN (???);

-- GC the extra info documents.
DELETE FROM router_extra_info WHERE rowid NOT IN (
	SELECT router_extra_info FROM router_descriptor
);

-- GC the authority_key_certificates.
DELETE FROM authority_key_certificate WHERE dir_key_expires <= UNIXEPOCH();

-- GC the compressed documents.
DELETE FROM compressed_document WHERE identity_sha256 NOT IN (
	SELECT content_sha256 FROM consensus UNION SELECT content_sha256 FROM consensus_diff
);

COMMIT;
```

## Cleaning the cache

Right now, there are the following proposals for cleaning the cache:

1. Utilize `Drop` traits
* A wrapper around the end of each HTTP callback which checks the `Arc`'s
	  reference count and deletes it in the case that it is currently no longer
	  used by any other active HTTP request.
	  The wrapper must contain a clone of the `Arc<RwLock<HashMap<..>>>`.
	  This is the approach presented in the text above.
2. Put `Weak` in the hash map.  Clean up dangling entries later.
    * Using `Weak` in the map means data is discarded as soon as it's no
          longer being served, but leaves dangling entries in the `HashMap`.
	* Periodically scan the `HashMap` for dangling `Weak`s.  This could
	  be done with an asynchronous task, or after database garbage collection..
3. Use `WeakValueHashMap` from [weak-tables](https://doc.rs/weak-table) (most likely)
	* A hash map where values are stored in hash table alongside a reference counter like structure
	* Once the reference counter goes to zero, entries are lazily removed

## HTTP backend

The current plan is to use warp as the HTTP backend.

## SQL backend

The current plan is to use SQLx as the SQL backend.

## Appendix - Memory usage and DoS; the case against mmap

A dircache is very exposed and must be as resistant to DoS as we can
make it.  We here analyse the memory usage and access patterns of the
planned design.  We consider the alternative of using mmap to
explicitly map persistent disk files containing the network documents.

### Terminology and concepts

* **in-memory cache**: The in memory `HashMap` indexed by document
  SHA256, as proposed above.

* **page cache**: The operating system's use of actual RAM as backing
  for process memory pages (ie, memory from malloc etc.), file data
  (whether accessed by `read`/`write` or `mmap`), etc.
  Most modern operating systems have one page cache, unifying the
  filesystem buffer cache with memory allocated by programs.

* **working set**: The data that a program accesses during
  operation, as opposed to data which is technically mapped or
  available, but in practice not frequnetly used.  The working set
  can include parts of disk files; conversely, not all allocated
  pages are part of the working set.

* **malloc**: We speak (rather loosely) of malloc when we mean
  process memory allocated from the OS or language general purpose
  allocator, including Rust's global allocator.  The memory obtained
  this way itself mmap'd.  (On Linux, but it has has similar
  performance characteristics on other systems.)

* **explicit mmap*: alternative designs (eg as found in tor-dirmgr)
  where document data (including expensively-compressed documents and
  diffs) is stored in persistent disk files, and queries are served
  by explicitly mmapping those files.

* **superpage**: page table entry, and therefore TLB entry, which
  covers a large (typically Mb rather than Kb) amount of virtual
  address space and a large amount of physical memory.  Modern
  systems use these when possible, because they reduce TLB misses.

* **TLB**: Translation Lookaside Buffer.  The cache of
  virtual-to-physical mappings maintained by the virtual memory
  system.  A TLB miss is typically expensive.

### Memory usage - in-memory cache size

In a worst case scenario, a combination of clients could force us to
populate the in-memory cache with every router descriptor, consensus
and extra-info document we are willing so serve.

In more detail:

* The total size of a current consensus plus all of its routerdescs and
  extra-infos is around 100Mbytes.

* We must also maintain old router documents for a period of time,
  along with old consensuses.  The total proportion of churn is
  considerably smaller than the whole consensus.

* We must also store the micordesc flavour documents.
  Again, these are smaller.

* We will store consensus document diffs between various versions,
  and compressed versions of these, but even a whole full consensus
  is only a few Mb so this is not very significant.  (We do not store
  compressed routerdescs or extra-infos.)

We don't expect the overall size of all these documents to exceed
200Mby (scaling with the Tor network size).  This seems reasonable.

### Working set, the buffer/page cache, and mmap

If the total size of documents we might be serving exceeds the
server's available actual RAM, then the operating system will need to
page out some of our data, so that it later has to be re-read from
slow storage (hopefully SSD).  This is not desirable, but it is
inevitable, no matter the storage and data access approach.

It would be possible to use mmap explicitly, instead of sqlite queries
which copy the data.

That would reduce the amount of memory we obtain from malloc.  But it
has a limited effect on the program's working set: with mmap, the
operating system still needs to load the data into memory to be able
to transmit it, and if it doesn't all fit, it will need to repeatedly
read it from the disk into the buffer/page cache, as it serves each
request.

The main benefit of explicit mmap files would be to reduces the number
of copies of the document data.  The current design drops a document
from the in-memory cache as soon as no request is streaming it out any
more.

So documents are frequently copied out of the database (ie, in
practice, from the page cache) into the in-memory cache (another set
of pages in the page cache), possibly once on every request.

This means the effective working set of the program is doubled: one
copy for the database's pages, and one copy from malloc.

### Working set and copy reduction - cache entry lifetime extension

We could extend the lifetime of entries in the in-memory cache, using
time-based expiry based on something near the lifetime of a consensus.

With such a design, steady state operation does not involve
significant amounts of copying of document text out of the db.

The working set would be the in-memory cache plus the pages for the
database *indexes* only, so about half of the current design.

We will implement this if experience shows that it's necessary.

#### Comparison with explicit mmap

This extension to the current design would offer performance
characteristics very similar to those of explicitly mmap.

The main difference is the effects of a restart: explicit mmap would
avoids the need for (on-demand) population of the in-memory cache.  So
its performance after restart would be better, until it reaches steady
state, and it would impose less wear on the system's storage.

Another performance-relevant difference is that mmaping many
persistent files corresponding to network documents would fragment the
process memory map.  There would be less use of superpages and greater
TLB pressure.  Performance in the steady state might be worse than the
current design with cache entry lifetime extension.

We do not consider the possible benefits to warrant the considerable
additional complexity needed to manage outside-database persistent
files, that we explicitly mmap.

### Implicit mmap by sqlite

sqlite3 is [capable of mmapping its database file](https://www.sqlite.org/mmap.html).
Using this feature might improve performance.

A possible downside is that we need to be using a pool of sqlite3
connections since a sqlite3 connection is not threadsafe, and each
connection would need its own mmap region.  Tuning this seems not
entirely obvious.

We might consider this as part of future perf work.

But note that this question is entirely separate from alternative
dircache designs using explicit mmap.  Even if sqlite is using mmap
internally, it does not expose its mmapped data to the calling
application.  That would be difficult for sqlite to expose, because
interactions with SQL concurrent transactions would require complex
and error-prone map invalidation and/or garbage collection.
