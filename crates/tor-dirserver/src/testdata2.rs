//! Test vectors for use in unit tests.
//!
//! This module is backed by `#[cfg(test)]`, meaning it will not be present in
//! production code.
//!
//! The purpose is to provide a shared set of functions/constants/etc. for use
//! in dirserver unit tests.
//!
//! These helpers assume that [`tor_netdoc`] works properly.

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
#![allow(clippy::string_slice)] // See arti#2571
//! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

use std::{
    iter,
    time::{Duration, SystemTime},
};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::named_params;
use tor_checkable::TimeBound;
use tor_dircommon::authority::{AuthorityContacts, AuthorityContactsBuilder};
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_netdoc::{
    doc::{
        authcert::{AuthCert, AuthCertUnverified},
        microdesc::Microdesc,
        netstatus::{ConsensusFlavor, md, plain},
        routerdesc::{RouterDesc, RouterDescUnverified},
    },
    parse2::{self, NetdocParseable, NetdocParseableUnverified, ParseInput, SignaturesData},
};

use crate::database::{
    self as db, AuthCertMeta, ContentEncoding, Sha1, Sha3_256, Sha256, Timestamp, sql, store_insert,
};

/// Pre-tolerance, 3 days.
const PRE_TOLERANCE: Duration = Duration::from_secs(60 * 60 * 72);

/// Post tolerance, 1 day.
const POST_TOLERANCE: Duration = Duration::from_secs(60 * 60 * 24);

/// Returns a consensus that can be used as a test vector.
///
/// We assume the consensus is valid to avoid circular dependencies with other
/// functions here.  This should be okay because these things are not intended
/// to test tor-netdoc itself.
pub(crate) fn current_consensus_ns() -> (plain::NetworkStatus, &'static str) {
    let raw = include_str!("../testdata2/cached-consensus");
    current_consensus::<plain::NetworkStatusUnverified>(raw)
}

/// [`current_consensus_ns()`] but for microdescriptor consensuses.
// TODO: Merge with current_consensus_ns() because it is repetitive.
pub(crate) fn current_consensus_md() -> (md::NetworkStatus, &'static str) {
    let raw = include_str!("../testdata2/cached-microdesc-consensus");
    current_consensus::<md::NetworkStatusUnverified>(raw)
}

/// Internal function for obtaining a consensus from a text file.
fn current_consensus<T: NetdocParseableUnverified + NetdocParseable>(
    raw: &'static str,
) -> (T::Body, &'static str) {
    let consensus = parse2::parse_netdoc::<T>(&ParseInput::new(raw, "consensus")).unwrap();
    (consensus.unwrap_unverified().0, raw)
}

/// Returns the unsigned SHA-3 of a given consensus as a string.
///
/// Required for consensus diffs.
// TODO DIRMIRROR: We *need* a method for this in tor-netdoc.
pub(crate) fn consensus_sha3(data: &str) -> Sha3_256 {
    Sha3_256::digest(
        data.split_inclusive("\ndirectory-signature ")
            .next()
            .unwrap()
            .as_bytes(),
    )
}

/// Returns the acknowledged fingerprints of the authority certificates.
///
/// Extracts them ad-hoc from testdata2/cached-certs; we acknowledge
/// all fingerprints listed their as trusted.
pub(crate) fn current_auth_cert_ids() -> Vec<RsaIdentity> {
    // Quick ad-hoc parser: Iterate line by line, use rest of line when line
    // starts with "fingerprint ".
    let raw = include_str!("../testdata2/cached-certs");
    let mut res = Vec::new();
    for line in raw.lines() {
        if let Some(fp) = line.strip_prefix("fingerprint ") {
            // Remove trailing \n.
            let fp = fp.trim();
            res.push(RsaIdentity::from_hex(fp).expect("invalid fingerprint in cached-certs?"));
        }
    }
    res
}

/// Returns the current and verified authority certificates.
pub(crate) fn current_auth_certs() -> Vec<(AuthCert, String)> {
    let raw = include_str!("../testdata2/cached-certs");
    let auth_certs = parse2::parse_netdoc_multiple_with_offsets::<AuthCertUnverified>(
        &ParseInput::new(raw, "cached-certs"),
    )
    .unwrap();

    let mut res = Vec::new();
    for (cert, start, end) in auth_certs {
        let cert = cert
            .verify(&current_auth_cert_ids())
            .unwrap()
            .if_valid_at(&valid_system_time())
            .unwrap();
        res.push((cert, raw[start..end].to_string()));
    }
    res
}

/// Returns the current [`AuthorityContacts`].
///
/// Right now, all of this is empty but it is requried at a few places regardless.
pub(crate) fn current_auth_cert_contacts() -> AuthorityContacts {
    let mut authorities = AuthorityContactsBuilder::default();
    authorities.set_v3idents(current_auth_cert_ids());
    authorities.set_downloads(vec![]);
    authorities.set_uploads(vec![]);
    authorities.set_votes(vec![]);
    authorities.build().unwrap()
}

/// Returns the current verified router descriptors, as well as their signatures.
///
/// Their signatures matter because we need their SHA-1/SHA-256.
pub(crate) fn current_router_descs()
-> Vec<(RouterDesc, SignaturesData<RouterDescUnverified>, String)> {
    let raw = include_str!("../testdata2/cached-descriptors.new");
    let routers = parse2::parse_netdoc_multiple_with_offsets::<RouterDescUnverified>(
        &ParseInput::new(raw, "cached-descriptors.new"),
    )
    .unwrap();

    let mut res = Vec::new();
    for (rd, start, end) in routers {
        // We need a tolerance here because the cached-descriptors may contain
        // descriptors not included in the current consensus, hence potentially
        // outside our current time.
        rd.clone()
            .verify()
            .unwrap()
            .extend_start_bound(PRE_TOLERANCE)
            .extend_end_bound(POST_TOLERANCE)
            .if_valid_at(&valid_system_time())
            .unwrap();
        let (body, sigs) = rd.unwrap_unverified();
        res.push((body, sigs, raw[start..end].to_string()));
    }
    res
}

/// Returns the current micro descriptors.
pub(crate) fn current_micro_descs() -> Vec<(Microdesc, String)> {
    let raw = include_str!("../testdata2/cached-microdescs.new");
    parse2::parse_netdoc_multiple_with_offsets::<Microdesc>(&ParseInput::new(
        raw,
        "cached-microdescs.new",
    ))
    .unwrap()
    .into_iter()
    .map(|(md, start, end)| (md, raw[start..end].to_string()))
    .collect()
}

/// Returns a [`SystemTime`] where the test data is valid.
///
/// It picks the middle of `fresh-until` and `valid-after` from
/// [`current_consensus_ns()`].
///
/// In other words: `valid_after + ((fresh_until - valid_after) / 2)`
///
/// Note that we still need to apply a tolerance sometimes, because the testdata
/// also contains data that is not yet published, hence not yet valid.
pub(crate) fn valid_system_time() -> SystemTime {
    let lifetime = current_consensus_ns().0.preamble.lifetime;
    let lifetime_md = current_consensus_md().0.preamble.lifetime;
    assert_eq!(lifetime, lifetime_md);
    lifetime.valid_after.0
        + lifetime
            .fresh_until
            .0
            .duration_since(lifetime.valid_after.0)
            .expect("invalid SystemTime?")
            / 2
}

/// Returns a [`SystemTime`] where the test data is not valid.
///
/// It picks [`valid_system_time()`] plus two years to ensure that even the
/// authority certificates are expired.
pub(crate) fn invalid_system_time() -> SystemTime {
    valid_system_time() + Duration::from_secs(60 * 60 * 24 * 365 * 2)
}

/// Creates a database based on data from test vectors.
///
/// The database is initialized with the following data:
/// * The database schema.
/// * [`current_consensus_ns()`] and [`current_consensus_md()`].
/// * [`current_auth_certs()`]
/// * [`current_router_descs()`].
/// * [`current_micro_descs()`].
///
/// It expects the database primitives to work properly and is intended to test
/// the actual operational aspect.
pub(crate) fn test_db() -> Pool<SqliteConnectionManager> {
    let pool = db::open("").unwrap();
    let mut conn = pool.get().unwrap();
    let tx = conn.transaction().unwrap();

    // Insert the authority certificates.
    for (cert, raw) in current_auth_certs() {
        AuthCertMeta::insert(&tx, iter::once(ContentEncoding::Identity), &cert, &raw).unwrap();
    }

    // TODO DIRMIRROR: Everything below here is very boilerplate and C&P.
    // This is because we currently lack proper insertion methods for
    // documents beside AuthCert.  Once we have them, we can replace this
    // monster with those.

    // Insert the plain consensus.
    let ns = current_consensus_ns();
    let docid = store_insert(&tx, ns.1.as_bytes(), iter::once(ContentEncoding::Identity)).unwrap();
    let unsigned_sha3_256 = consensus_sha3(ns.1);
    tx.execute(
        sql!(
            "
            INSERT INTO consensus
            (docid, unsigned_sha3_256, flavor, valid_after, fresh_until, valid_until)
            VALUES
            (:docid, :unsigned_sha3_256, :flavor, :valid_after, :fresh_until, :valid_until)
            "
        ),
        named_params! {
            ":docid": docid,
            ":unsigned_sha3_256": unsigned_sha3_256,
            ":flavor": ConsensusFlavor::Plain.name(),
            ":valid_after": Timestamp::from(ns.0.preamble.lifetime.valid_after.0),
            ":fresh_until": Timestamp::from(ns.0.preamble.lifetime.fresh_until.0),
            ":valid_until": Timestamp::from(ns.0.preamble.lifetime.valid_until.0),
        },
    )
    .unwrap();

    // Insert the consensus/desc relationship.
    for relay in &ns.0.routers {
        tx.execute(
            sql!(
                "
                INSERT INTO consensus_router_descriptor_member
                (consensus_docid, unsigned_sha1, unsigned_sha2)
                VALUES
                (:consensus_docid, :unsigned_sha1, NULL)
                "
            ),
            named_params! {
                ":consensus_docid": docid,
                ":unsigned_sha1": Sha1::from(relay.doc_digest().clone())
            },
        )
        .unwrap();
    }

    // Insert the router descriptors.
    for (rd, rd_sigs, raw) in current_router_descs() {
        let docid =
            store_insert(&tx, raw.as_bytes(), iter::once(ContentEncoding::Identity)).unwrap();
        let sha1 = Sha1::from(rd_sigs.hashes.sha1.unwrap());
        let sha2 = Sha256::from(rd_sigs.hashes.sha256.unwrap());

        tx.execute(
            sql!(
                "
                INSERT INTO router_descriptor
                (docid, unsigned_sha1, unsigned_sha2, kp_relay_id_rsa_sha1, flavor, extra_unsigned_sha1)
                VALUES
                -- TODO DIRMIRROR: Support extra-info.
                (:docid, :sha1, :sha2, :fingerprint, :flavor, NULL)
                "
            ),
            named_params! {
                ":docid": docid,
                ":sha1": sha1,
                ":sha2": sha2,
                ":fingerprint": Sha1::from(rd.signing_key.to_rsa_identity().to_bytes()),
                ":flavor": ConsensusFlavor::Plain.name()
            },
        )
        .unwrap();
    }

    // Insert the microdesc consensus (mostly a copy of the above code).
    // Yes, this is not super nice but will hopefully be solved when we have
    // a ConsensusMeta::insert() method.
    let md = current_consensus_md();
    let docid = store_insert(&tx, md.1.as_bytes(), iter::once(ContentEncoding::Identity)).unwrap();
    let unsigned_sha3_256 = consensus_sha3(md.1);
    tx.execute(
        sql!(
            "
            INSERT INTO consensus
            (docid, unsigned_sha3_256, flavor, valid_after, fresh_until, valid_until)
            VALUES
            (:docid, :unsigned_sha3_256, :flavor, :valid_after, :fresh_until, :valid_until)
            "
        ),
        named_params! {
            ":docid": docid,
            ":unsigned_sha3_256": unsigned_sha3_256,
            ":flavor": ConsensusFlavor::Microdesc.name(),
            ":valid_after": Timestamp::from(md.0.preamble.lifetime.valid_after.0),
            ":fresh_until": Timestamp::from(md.0.preamble.lifetime.fresh_until.0),
            ":valid_until": Timestamp::from(md.0.preamble.lifetime.valid_until.0),
        },
    )
    .unwrap();

    // Insert the consensus-md/desc relationship.
    for relay in &md.0.routers {
        tx.execute(
            sql!(
                "
                -- TODO DIRMIRROR: Change table name to descriptor only, as it
                -- obviously also contains microdesc relationships.
                INSERT INTO consensus_router_descriptor_member
                (consensus_docid, unsigned_sha1, unsigned_sha2)
                VALUES
                (:consensus_docid, NULL, :unsigned_sha2)
                "
            ),
            named_params! {
                ":consensus_docid": docid,
                ":unsigned_sha2": Sha256::from(relay.doc_digest().clone())
            },
        )
        .unwrap();
    }

    // Insert the actual micro descriptors.
    for (_md, raw) in current_micro_descs() {
        let docid =
            store_insert(&tx, raw.as_bytes(), iter::once(ContentEncoding::Identity)).unwrap();
        // Microdescs contain no signature, so the hash goes over everything.
        let sha1 = Sha1::digest(raw.as_bytes());
        let sha2 = Sha256::digest(raw.as_bytes());
        tx.execute(
            sql!(
                "
                -- TODO DIRMIRROR: Same naming issue here.
                INSERT INTO router_descriptor
                (docid, unsigned_sha1, unsigned_sha2, kp_relay_id_rsa_sha1, flavor, extra_unsigned_sha1)
                VALUES
                (:docid, :sha1, :sha2, NULL, :flavor, NULL)
                "
            ),
            named_params! {
                ":docid": docid,
                ":sha1": sha1,
                ":sha2": sha2,
                ":flavor": ConsensusFlavor::Microdesc.name(),
            }
        ).unwrap();
    }

    tx.commit().unwrap();
    pool
}
