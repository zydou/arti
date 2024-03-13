//! Declare a general purpose "document ID type" for tracking which
//! documents we want and which we have.

use std::collections::HashMap;
use tracing::trace;

use crate::storage::Store;
use crate::DocumentText;
use tor_dirclient::request;
#[cfg(feature = "routerdesc")]
use tor_netdoc::doc::routerdesc::RdDigest;
use tor_netdoc::doc::{authcert::AuthCertKeyIds, microdesc::MdDigest, netstatus::ConsensusFlavor};

/// The identity of a single document, in enough detail to load it
/// from storage.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
#[non_exhaustive]
pub enum DocId {
    /// A request for the most recent consensus document.
    LatestConsensus {
        /// The flavor of consensus to request.
        flavor: ConsensusFlavor,
        /// Rules for loading this consensus from the cache.
        cache_usage: CacheUsage,
    },
    /// A request for an authority certificate, by the SHA1 digests of
    /// its identity key and signing key.
    AuthCert(AuthCertKeyIds),
    /// A request for a single microdescriptor, by SHA256 digest.
    Microdesc(MdDigest),
    /// A request for the router descriptor of a public relay, by SHA1
    /// digest.
    #[cfg(feature = "routerdesc")]
    RouterDesc(RdDigest),
}

/// The underlying type of a DocId.
///
/// Documents with the same type can be grouped into the same query; others
/// cannot.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[non_exhaustive]
pub(crate) enum DocType {
    /// A consensus document
    Consensus(ConsensusFlavor),
    /// An authority certificate
    AuthCert,
    /// A microdescriptor
    Microdesc,
    /// A router descriptor.
    #[cfg(feature = "routerdesc")]
    RouterDesc,
}

impl DocId {
    /// Return the associated doctype of this DocId.
    pub(crate) fn doctype(&self) -> DocType {
        use DocId::*;
        use DocType as T;
        match self {
            LatestConsensus { flavor: f, .. } => T::Consensus(*f),
            AuthCert(_) => T::AuthCert,
            Microdesc(_) => T::Microdesc,
            #[cfg(feature = "routerdesc")]
            RouterDesc(_) => T::RouterDesc,
        }
    }
}

/// A request for a specific kind of directory resource that a DirMgr can
/// request.
#[derive(Clone, Debug)]
pub(crate) enum ClientRequest {
    /// Request for a consensus
    Consensus(request::ConsensusRequest),
    /// Request for one or more authority certificates
    AuthCert(request::AuthCertRequest),
    /// Request for one or more microdescriptors
    Microdescs(request::MicrodescRequest),
    /// Request for one or more router descriptors
    #[cfg(feature = "routerdesc")]
    RouterDescs(request::RouterDescRequest),
}

impl ClientRequest {
    /// Turn a ClientRequest into a Requestable.
    pub(crate) fn as_requestable(&self) -> &(dyn request::Requestable + Send + Sync) {
        use ClientRequest::*;
        match self {
            Consensus(a) => a,
            AuthCert(a) => a,
            Microdescs(a) => a,
            #[cfg(feature = "routerdesc")]
            RouterDescs(a) => a,
        }
    }
}

/// Description of how to start out a given bootstrap attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CacheUsage {
    /// The bootstrap attempt will only use the cache.  Therefore, don't
    /// load a pending consensus from the cache, since we won't be able
    /// to find enough information to make it usable.
    CacheOnly,
    /// The bootstrap attempt is willing to download information or to
    /// use the cache.  Therefore, we want the latest cached
    /// consensus, whether it is pending or not.
    CacheOkay,
    /// The bootstrap attempt is trying to fetch a new consensus. Therefore,
    /// we don't want a consensus from the cache.
    MustDownload,
}

impl CacheUsage {
    /// Turn this CacheUsage into a pending field for use with
    /// SqliteStorage.
    pub(crate) fn pending_requirement(&self) -> Option<bool> {
        match self {
            CacheUsage::CacheOnly => Some(false),
            _ => None,
        }
    }
}

/// A group of DocIds that can be downloaded or loaded from the database
/// together.
///
/// TODO: Perhaps this should be the same as ClientRequest?
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DocQuery {
    /// A request for the latest consensus
    LatestConsensus {
        /// A desired flavor of consensus
        flavor: ConsensusFlavor,
        /// Whether we can or must use the cache
        cache_usage: CacheUsage,
    },
    /// A request for authority certificates
    AuthCert(Vec<AuthCertKeyIds>),
    /// A request for microdescriptors
    Microdesc(Vec<MdDigest>),
    /// A request for router descriptors
    #[cfg(feature = "routerdesc")]
    RouterDesc(Vec<RdDigest>),
}

impl DocQuery {
    /// Construct an "empty" docquery from the given DocId
    pub(crate) fn empty_from_docid(id: &DocId) -> Self {
        match *id {
            DocId::LatestConsensus {
                flavor,
                cache_usage,
            } => Self::LatestConsensus {
                flavor,
                cache_usage,
            },
            DocId::AuthCert(_) => Self::AuthCert(Vec::new()),
            DocId::Microdesc(_) => Self::Microdesc(Vec::new()),
            #[cfg(feature = "routerdesc")]
            DocId::RouterDesc(_) => Self::RouterDesc(Vec::new()),
        }
    }

    /// Add `id` to this query, if possible.
    fn push(&mut self, id: DocId) {
        match (self, id) {
            (Self::LatestConsensus { .. }, DocId::LatestConsensus { .. }) => {}
            (Self::AuthCert(ids), DocId::AuthCert(id)) => ids.push(id),
            (Self::Microdesc(ids), DocId::Microdesc(id)) => ids.push(id),
            #[cfg(feature = "routerdesc")]
            (Self::RouterDesc(ids), DocId::RouterDesc(id)) => ids.push(id),
            (_, _) => panic!(),
        }
    }

    /// If this query contains too many documents to download with a single
    /// request, divide it up.
    pub(crate) fn split_for_download(self) -> Vec<Self> {
        use DocQuery::*;
        /// How many objects can be put in a single HTTP GET line?
        const N: usize = 500;
        match self {
            LatestConsensus { .. } => vec![self],
            AuthCert(mut v) => {
                v.sort_unstable();
                v[..].chunks(N).map(|s| AuthCert(s.to_vec())).collect()
            }
            Microdesc(mut v) => {
                v.sort_unstable();
                v[..].chunks(N).map(|s| Microdesc(s.to_vec())).collect()
            }
            #[cfg(feature = "routerdesc")]
            RouterDesc(mut v) => {
                v.sort_unstable();
                v[..].chunks(N).map(|s| RouterDesc(s.to_vec())).collect()
            }
        }
    }

    /// Load documents specified by this `DocQuery` from the store, if they can be found.
    ///
    /// # Note
    ///
    /// This function may not return all documents that the query asked for. If this happens, no
    /// error will be returned. It is the caller's responsibility to handle this case.
    pub(crate) fn load_from_store_into(
        &self,
        result: &mut HashMap<DocId, DocumentText>,
        store: &dyn Store,
    ) -> crate::Result<()> {
        use DocQuery::*;
        match self {
            LatestConsensus {
                flavor,
                cache_usage,
            } => {
                if *cache_usage == CacheUsage::MustDownload {
                    // Do nothing: we don't want a cached consensus.
                    trace!("MustDownload is set; not checking for cached consensus.");
                } else if let Some(c) =
                    store.latest_consensus(*flavor, cache_usage.pending_requirement())?
                {
                    trace!("Found a reasonable consensus in the cache");
                    let id = DocId::LatestConsensus {
                        flavor: *flavor,
                        cache_usage: *cache_usage,
                    };
                    result.insert(id, c.into());
                }
            }
            AuthCert(ids) => result.extend(
                store
                    .authcerts(ids)?
                    .into_iter()
                    .map(|(id, c)| (DocId::AuthCert(id), DocumentText::from_string(c))),
            ),
            Microdesc(digests) => {
                result.extend(
                    store
                        .microdescs(digests)?
                        .into_iter()
                        .map(|(id, md)| (DocId::Microdesc(id), DocumentText::from_string(md))),
                );
            }
            #[cfg(feature = "routerdesc")]
            RouterDesc(digests) => result.extend(
                store
                    .routerdescs(digests)?
                    .into_iter()
                    .map(|(id, rd)| (DocId::RouterDesc(id), DocumentText::from_string(rd))),
            ),
        }
        Ok(())
    }
}

impl From<DocId> for DocQuery {
    fn from(d: DocId) -> DocQuery {
        let mut result = DocQuery::empty_from_docid(&d);
        result.push(d);
        result
    }
}

/// Given a list of DocId, split them up into queries, by type.
pub(crate) fn partition_by_type<T>(collection: T) -> HashMap<DocType, DocQuery>
where
    T: IntoIterator<Item = DocId>,
{
    let mut result = HashMap::new();
    for item in collection.into_iter() {
        let tp = item.doctype();
        result
            .entry(tp)
            .or_insert_with(|| DocQuery::empty_from_docid(&item))
            .push(item);
    }
    result
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
    use tor_basic_utils::test_rng::testing_rng;

    #[test]
    fn doctype() {
        assert_eq!(
            DocId::LatestConsensus {
                flavor: ConsensusFlavor::Microdesc,
                cache_usage: CacheUsage::CacheOkay,
            }
            .doctype(),
            DocType::Consensus(ConsensusFlavor::Microdesc)
        );

        let auth_id = AuthCertKeyIds {
            id_fingerprint: [10; 20].into(),
            sk_fingerprint: [12; 20].into(),
        };
        assert_eq!(DocId::AuthCert(auth_id).doctype(), DocType::AuthCert);

        assert_eq!(DocId::Microdesc([22; 32]).doctype(), DocType::Microdesc);
        #[cfg(feature = "routerdesc")]
        assert_eq!(DocId::RouterDesc([42; 20]).doctype(), DocType::RouterDesc);
    }

    #[test]
    fn partition_ids() {
        let mut ids = Vec::new();
        for byte in 0..=255 {
            ids.push(DocId::Microdesc([byte; 32]));
            #[cfg(feature = "routerdesc")]
            ids.push(DocId::RouterDesc([byte; 20]));
            ids.push(DocId::AuthCert(AuthCertKeyIds {
                id_fingerprint: [byte; 20].into(),
                sk_fingerprint: [33; 20].into(),
            }));
        }
        let consensus_q = DocId::LatestConsensus {
            flavor: ConsensusFlavor::Microdesc,
            cache_usage: CacheUsage::CacheOkay,
        };
        ids.push(consensus_q);

        let split = partition_by_type(ids);
        #[cfg(feature = "routerdesc")]
        assert_eq!(split.len(), 4); // 4 distinct types.
        #[cfg(not(feature = "routerdesc"))]
        assert_eq!(split.len(), 3); // 3 distinct types.

        let q = split
            .get(&DocType::Consensus(ConsensusFlavor::Microdesc))
            .unwrap();
        assert!(matches!(q, DocQuery::LatestConsensus { .. }));

        let q = split.get(&DocType::Microdesc).unwrap();
        assert!(matches!(q, DocQuery::Microdesc(v) if v.len() == 256));

        #[cfg(feature = "routerdesc")]
        {
            let q = split.get(&DocType::RouterDesc).unwrap();
            assert!(matches!(q, DocQuery::RouterDesc(v) if v.len() == 256));
        }
        let q = split.get(&DocType::AuthCert).unwrap();
        assert!(matches!(q, DocQuery::AuthCert(v) if v.len() == 256));
    }

    #[test]
    fn split_into_chunks() {
        use std::collections::HashSet;
        //use itertools::Itertools;
        use rand::Rng;

        // Construct a big query.
        let mut rng = testing_rng();
        let ids: HashSet<MdDigest> = (0..3400).map(|_| rng.gen()).collect();

        // Test microdescs.
        let split = DocQuery::Microdesc(ids.clone().into_iter().collect()).split_for_download();
        assert_eq!(split.len(), 7);
        let mut found_ids = HashSet::new();
        for q in split {
            match q {
                DocQuery::Microdesc(ids) => ids.into_iter().for_each(|id| {
                    found_ids.insert(id);
                }),
                _ => panic!("Wrong type."),
            }
        }
        assert_eq!(found_ids.len(), 3400);
        assert_eq!(found_ids, ids);

        // Test routerdescs.
        #[cfg(feature = "routerdesc")]
        {
            let ids: HashSet<RdDigest> = (0..1001).map(|_| rng.gen()).collect();
            let split =
                DocQuery::RouterDesc(ids.clone().into_iter().collect()).split_for_download();
            assert_eq!(split.len(), 3);
            let mut found_ids = HashSet::new();
            for q in split {
                match q {
                    DocQuery::RouterDesc(ids) => ids.into_iter().for_each(|id| {
                        found_ids.insert(id);
                    }),
                    _ => panic!("Wrong type."),
                }
            }
            assert_eq!(found_ids.len(), 1001);
            assert_eq!(&found_ids, &ids);
        }

        // Test authcerts.
        let ids: HashSet<AuthCertKeyIds> = (0..2500)
            .map(|_| {
                let id_fingerprint = rng.gen::<[u8; 20]>().into();
                let sk_fingerprint = rng.gen::<[u8; 20]>().into();
                AuthCertKeyIds {
                    id_fingerprint,
                    sk_fingerprint,
                }
            })
            .collect();
        let split = DocQuery::AuthCert(ids.clone().into_iter().collect()).split_for_download();
        assert_eq!(split.len(), 5);
        let mut found_ids = HashSet::new();
        for q in split {
            match q {
                DocQuery::AuthCert(ids) => ids.into_iter().for_each(|id| {
                    found_ids.insert(id);
                }),
                _ => panic!("Wrong type."),
            }
        }
        assert_eq!(found_ids.len(), 2500);
        assert_eq!(&found_ids, &ids);

        // Consensus is trivial?
        let query = DocQuery::LatestConsensus {
            flavor: ConsensusFlavor::Microdesc,
            cache_usage: CacheUsage::CacheOkay,
        };
        let split = query.clone().split_for_download();
        assert_eq!(split, vec![query]);
    }

    #[test]
    fn into_query() {
        let q: DocQuery = DocId::Microdesc([99; 32]).into();
        assert_eq!(q, DocQuery::Microdesc(vec![[99; 32]]));
    }

    #[test]
    fn pending_requirement() {
        // If we want to keep all of our activity within the cache,
        // we must request a non-pending consensus from the cache.
        assert_eq!(CacheUsage::CacheOnly.pending_requirement(), Some(false));
        // Otherwise, any cached consensus, pending or not, will meet
        // our needs.
        assert_eq!(CacheUsage::CacheOkay.pending_requirement(), None);
        assert_eq!(CacheUsage::MustDownload.pending_requirement(), None);
    }
}
