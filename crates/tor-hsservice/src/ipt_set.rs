//! IPT set - the principal API between the IPT manager and publisher

use std::time::Duration;

/// Set of introduction points to be advertised in a descriptor (if we are to publish)
///
/// If `Some`, the publisher will try to maintain a published descriptor,
/// of lifetime `lifetime`, listing `ipts`.
///
/// If `None`, the publisher will not try to publish.
/// (Already-published descriptors will not be deleted.)
///
/// These instructions ultimately come from
/// [`IptManager::compute_iptsetstatus_publish`](crate::ipt_mgr::IptManager::compute_iptsetstatus_publish).
pub(crate) type PublishIptSet = Option<IptSet>;

/// A set of introduction points for publication
pub(crate) struct IptSet {
    /// The actual introduction points
    pub(crate) ipts: Vec<Ipt>,

    /// When to make the descriptor expire
    pub(crate) lifetime: Duration,
}

/// Introduction point as specified to publisher by manager
///
/// Convenience type alias.
pub(crate) type Ipt = tor_netdoc::doc::hsdesc::IntroPointDesc;

/// Descriptor expiry time slop
///
/// How long after our descriptor expired should we continue to maintain an old IPT?
/// This is an allowance for:
///
///   - Various RTTs and delays in clients setting up circuits
///     (we can't really measure this ourselves properly,
///     since what matters is the client's latency)
///
///   - Clock skew
//
// TODO HSS IPT_PUBLISH_EXPIRY_SLOP configure?
pub(crate) const IPT_PUBLISH_EXPIRY_SLOP: Duration = Duration::from_secs(300); // 5 minutes
