//! IPT set - the principal API between the IPT manager and publisher

use std::time::{Duration, Instant};

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
///
/// This is shared between the manager and the publisher.
/// Each leaf field says who sets it.
pub(crate) struct IptSet {
    /// The actual introduction points
    pub(crate) ipts: Vec<IptInSet>,

    /// When to make the descriptor expire
    ///
    /// Set by the manager and read by the publisher.
    pub(crate) lifetime: Duration,
}

/// Introduction point as specified to publisher by manager
///
/// Convenience type alias.
pub(crate) struct IptInSet {
    /// Details of the introduction point
    ///
    /// Set by the manager and read by the publisher.
    pub(crate) ipt: Ipt,

    /// Time until which the manager ought we to try to maintain this ipt,
    /// even after we stop publishing it.
    ///
    /// This is a ceiling on:
    ///
    ///   * The last time we *finished* publishing the descriptor
    ///     (we can estimate this by taking the time we *started* to publish
    ///     plus our timeout on the publication attempt).
    ///
    ///   * Plus the `lifetime` that was used for publication.
    ///
    ///   * Plus the length of time between a client obtaining the descriptor
    ///     and its introduction request reaching us through the intro point
    ///     ([`IPT_PUBLISH_EXPIRY_SLOP`])
    ///
    /// If the descriptor has never been published, is `None`.
    ///
    /// This field is updated by the publisher and read by the manager.
    pub(crate) last_descriptor_expiry_including_slop: Option<Instant>,
}

/// Actual introduction point details as specified to publisher by manager
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
