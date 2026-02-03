//! Relay responder channel.
//!
//! Code related to the relay channel opened as a responder. The handshake code is responsible for
//! creating an [`MaybeVerifiableRelayResponderChannel`] when accepting an inbound connection.
//!
//! It can then be used to get a fully working channel.

use futures::{AsyncRead, AsyncWrite};
use std::{ops::Deref, sync::Arc};
use tracing::instrument;

use tor_cell::chancell::msg;
use tor_linkspec::OwnedChanTarget;
use tor_rtcompat::{CertifiedConn, CoarseTimeProvider, SleepProvider, StreamOps};

use crate::{
    Error, RelayIdentities, Result,
    channel::{
        Channel, Reactor,
        handshake::{UnverifiedChannel, VerifiedChannel},
    },
    relay::channel::ChannelAuthenticationData,
};

/// An enum combining both the possibility of a verifable (relay) or non verifiable channel
/// (client/bridge).
pub enum MaybeVerifiableRelayResponderChannel<
    T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> {
    /// Verifiable channel (relay).
    Verifiable(UnverifiedResponderRelayChannel<T, S>),
    /// Non verifiable channel (client/bridge).
    NonVerifiable(NonVerifiableResponderRelayChannel<T, S>),
}

/// A channel that can NOT be verified. This is solely either a client or bridge on the other end.
///
/// This can only be built if no [`msg::Authenticate`] was ever received.
pub struct NonVerifiableResponderRelayChannel<
    T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> {
    /// The common unverified channel that both client and relays use.
    pub(crate) inner: UnverifiedChannel<T, S>,
}

/// A verifiable relay responder channel that is currently unverified. This can only be a relay on
/// the other end.
///
/// The verify() and then finish() functions are to be used to get a final Channel/Reactor.
pub struct UnverifiedResponderRelayChannel<
    T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> {
    /// The common unverified channel that both client and relays use.
    pub(crate) inner: UnverifiedChannel<T, S>,
    /// AUTHENTICATE cell received from the initiator.
    pub(crate) auth_cell: msg::Authenticate,
    /// The netinfo cell received from the initiator.
    pub(crate) netinfo_cell: msg::Netinfo,
    /// Our identity keys needed for authentication.
    pub(crate) identities: Arc<RelayIdentities>,
}

/// A verified relay responder channel.
///
/// Only finish() remains to transform this into a fully usable [`crate::channel::Channel`] and
/// [`crate::channel::Reactor`].
pub struct VerifiedResponderRelayChannel<
    T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
> {
    /// The common unverified channel that both client and relays use.
    inner: VerifiedChannel<T, S>,
    /// The netinfo cell that we got from the relay. Canonicity decision.
    #[expect(unused)]
    netinfo_cell: msg::Netinfo,
}

impl<T, S> UnverifiedResponderRelayChannel<T, S>
where
    T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
{
    /// Validate the certificates and keys in the relay's handshake.
    ///
    /// 'peer' is the peer that we want to make sure we're connecting to.
    ///
    /// 'peer_cert' is the x.509 certificate that the peer presented during its TLS handshake
    /// (ServerHello).
    ///
    /// 'now' is the time at which to check that certificates are valid.  `None` means to use the
    /// current time. It can be used for testing to override the current view of the time.
    ///
    /// This is a separate function because it's likely to be somewhat CPU-intensive.
    #[instrument(skip_all, level = "trace")]
    pub fn verify(
        self,
        peer: &OwnedChanTarget,
        peer_cert: &[u8],
        now: Option<std::time::SystemTime>,
    ) -> Result<VerifiedResponderRelayChannel<T, S>> {
        // Get these object out as we consume "self" in the inner check().
        let identities = self.identities;
        let netinfo_cell = self.netinfo_cell;
        let initiator_auth_cell = self.auth_cell;

        // Verify our inner channel and then proceed to handle the authentication challenge if any.
        let mut verified = self.inner.check(peer, peer_cert, now)?;

        // By building the ChannelAuthenticationData, we are certain that the authentication type
        // of the initiator is supported by us.
        let our_auth_cell = ChannelAuthenticationData::build(None, &identities, &mut verified)?
            .into_authenticate(verified.framed_tls.deref(), &identities.link_sign_kp)?;

        // CRITICAL: This if is what authenticates a channel on the responder side. We compare
        // what we expected to what we received.
        if initiator_auth_cell != our_auth_cell {
            return Err(Error::ChanProto(
                "AUTHENTICATE was unexpected. Failing authentication".into(),
            ));
        }
        // This part is very important as we now flag that we are verified and thus authenticated.
        //
        // At this point, the underlying cell handler is in the Handshake state. Setting the
        // channel type here as authenticated means that once the handler transition to the Open
        // state, it will carry this authenticated flag leading to the message filter of the
        // channel codec to adapt its restricted message sets (meaning R2R only).
        //
        // After this call, it is considered a R2R channel.
        verified.set_authenticated()?;

        Ok(VerifiedResponderRelayChannel {
            inner: verified,
            netinfo_cell,
        })
    }
}

impl<T, S> VerifiedResponderRelayChannel<T, S>
where
    T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
{
    /// Finish the handhshake which will create an open channel and reactor.
    ///
    /// The resulting channel is considered, by Tor protocol standard, an authenticated relay
    /// channel on which circuits can be opened.
    #[instrument(skip_all, level = "trace")]
    pub async fn finish(self) -> Result<(Arc<Channel>, Reactor<S>)> {
        // TODO(relay): This would be the time to set a "is_canonical" flag to Channel which is
        // true if the Netinfo address matches the address we are connected to. Canonical
        // definition is if the address we are connected to is what we expect it to be. This only
        // makes sense for relay channels.

        self.inner.finish().await
    }
}

impl<T, S> NonVerifiableResponderRelayChannel<T, S>
where
    T: AsyncRead + AsyncWrite + CertifiedConn + StreamOps + Send + Unpin + 'static,
    S: CoarseTimeProvider + SleepProvider,
{
    /// Finish the handhshake which will create an open channel and reactor.
    ///
    /// The resulting channel is considered, by Tor protocol standard, a client/bridge relay
    /// channel meaning not authenticated. Circuit can be opened on it.
    #[instrument(skip_all, level = "trace")]
    pub fn finish(self) -> Result<(Arc<Channel>, Reactor<S>)> {
        // Non verifiable responder channel, we simply finalize our underlying channel and we are
        // done. We are connect to a client or bridge.
        self.inner.finish()
    }
}
