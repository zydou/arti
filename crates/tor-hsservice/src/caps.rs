//! Helpers for capability declaration and negotiation.

// TODO #2598: Remove duplicate code between tor_hsclient::caps,
// tor_hsservice::caps, and tor_proto::circuit (to the extent possible).

use cfg_if::cfg_if;
use tor_cell::relaycell::hs::intro_payload::IntroduceHandshakePayload;
use tor_protover::Protocols;

use crate::IntroRequestError;

cfg_if! {
    if #[cfg(feature = "negotiate-extensions")] {
        use std::sync::LazyLock;
        use tor_protover::{NamedSubver, named::*};

        /// A set of protocols that we can advertise in our HS descriptor,
        /// if we support them.
        static ADVERTIZABLE_PROTOCOLS: LazyLock<Protocols> = LazyLock::new(
           || [RELAY_CRYPT_CGO, RELAY_NEGOTIATE_SUBPROTO].into_iter().collect()
        );

        /// An array of protocols that can be requested via a subprotocol
        /// request extension.
        ///
        /// Note that we don't necessarily support all of these ourselves!
        static REQUESTABLE_LIST: &[NamedSubver] = &[
             RELAY_CRYPT_CGO
        ];

        /// A set of protocols that can be requested via a subprotocol request extension.
        static REQUESTABLE: LazyLock<Protocols> = LazyLock::new(
            || REQUESTABLE_LIST.iter().copied().collect()
        );

        /// A set of protocols that we should advertise, if supported,
        /// in our `flow-control` line.
        static ADVERTISE_FLOWCTRL: LazyLock<Protocols> = LazyLock::new(
            || [FLOWCTRL_AUTH_SENDME, FLOWCTRL_CC].into_iter().collect()
        );
    }
}

/// Return the list of protocols that we should advertise in our hsdesc.
pub(crate) fn declared_protocols() -> Protocols {
    cfg_if! {
        if #[cfg(feature = "negotiate-extensions")] {
            tor_proto::supported_client_protocols().intersection(&ADVERTIZABLE_PROTOCOLS)
        } else {
            Protocols::new()
        }
    }
}

/// Return the flow control information that we should include in our hsdesc.
pub(crate) fn declared_flowctrl(
    params: &tor_netdir::params::NetParameters,
) -> Option<(Protocols, u8)> {
    cfg_if! {
        if #[cfg(feature = "negotiate-extensions")] {
            let supported = tor_proto::supported_client_protocols();
            supported.supports_named_subver(FLOWCTRL_CC).then(|| {
                (
                    supported.intersection(&ADVERTISE_FLOWCTRL),
                    params.cc_sendme_inc.into()
                )
            })
        } else {
            None
        }
    }
}

/// Return a set of capabilities requested by the client in an INTRODUCE2 message payload.
///
/// The returned set will include capabilities that are...
///    - Requested explicitly by using `SUBPROTOCOL_REQUEST`
///    - Requested implicitly by using `FLOWCTRL_CC`
///
/// Returns an error if the client requested any capability that we do not support,
/// or which may not be included in a list of requested protocols.
#[cfg(feature = "negotiate-extensions")]
pub(crate) fn negotiated_capabilities(
    intro: &IntroduceHandshakePayload,
) -> Result<Protocols, IntroRequestError> {
    let mut requested = Vec::new();

    // A list of capabilities (at the tor_proto level!) that we actually support.
    //
    // (We could possibly stop checking this once the flowctrl-cc and counter-galois-onion features
    // are always-on.)
    //
    // We use this instead of annotating NEGOTIABLE_REQUEST_LIST members with `cfg`,
    // because we don't want to add our own set of flowctrl-cc/counter-galois-onion features
    // to match tor-proto.
    let supported_protocols = tor_proto::supported_client_protocols();

    if intro.cc_request_extension().is_some() {
        // The client asked for FLOWCTRL_CC.  If we support it, add it to `requested`.
        // Otherwise, reject the request.
        if supported_protocols.supports_named_subver(FLOWCTRL_CC) {
            requested.push(FLOWCTRL_CC);
        } else {
            return Err(IntroRequestError::UnsupportedCapability);
        }
    }

    if let Some(sp) = intro.subprotocol_request_extension() {
        if !sp.contains_only(&REQUESTABLE) {
            // Some capability was listed that is not supported at all with this extension.
            // Reject.
            return Err(IntroRequestError::UnsupportedCapability);
        }
        for cap in REQUESTABLE_LIST {
            if sp.contains(*cap) {
                if !supported_protocols.supports_named_subver(*cap) {
                    // They requested something that we don't support. Reject the request.
                    return Err(IntroRequestError::UnsupportedCapability);
                }
                requested.push(*cap);
            }
        }
    }

    let requested: Protocols = requested.into_iter().collect();

    // We cannot provide CGO unless we also have negotiated CC .
    if requested.supports_named_subver(RELAY_CRYPT_CGO)
        && !requested.supports_named_subver(FLOWCTRL_CC)
    {
        return Err(IntroRequestError::UnsupportedCapability);
    }

    Ok(requested)
}

/// Legacy implementation of negotiated_capabilities.
///
// TODO: Remove this, and make the entire negotiate-extensions feature always-on.
#[cfg(not(feature = "negotiate-extensions"))]
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn negotiated_capabilities(
    intro: &IntroduceHandshakePayload,
) -> Result<Protocols, IntroRequestError> {
    // In this case, we "do not recognize" SUBPROTO_REQUEST,
    // and so we ignore it.

    Ok(Protocols::new())
}
